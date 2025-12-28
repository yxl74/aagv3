"""Phase output validation with Pydantic schemas.

This module provides JSON schema validation for phase outputs with
parse-before-validate logic and auto-retry capabilities.

Fix 11: Per-unit tool coverage validation.
Fix 14: JSON schema in prompt + pre-acceptance validation + auto-retry.
Fix 24: JSON parse before schema validation.
Fix 32: Strict per-callsite EFFECT claim validation.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Tuple, Type

from pydantic import BaseModel, Field, field_validator


# =============================================================================
# Pydantic Schemas for Phase Outputs
# =============================================================================


class ExtractedStructureSchema(BaseModel):
    """Schema for Phase 1A output validation."""

    seed_id: str
    api_calls: List[Dict[str, Any]]
    control_guards: List[Dict[str, Any]] = Field(default_factory=list)
    ambiguous_units: List[str] = Field(default_factory=list)
    flagged_for_review: List[str] = Field(default_factory=list)
    extraction_coverage: str
    extraction_confidence: float

    @field_validator("extraction_coverage")
    @classmethod
    def validate_coverage(cls, v: str) -> str:
        if v not in ["complete", "partial", "minimal"]:
            raise ValueError(f"Invalid coverage: {v}")
        return v

    @field_validator("extraction_confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"Confidence must be 0.0-1.0, got {v}")
        return v


class InterpretedClaimSchema(BaseModel):
    """Schema for Phase 1B claim validation."""

    claim_id: str = Field(pattern=r"^c\d{3}$")
    unit_id: str
    claim_type: str
    tier1_field: str
    interpretation: str = Field(min_length=10)
    source_unit_ids: List[str] = Field(min_length=1)
    resolved_by: str
    confidence: float = Field(ge=0.0, le=1.0)
    needs_investigation: bool = False

    @field_validator("claim_type")
    @classmethod
    def validate_claim_type(cls, v: str) -> str:
        if v not in ["effect", "constraint", "input"]:
            raise ValueError(f"Invalid claim_type: {v}")
        return v

    @field_validator("tier1_field")
    @classmethod
    def validate_tier1_field(cls, v: str) -> str:
        if v not in ["path_constraints", "observable_effects", "required_inputs"]:
            raise ValueError(f"Invalid tier1_field: {v}")
        return v

    @field_validator("resolved_by")
    @classmethod
    def validate_resolved_by(cls, v: str) -> str:
        if v not in ["jadx", "cfg", "heuristic", "unresolved"]:
            raise ValueError(f"Invalid resolved_by: {v}")
        return v


class SourceLookupSchema(BaseModel):
    """Schema for source lookup validation."""

    unit_id: str
    tool_used: str
    tool_args: Dict[str, Any] = Field(default_factory=dict)
    success: bool
    failure_reason: Optional[str] = None

    @field_validator("tool_used")
    @classmethod
    def validate_tool_used(cls, v: str) -> str:
        valid_tools = ["read_java_source", "read_cfg_units", "search_java_source"]
        if v not in valid_tools:
            raise ValueError(f"Invalid tool_used: {v}")
        return v


class InterpretedBehaviorSchema(BaseModel):
    """Schema for Phase 1B output validation."""

    seed_id: str
    claims: List[InterpretedClaimSchema]
    source_lookups: List[SourceLookupSchema] = Field(default_factory=list)
    unresolved: List[str] = Field(default_factory=list)
    unclaimed_apis: List[str] = Field(default_factory=list)


class FactSchema(BaseModel):
    """Schema for Phase 1C fact validation."""

    statement: str = Field(min_length=5)
    support_unit_ids: List[str] = Field(default_factory=list)
    claim_id: Optional[str] = None
    from_deterministic: bool = False
    confidence: float = Field(ge=0.0, le=1.0)


# =============================================================================
# JSON Schema Constants for Prompts
# =============================================================================

CLAIM_JSON_SCHEMA = {
    "type": "object",
    "required": [
        "claim_id",
        "claim_type",
        "tier1_field",
        "unit_id",
        "interpretation",
        "source_unit_ids",
        "resolved_by",
        "confidence",
    ],
    "properties": {
        "claim_id": {"type": "string", "pattern": "^c[0-9]{3}$"},
        "claim_type": {"type": "string", "enum": ["effect", "constraint", "input"]},
        "tier1_field": {
            "type": "string",
            "enum": ["path_constraints", "observable_effects", "required_inputs"],
        },
        "unit_id": {"type": "string"},
        "interpretation": {"type": "string", "minLength": 10},
        "source_unit_ids": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        "resolved_by": {"type": "string", "enum": ["jadx", "cfg", "heuristic", "unresolved"]},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "needs_investigation": {"type": "boolean"},
    },
}


# =============================================================================
# Validation Functions
# =============================================================================


class SchemaValidationError(Exception):
    """Raised when schema validation fails after retries."""

    pass


class JSONParseError(Exception):
    """Raised when JSON parsing fails."""

    pass


def validate_phase_output(
    phase: str,
    raw_output: str,
) -> Tuple[Dict[str, Any], bool, List[str]]:
    """Parse and validate phase output.

    Fix 24: Parse JSON first, then validate.

    Args:
        phase: Phase name ("1A", "1B", "1C").
        raw_output: Raw string output from LLM.

    Returns:
        Tuple of (parsed_output, is_valid, errors).
    """
    errors: List[str] = []

    # Step 1: Parse JSON
    try:
        output = json.loads(raw_output)
    except json.JSONDecodeError as e:
        return {}, False, [f"JSON parse error: {e}"]

    # Step 2: Schema validation
    if phase == "1A":
        try:
            ExtractedStructureSchema(**output)
        except Exception as e:
            errors.append(f"1A schema validation failed: {e}")

    elif phase == "1B":
        for i, claim in enumerate(output.get("claims", [])):
            try:
                InterpretedClaimSchema(**claim)
            except Exception as e:
                errors.append(f"1B claim[{i}] validation failed: {e}")

    elif phase == "1C":
        for fact in output.get("facts", []):
            if not fact.get("claim_id") and not fact.get("from_deterministic"):
                errors.append(f"Fact missing claim_id: {fact.get('statement', '')[:50]}")

    return output, len(errors) == 0, errors


def validate_1b_tool_coverage(
    ambiguous_units: List[str],
    source_lookups: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
) -> Tuple[bool, List[str]]:
    """Validate every ambiguous unit has a tool outcome.

    Fix 11: Per-unit tool enforcement.

    Args:
        ambiguous_units: List of unit IDs that need interpretation.
        source_lookups: List of source lookup records.
        claims: List of claims produced.

    Returns:
        Tuple of (is_valid, errors).
    """
    errors: List[str] = []
    lookup_units = {sl.get("unit_id") for sl in source_lookups}

    for unit_id in ambiguous_units:
        if unit_id not in lookup_units:
            errors.append(f"No tool lookup for ambiguous unit: {unit_id}")

    return len(errors) == 0, errors


def validate_1b_strict_claim_coverage(
    api_calls: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
) -> Tuple[bool, List[str], List[str]]:
    """Validate strict per-callsite EFFECT claim coverage.

    Fix 32: Every API callsite MUST have >=1 EFFECT claim.

    Args:
        api_calls: List of API call extractions.
        claims: List of claims produced.

    Returns:
        Tuple of (is_valid, errors, unclaimed_api_ids).
    """
    errors: List[str] = []

    # Find API callsites with EFFECT claims
    effect_claims = [c for c in claims if c.get("claim_type") == "effect"]
    covered_apis = {c.get("unit_id") for c in effect_claims}
    api_unit_ids = {call.get("unit_id") for call in api_calls}

    # Strict: any API without EFFECT claim is unclaimed
    unclaimed_apis = [uid for uid in api_unit_ids if uid not in covered_apis]

    if unclaimed_apis:
        errors.append(
            f"Missing EFFECT claims for {len(unclaimed_apis)} API callsites: "
            f"{unclaimed_apis[:5]}{'...' if len(unclaimed_apis) > 5 else ''}"
        )

    return len(errors) == 0, errors, unclaimed_apis


def run_phase_with_schema_enforcement(
    llm_complete: Callable[[str], str],
    prompt: str,
    phase: str,
    max_retries: int = 2,
) -> Dict[str, Any]:
    """Run LLM phase with proper JSON parsing and schema validation.

    Fix 14: JSON schema in prompt + pre-acceptance validation + auto-retry.
    Fix 24: Parse JSON first, then validate.

    Args:
        llm_complete: Function to call LLM and get string response.
        prompt: The prompt to send.
        phase: Phase name for schema selection.
        max_retries: Maximum retry attempts.

    Returns:
        Parsed and validated output dict.

    Raises:
        SchemaValidationError: If validation fails after all retries.
    """
    current_prompt = prompt

    for attempt in range(max_retries + 1):
        # Get LLM output
        raw_output = llm_complete(current_prompt)

        # Parse and validate
        parsed, is_valid, errors = validate_phase_output(phase, raw_output)

        if is_valid:
            return parsed

        # Prepare retry prompt
        if attempt < max_retries:
            error_msg = "\n".join(errors)
            if "JSON parse error" in error_msg:
                current_prompt = (
                    f"{prompt}\n\n"
                    f"YOUR PREVIOUS OUTPUT WAS INVALID JSON:\n{error_msg}\n\n"
                    f"Return valid JSON only. No markdown, no explanations."
                )
            else:
                current_prompt = (
                    f"{prompt}\n\n"
                    f"YOUR PREVIOUS OUTPUT FAILED SCHEMA VALIDATION:\n{error_msg}\n\n"
                    f"Fix these errors and return valid JSON."
                )
        else:
            raise SchemaValidationError(
                f"Schema validation failed after {max_retries} retries: {errors}"
            )

    # Should not reach here, but satisfy type checker
    raise SchemaValidationError("Unexpected validation failure")

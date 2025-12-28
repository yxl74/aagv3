"""Tier1 phase models and data contracts.

This module defines all dataclasses and enums for the three-phase Tier1 analysis:
- Phase 1A: Structural Extraction (ExtractedStructure)
- Phase 1B: Semantic Interpretation (InterpretedBehavior)
- Phase 1C: Evidence Synthesis (Tier1Output)

Fix 9: Claim taxonomy with tier1_field mapping
Fix 11: Per-unit SourceLookup tracking
Fix 16: Permission scope tracking (RequiredPermission)
Fix 17: PhaseStatus enum (ok/partial/failed)
Fix 22: API claim coverage validation
Fix 23: RequiredPermission as single canonical source (removed from ComponentHints)
Fix 27: Strict per-callsite claim enforcement with unclaimed_apis
Fix 31: ExtractedStructure includes permissions field
Fix 32: Unified claim coverage policy - per-callsite EFFECT claims
Fix 33: Unknown API handling with needs_investigation flag
Improvement B: ParsedUnit for pre-parsed CFG units
Improvement C: from_deterministic fact type
Improvement D: unresolved_ratio in 1B output
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Any

from apk_analyzer.models.analysis_context import ComponentHints


class PhaseStatus(str, Enum):
    """Phase execution status for orchestrator decisions.

    Fix 17: Explicit PhaseStatus enum (ok/partial/failed).
    """

    OK = "ok"  # Completed successfully
    PARTIAL = "partial"  # Completed with some issues
    FAILED = "failed"  # Critical failure, output unreliable


class ExtractionCoverage(str, Enum):
    """Extraction coverage level.

    Fix 3: Default to PARTIAL, require heuristics for COMPLETE.
    """

    COMPLETE = "complete"  # All heuristics passed
    PARTIAL = "partial"  # Default - some extraction issues
    MINIMAL = "minimal"  # Critical structure missing or extractor drift


@dataclass
class PhaseOutput:
    """Base class for all phase outputs.

    Fix 17: Phase status markers for orchestrator decisions.
    """

    phase_status: PhaseStatus = PhaseStatus.OK
    status_reason: Optional[str] = None  # Why partial/failed


# =============================================================================
# Phase 1A: Structural Extraction Data Classes
# =============================================================================


@dataclass
class ApiCallExtraction:
    """Extracted API call information.

    Represents a sensitive API callsite extracted from the CFG.
    """

    unit_id: str
    signature: str
    class_name: str
    method_name: str
    args: List[str] = field(default_factory=list)
    line_number: Optional[int] = None
    sensitivity_source: Optional[str] = None  # "catalog_method" | "catalog_class" | "pattern" | "prefix"
    sensitivity_confidence: Optional[float] = None  # 0.0-1.0


@dataclass
class ControlGuard:
    """Extracted control flow guard (branch condition)."""

    unit_id: str
    condition: str
    guard_type: str  # "permission_check", "null_check", "value_check", "other"
    related_api_unit_ids: List[str] = field(default_factory=list)


@dataclass
class SemanticAnnotation:
    """Semantic meaning annotation for constant values.

    Fix 6: SDK-versioned mappings with resolution_source.
    Improvement A: resolution_confidence per annotation.
    """

    unit_id: str
    original_value: str
    semantic_meaning: str
    enum_type: str
    resolution_confidence: float  # 0.0-1.0
    resolution_source: str  # "sdk_official" | "aosp_source" | "heuristic"


@dataclass
class RequiredPermission:
    """Single canonical permission representation.

    Fix 16: Permission scope tracking.
    Fix 23: This is the ONLY source of permission info (not ComponentHints).
    """

    permission: str
    scope: str  # "global_manifest" | "inferred_from_api"
    evidence_unit_ids: List[str] = field(default_factory=list)  # Empty for global_manifest
    confidence: float = 0.5


@dataclass
class ExtractedStructure(PhaseOutput):
    """Phase 1A output - deterministic structure extraction.

    Fix 3: Default extraction_coverage to PARTIAL.
    Fix 23: permissions field is the canonical source (not in ComponentHints).
    Fix 31: ExtractedStructure includes permissions field.
    """

    seed_id: str
    api_calls: List[ApiCallExtraction] = field(default_factory=list)
    control_guards: List[ControlGuard] = field(default_factory=list)
    component_hints: Optional[ComponentHints] = None
    semantic_annotations: List[SemanticAnnotation] = field(default_factory=list)
    permissions: List[RequiredPermission] = field(default_factory=list)  # Fix 23, 31
    ambiguous_units: List[str] = field(default_factory=list)
    flagged_for_review: List[str] = field(default_factory=list)
    extraction_coverage: ExtractionCoverage = ExtractionCoverage.PARTIAL  # Fix 3
    extraction_confidence: float = 0.5

    def needs_interpretation(self) -> bool:
        """Check if Phase 1B is needed.

        Fix 19: Run 1B for ALL seeds with sensitive API callsites.
        """
        has_sensitive_apis = len(self.api_calls) > 0
        has_ambiguity = bool(self.ambiguous_units) or bool(self.flagged_for_review)
        return has_sensitive_apis or has_ambiguity


# =============================================================================
# Phase 1B: Semantic Interpretation Data Classes
# =============================================================================


@dataclass
class SourceLookup:
    """Per-unit tool usage tracking.

    Fix 11: Require source_lookups keyed by unit_id.
    """

    unit_id: str
    tool_used: str  # "read_java_source" | "read_cfg_units" | "search_java_source"
    tool_args: Dict[str, Any] = field(default_factory=dict)
    success: bool = False
    failure_reason: Optional[str] = None


@dataclass
class InterpretedClaim:
    """Behavioral claim from Phase 1B interpretation.

    Fix 1: resolved_by tracking for JADX/CFG fallback.
    Fix 9: tier1_field for explicit Tier1Output field mapping.
    Fix 33: needs_investigation for unknown APIs.
    """

    claim_id: str
    unit_id: str
    claim_type: str  # "effect" | "constraint" | "input"
    tier1_field: str  # "path_constraints" | "observable_effects" | "required_inputs"
    interpretation: str
    source_unit_ids: List[str] = field(default_factory=list)
    resolved_by: str = "unresolved"  # "jadx" | "cfg" | "heuristic" | "unresolved"
    confidence: float = 0.5
    needs_investigation: bool = False  # Fix 33: True for unknown/ambiguous APIs


@dataclass
class InterpretedBehavior(PhaseOutput):
    """Phase 1B output - behavioral interpretation.

    Fix 11: source_lookups per unit.
    Fix 22: api_claim_coverage tracking.
    Fix 27: unclaimed_apis tracking.
    Fix 32: Unified strict per-callsite claim coverage policy.
    Improvement D: unresolved_ratio in output.
    """

    seed_id: str
    claims: List[InterpretedClaim] = field(default_factory=list)
    source_lookups: List[SourceLookup] = field(default_factory=list)
    unresolved: List[str] = field(default_factory=list)  # Ambiguous units that couldn't be resolved
    unclaimed_apis: List[str] = field(default_factory=list)  # Fix 27: API unit_ids without EFFECT claims
    unresolved_ratio: float = 0.0  # Improvement D

    @classmethod
    def empty(cls, seed_id: str) -> "InterpretedBehavior":
        """Create empty InterpretedBehavior for seeds without 1B."""
        return cls(
            seed_id=seed_id,
            phase_status=PhaseStatus.OK,
        )

    @classmethod
    def compute_with_strict_audit(
        cls,
        seed_id: str,
        claims: List[InterpretedClaim],
        source_lookups: List[SourceLookup],
        api_calls: List[ApiCallExtraction],
        ambiguous_units: List[str],
        unresolved: List[str],
    ) -> "InterpretedBehavior":
        """Create InterpretedBehavior with strict per-callsite claim audit.

        Fix 32: STRICT POLICY:
        - Every API callsite MUST have >=1 EFFECT claim
        - unclaimed_apis = APIs without effect claims
        """
        # Find API callsites with EFFECT claims
        effect_claims = [c for c in claims if c.claim_type == "effect"]
        covered_apis: Set[str] = {c.unit_id for c in effect_claims}
        api_unit_ids: Set[str] = {call.unit_id for call in api_calls}

        # Strict: any API without EFFECT claim goes to unclaimed
        unclaimed_apis = [uid for uid in api_unit_ids if uid not in covered_apis]

        # Compute unresolved ratio
        if ambiguous_units:
            unresolved_ratio = len(unresolved) / len(ambiguous_units)
        else:
            unresolved_ratio = 0.0

        result = cls(
            seed_id=seed_id,
            claims=claims,
            source_lookups=source_lookups,
            unresolved=unresolved,
            unclaimed_apis=unclaimed_apis,
            unresolved_ratio=unresolved_ratio,
        )

        # Compute phase status
        result.phase_status = result.compute_phase_status(len(api_calls))
        return result

    def compute_phase_status(self, total_apis: int) -> PhaseStatus:
        """Compute phase status based on strict per-callsite enforcement.

        Fix 32: UNIFIED STATUS LOGIC:
        - FAILED: >50% of APIs unclaimed
        - PARTIAL: Any APIs unclaimed (but <=50%)
        - OK: All APIs have EFFECT claims
        """
        if not total_apis:
            return PhaseStatus.OK  # No APIs to claim

        unclaimed_ratio = len(self.unclaimed_apis) / total_apis

        if unclaimed_ratio > 0.5:
            return PhaseStatus.FAILED
        elif self.unclaimed_apis:  # Any unclaimed = PARTIAL
            return PhaseStatus.PARTIAL
        # All APIs claimed; now factor ambiguity resolution
        if self.unresolved_ratio > 0.5:
            return PhaseStatus.FAILED
        if self.unresolved_ratio > 0.2:
            return PhaseStatus.PARTIAL
        return PhaseStatus.OK


# =============================================================================
# Phase 1C: Evidence Synthesis Data Classes
# =============================================================================


@dataclass
class Fact:
    """Evidence fact for Tier1 output.

    Fix 4: Explicit claim_id reference (not string matching).
    Improvement C: from_deterministic fact type for high-trust structural facts.
    """

    statement: str
    support_unit_ids: List[str] = field(default_factory=list)
    claim_id: Optional[str] = None  # Required for behavioral facts
    from_deterministic: bool = False  # True for structural facts from 1A
    fact_category: str = "behavioral"  # "structural" | "behavioral"
    confidence: float = 0.5


@dataclass
class PathConstraint:
    """Path constraint for Tier1 output."""

    constraint: str
    unit_ids: List[str] = field(default_factory=list)
    claim_id: Optional[str] = None


@dataclass
class ObservableEffect:
    """Observable effect for Tier1 output."""

    effect: str
    unit_ids: List[str] = field(default_factory=list)
    claim_id: Optional[str] = None


@dataclass
class RequiredInput:
    """Required input for Tier1 output.

    Fix 16: scope tracking for permissions.
    """

    input_type: str  # "permission" | "intent_extra" | "content_uri" | etc.
    name: str
    scope: Optional[str] = None  # For permissions: "global_manifest" | "inferred_from_api"
    evidence_unit_ids: List[str] = field(default_factory=list)


# =============================================================================
# Helper Classes
# =============================================================================


@dataclass
class ParsedUnit:
    """Pre-parsed CFG unit.

    Improvement B: Pre-parsed fields so 1B doesn't parse Jimple text.
    """

    unit_id: str
    raw_stmt: str
    op: str  # "invoke" | "assign" | "if" | "goto" | "return" | "other"
    call_sig: Optional[str] = None  # For invoke ops
    args: List[str] = field(default_factory=list)  # Parsed arguments
    lhs: Optional[str] = None  # Left-hand side for assignments
    condition: Optional[str] = None  # For if statements


# =============================================================================
# Type Aliases
# =============================================================================

# JSON-serializable versions for prompts/outputs
ExtractedStructureDict = Dict[str, Any]
InterpretedBehaviorDict = Dict[str, Any]
Tier1OutputDict = Dict[str, Any]

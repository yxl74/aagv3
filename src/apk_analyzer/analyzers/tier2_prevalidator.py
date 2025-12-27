"""
Pre-validator for Tier2 execution guidance generation.

This module validates seeds before passing them to the Tier2 phases.
Instead of blocking entirely on missing information, it:
- Warns about issues
- Downgrades automation feasibility appropriately
- Still allows processing to continue with partial guidance

Design principle: Warn/downgrade, never block.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class AutomationFeasibility(Enum):
    """Levels of automation feasibility for execution guidance."""
    FULL = "full"                              # All info available, can fully automate
    PARTIAL = "partial"                        # Some info missing, partial automation possible
    MANUAL_INVESTIGATION = "manual_investigation_required"  # Critical info missing
    BLOCKED = "blocked"                        # Cannot process (e.g., no tier1 output)


@dataclass
class ValidationWarning:
    """A warning about potential issues with a seed."""
    seed_id: str
    warning_type: str
    message: str
    severity: str = "warning"  # "warning", "info", "error"
    suggested_action: Optional[str] = None


@dataclass
class SeedValidationResult:
    """Validation result for a single seed."""
    seed_id: str
    feasibility: AutomationFeasibility
    warnings: List[ValidationWarning] = field(default_factory=list)
    missing_info: List[str] = field(default_factory=list)
    non_automatable_extras: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def is_automatable(self) -> bool:
        """Check if this seed can be automated (even partially)."""
        return self.feasibility in (AutomationFeasibility.FULL, AutomationFeasibility.PARTIAL)


@dataclass
class PreValidationResult:
    """Overall pre-validation result for all seeds."""
    can_proceed: bool = True  # Always true (we don't block)
    seed_results: Dict[str, SeedValidationResult] = field(default_factory=dict)
    global_warnings: List[ValidationWarning] = field(default_factory=list)

    @property
    def fully_automatable_seeds(self) -> List[str]:
        """Seeds that can be fully automated."""
        return [
            sid for sid, result in self.seed_results.items()
            if result.feasibility == AutomationFeasibility.FULL
        ]

    @property
    def partially_automatable_seeds(self) -> List[str]:
        """Seeds that can be partially automated."""
        return [
            sid for sid, result in self.seed_results.items()
            if result.feasibility == AutomationFeasibility.PARTIAL
        ]

    @property
    def manual_investigation_seeds(self) -> List[str]:
        """Seeds that require manual investigation."""
        return [
            sid for sid, result in self.seed_results.items()
            if result.feasibility == AutomationFeasibility.MANUAL_INVESTIGATION
        ]

    @property
    def all_warnings(self) -> List[ValidationWarning]:
        """All warnings from all seeds plus global warnings."""
        warnings = list(self.global_warnings)
        for result in self.seed_results.values():
            warnings.extend(result.warnings)
        return warnings


# Non-injectable extra types that require manual intervention
NON_INJECTABLE_TYPES = {"parcelable", "serializable", "unknown", "mixed"}

# Confidence threshold for warnings
LOW_CONFIDENCE_THRESHOLD = 0.5


def prevalidate_for_tier2(
    consolidated_tier1: List[Dict[str, Any]],
    manifest: Optional[Dict[str, Any]] = None,
    intent_contracts: Optional[Dict[str, Any]] = None,
) -> PreValidationResult:
    """
    Pre-validate consolidated Tier1 outputs before Tier2 processing.

    This function checks for:
    1. Missing component_name in trigger_surface
    2. Low confidence scores
    3. Non-injectable intent extras
    4. Missing facts or high uncertainty

    It NEVER blocks processing, only warns and downgrades feasibility.

    Args:
        consolidated_tier1: List of Tier1 outputs (one per seed)
        manifest: Optional manifest for component validation
        intent_contracts: Optional intent contracts for extra type checking

    Returns:
        PreValidationResult with per-seed results and warnings
    """
    result = PreValidationResult()
    intent_contracts = intent_contracts or {}

    if not consolidated_tier1:
        result.global_warnings.append(ValidationWarning(
            seed_id="global",
            warning_type="no_seeds",
            message="No Tier1 outputs provided",
            severity="warning",
        ))
        return result

    for tier1 in consolidated_tier1:
        seed_id = tier1.get("seed_id") or tier1.get("unit_id") or "unknown"
        seed_result = _validate_seed(tier1, intent_contracts)
        result.seed_results[seed_id] = seed_result

    return result


def _validate_seed(
    tier1: Dict[str, Any],
    intent_contracts: Dict[str, Any],
) -> SeedValidationResult:
    """Validate a single Tier1 output."""
    seed_id = tier1.get("seed_id") or tier1.get("unit_id") or "unknown"
    warnings: List[ValidationWarning] = []
    missing_info: List[str] = []
    non_automatable_extras: List[str] = []

    # 1. Check trigger_surface.component_name
    trigger = tier1.get("trigger_surface") or {}
    component_name = trigger.get("component_name")
    component_type = trigger.get("component_type", "Unknown")

    if not component_name:
        missing_info.append("trigger_surface.component_name")
        warnings.append(ValidationWarning(
            seed_id=seed_id,
            warning_type="missing_component_name",
            message="No component_name in trigger_surface - cannot generate start command",
            severity="warning",
            suggested_action="Add component_name to trigger_surface or mark for manual investigation",
        ))

    if component_type == "Unknown":
        missing_info.append("trigger_surface.component_type")
        warnings.append(ValidationWarning(
            seed_id=seed_id,
            warning_type="unknown_component_type",
            message="Component type is Unknown - may use wrong start command template",
            severity="info",
        ))

    # 2. Check confidence score
    confidence = tier1.get("confidence", 0.0)
    if confidence < LOW_CONFIDENCE_THRESHOLD:
        warnings.append(ValidationWarning(
            seed_id=seed_id,
            warning_type="low_confidence",
            message=f"Low confidence score ({confidence:.2f}) - facts may not be reliable",
            severity="warning",
        ))

    # 3. Check for non-injectable intent extras
    if component_name:
        contract = intent_contracts.get(component_name) or {}
        for extra in contract.get("extras", []):
            extra_type = extra.get("type", "unknown")
            extra_name = extra.get("name", "unknown_extra")
            if extra_type in NON_INJECTABLE_TYPES:
                non_automatable_extras.append(extra_name)
                warnings.append(ValidationWarning(
                    seed_id=seed_id,
                    warning_type="non_injectable_extra",
                    message=f"Extra '{extra_name}' has type '{extra_type}' - cannot inject via ADB",
                    severity="info",
                    suggested_action=f"Add Frida hook to set '{extra_name}' or mark step as manual",
                ))

    # 4. Check for missing or empty facts
    facts = tier1.get("facts", [])
    if not facts:
        missing_info.append("facts")
        warnings.append(ValidationWarning(
            seed_id=seed_id,
            warning_type="no_facts",
            message="No facts extracted - reasoning may be limited",
            severity="warning",
        ))

    # 5. Check for high uncertainty
    uncertainties = tier1.get("uncertainties", [])
    if len(uncertainties) > len(facts):
        warnings.append(ValidationWarning(
            seed_id=seed_id,
            warning_type="high_uncertainty",
            message=f"More uncertainties ({len(uncertainties)}) than facts ({len(facts)})",
            severity="info",
        ))

    # Determine feasibility based on validation results
    feasibility = _determine_feasibility(missing_info, non_automatable_extras, confidence)

    return SeedValidationResult(
        seed_id=seed_id,
        feasibility=feasibility,
        warnings=warnings,
        missing_info=missing_info,
        non_automatable_extras=non_automatable_extras,
        confidence=confidence,
    )


def _determine_feasibility(
    missing_info: List[str],
    non_automatable_extras: List[str],
    confidence: float,
) -> AutomationFeasibility:
    """Determine automation feasibility based on validation results."""

    # Critical: no component_name means we can't generate start command
    if "trigger_surface.component_name" in missing_info:
        return AutomationFeasibility.MANUAL_INVESTIGATION

    # No facts means very limited reasoning
    if "facts" in missing_info:
        return AutomationFeasibility.MANUAL_INVESTIGATION

    # Low confidence + issues = manual investigation
    if confidence < LOW_CONFIDENCE_THRESHOLD and (missing_info or non_automatable_extras):
        return AutomationFeasibility.MANUAL_INVESTIGATION

    # Non-injectable extras = partial automation
    if non_automatable_extras:
        return AutomationFeasibility.PARTIAL

    # Missing component type = partial (can still work, just less precise)
    if "trigger_surface.component_type" in missing_info:
        return AutomationFeasibility.PARTIAL

    # Low confidence alone = partial
    if confidence < LOW_CONFIDENCE_THRESHOLD:
        return AutomationFeasibility.PARTIAL

    return AutomationFeasibility.FULL


def get_manual_steps_for_seed(
    seed_result: SeedValidationResult,
    intent_contracts: Dict[str, Any],
    component_name: Optional[str],
) -> List[Dict[str, Any]]:
    """
    Generate manual investigation steps for a degraded seed.

    Returns a list of manual steps to add to execution_guidance.
    """
    manual_steps: List[Dict[str, Any]] = []

    if seed_result.feasibility == AutomationFeasibility.MANUAL_INVESTIGATION:
        if "trigger_surface.component_name" in seed_result.missing_info:
            manual_steps.append({
                "step_id": f"{seed_result.seed_id}_manual_component",
                "type": "manual",
                "description": "Identify the target component from static analysis",
                "reason": "component_name missing from Tier1 analysis",
                "command": "MANUAL: Review JADX decompilation to identify entrypoint component",
            })

        if "facts" in seed_result.missing_info:
            manual_steps.append({
                "step_id": f"{seed_result.seed_id}_manual_behavior",
                "type": "manual",
                "description": "Analyze behavior from source code",
                "reason": "No facts extracted from Tier1",
                "command": "MANUAL: Review source code to understand behavior before testing",
            })

    # Add steps for non-injectable extras
    for extra_name in seed_result.non_automatable_extras:
        contract = intent_contracts.get(component_name, {}) if component_name else {}
        extra_info = next(
            (e for e in contract.get("extras", []) if e.get("name") == extra_name),
            {}
        )
        extra_type = extra_info.get("type", "unknown")

        manual_steps.append({
            "step_id": f"{seed_result.seed_id}_manual_{extra_name}",
            "type": "manual",
            "description": f"Manually provide {extra_type} extra '{extra_name}'",
            "reason": f"Extra type '{extra_type}' cannot be injected via ADB",
            "command": f"MANUAL: Use Frida or modify APK to provide '{extra_name}' ({extra_type})",
            "extra_info": {
                "name": extra_name,
                "type": extra_type,
                "value_hints": extra_info.get("value_hints", []),
            },
        })

    return manual_steps


def format_validation_summary(result: PreValidationResult) -> str:
    """Format validation result as human-readable summary."""
    lines = ["Pre-validation Summary:"]

    full = result.fully_automatable_seeds
    partial = result.partially_automatable_seeds
    manual = result.manual_investigation_seeds

    lines.append(f"  - Fully automatable: {len(full)} seeds")
    lines.append(f"  - Partially automatable: {len(partial)} seeds")
    lines.append(f"  - Manual investigation: {len(manual)} seeds")

    if result.all_warnings:
        lines.append("\nWarnings:")
        for w in result.all_warnings:
            lines.append(f"  [{w.severity.upper()}] {w.seed_id}: {w.message}")
            if w.suggested_action:
                lines.append(f"      → {w.suggested_action}")

    return "\n".join(lines)

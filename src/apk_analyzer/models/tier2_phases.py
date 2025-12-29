"""
Data classes for Tier2 phase outputs.

Phase 2A: Attack chain reasoning
Phase 2B: Command generation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# =============================================================================
# PHASE 2A: ATTACK CHAIN REASONING
# =============================================================================

class IntentVerdict(Enum):
    """Overall verdict on malicious intent."""
    CONFIRMED_MALICIOUS = "confirmed_malicious"
    LIKELY_MALICIOUS = "likely_malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


@dataclass
class EvidenceCitation:
    """Citation to support a claim."""
    unit_id: str
    seed_id: str
    statement: str
    interpretation: str


@dataclass
class DriverRequirement:
    """
    Structured requirement for Phase 2B command generation.

    Extracted by Phase 2A reasoning, consumed by Phase 2B for grounded
    command generation.
    """
    requirement_id: str
    seed_id: str  # Links back to the originating seed

    # What component to trigger
    component_name: str
    component_type: str

    # How to trigger it
    trigger_method: str  # "adb_start", "adb_broadcast", "frida_hook", "manual"
    intent_action: Optional[str] = None
    intent_extras: List[Dict[str, Any]] = field(default_factory=list)

    # What behavior to observe
    expected_behavior: str = ""
    observable_effects: List[str] = field(default_factory=list)

    # Evidence grounding
    evidence_citations: List[EvidenceCitation] = field(default_factory=list)

    # Threat category for template selection
    threat_category: str = "unknown"

    # Automation feasibility (from pre-validation)
    automation_feasibility: str = "full"  # "full", "partial", "manual_investigation_required"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "requirement_id": self.requirement_id,
            "seed_id": self.seed_id,
            "component_name": self.component_name,
            "component_type": self.component_type,
            "trigger_method": self.trigger_method,
            "intent_action": self.intent_action,
            "intent_extras": self.intent_extras,
            "expected_behavior": self.expected_behavior,
            "observable_effects": self.observable_effects,
            "evidence_citations": [
                {
                    "unit_id": c.unit_id,
                    "seed_id": c.seed_id,
                    "statement": c.statement,
                    "interpretation": c.interpretation,
                }
                for c in self.evidence_citations
            ],
            "threat_category": self.threat_category,
            "automation_feasibility": self.automation_feasibility,
        }


@dataclass
class Phase2AOutput:
    """
    Output from Phase 2A: Attack Chain Reasoning.

    Contains the reasoning about malicious intent and structured requirements
    for Phase 2B command generation.
    """
    # Case identification
    case_id: str

    # Overall verdict
    intent_verdict: IntentVerdict
    confidence: float  # 0.0-1.0

    # Attack chain summary
    attack_chain_summary: str
    attack_stages: List[str] = field(default_factory=list)

    # Aggregated evidence
    evidence: List[Dict[str, Any]] = field(default_factory=list)

    # Structured requirements for Phase 2B
    driver_requirements: List[DriverRequirement] = field(default_factory=list)

    # Aggregated facts from all seeds
    aggregated_facts: List[Dict[str, Any]] = field(default_factory=list)

    # Uncertainties that Phase 2B should be aware of
    uncertainties: List[str] = field(default_factory=list)

    # Threat categories identified
    threat_categories: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "case_id": self.case_id,
            "intent_verdict": self.intent_verdict.value,
            "confidence": self.confidence,
            "attack_chain_summary": self.attack_chain_summary,
            "attack_stages": self.attack_stages,
            "evidence": self.evidence,
            "driver_requirements": [dr.to_dict() for dr in self.driver_requirements],
            "aggregated_facts": self.aggregated_facts,
            "uncertainties": self.uncertainties,
            "threat_categories": self.threat_categories,
            "schema_version": "2.0",
            "phase": "2a",
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Phase2AOutput":
        """Create from dictionary."""
        driver_reqs = []
        for dr_data in data.get("driver_requirements", []):
            citations = [
                EvidenceCitation(**c) for c in dr_data.get("evidence_citations", [])
            ]
            dr = DriverRequirement(
                requirement_id=dr_data.get("requirement_id", ""),
                seed_id=dr_data.get("seed_id", ""),
                component_name=dr_data.get("component_name", ""),
                component_type=dr_data.get("component_type", ""),
                trigger_method=dr_data.get("trigger_method", ""),
                intent_action=dr_data.get("intent_action"),
                intent_extras=dr_data.get("intent_extras", []),
                expected_behavior=dr_data.get("expected_behavior", ""),
                observable_effects=dr_data.get("observable_effects", []),
                evidence_citations=citations,
                threat_category=dr_data.get("threat_category", "unknown"),
                automation_feasibility=dr_data.get("automation_feasibility", "full"),
            )
            driver_reqs.append(dr)

        return cls(
            case_id=data.get("case_id", ""),
            intent_verdict=IntentVerdict(data.get("intent_verdict", "insufficient_evidence")),
            confidence=data.get("confidence", 0.0),
            attack_chain_summary=data.get("attack_chain_summary", ""),
            attack_stages=data.get("attack_stages", []),
            evidence=data.get("evidence", []),
            driver_requirements=driver_reqs,
            aggregated_facts=data.get("aggregated_facts", []),
            uncertainties=data.get("uncertainties", []),
            threat_categories=data.get("threat_categories", []),
        )


# =============================================================================
# PHASE 2B: COMMAND GENERATION
# =============================================================================

@dataclass
class ExecutionStep:
    """A single step in the execution guidance."""
    step_id: str
    type: str  # "adb", "frida", "manual", "verify"
    description: str
    command: Optional[str] = None
    verify: Optional[Dict[str, Any]] = None
    evidence_citation: Optional[str] = None  # unit_id or seed_id reference
    notes: Optional[str] = None

    # For template-generated steps
    template_id: Optional[str] = None
    template_vars: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "step_id": self.step_id,
            "type": self.type,
            "description": self.description,
        }
        if self.command:
            result["command"] = self.command
        if self.verify:
            result["verify"] = self.verify
        if self.evidence_citation:
            result["evidence_citation"] = self.evidence_citation
        if self.notes:
            result["notes"] = self.notes
        if self.template_id:
            result["_template_id"] = self.template_id
        return result


@dataclass
class Phase2BOutput:
    """
    Output from Phase 2B: Command Generation.

    Contains concrete execution guidance for a single driver requirement.
    """
    # Links to Phase 2A
    requirement_id: str
    seed_id: str

    # Execution steps
    steps: List[ExecutionStep] = field(default_factory=list)
    manual_steps: List[ExecutionStep] = field(default_factory=list)

    # Overall feasibility
    automation_feasibility: str = "full"  # "full", "partial", "manual_investigation_required"

    # Warnings from command generation
    warnings: List[str] = field(default_factory=list)

    # Validation results (from post-QA)
    validated: bool = False
    validation_errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "requirement_id": self.requirement_id,
            "seed_id": self.seed_id,
            "steps": [s.to_dict() for s in self.steps],
            "manual_steps": [s.to_dict() for s in self.manual_steps],
            "automation_feasibility": self.automation_feasibility,
            "warnings": self.warnings,
            "validated": self.validated,
            "validation_errors": self.validation_errors,
            "schema_version": "2.0",
            "phase": "2b",
        }


@dataclass
class MergedTier2Output:
    """
    Merged Tier2 output for backward compatibility.

    Combines Phase 2A reasoning with Phase 2B commands into a format
    compatible with existing downstream consumers.
    """
    case_id: str

    # From Phase 2A
    intent_verdict: str
    attack_chain_summary: str
    evidence: List[Dict[str, Any]]
    threat_categories: List[str]

    # Merged execution guidance from Phase 2B
    execution_guidance: Dict[str, Any]
    # Per-seed execution guidance (one per driver requirement)
    execution_guidance_by_seed: List[Dict[str, Any]] = field(default_factory=list)

    # Debug info
    _phases: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "case_id": self.case_id,
            "intent_verdict": self.intent_verdict,
            "attack_chain_summary": self.attack_chain_summary,
            "evidence": self.evidence,
            "threat_categories": self.threat_categories,
            "execution_guidance": self.execution_guidance,
            "execution_guidance_by_seed": self.execution_guidance_by_seed,
            "_phases": self._phases,
            "schema_version": "2.0",
        }


def merge_phase_outputs(
    phase2a: Phase2AOutput,
    phase2b_outputs: List[Phase2BOutput],
    package_name: str,
) -> MergedTier2Output:
    """
    Merge Phase 2A and 2B outputs for backward compatibility.

    Args:
        phase2a: Output from Phase 2A reasoning
        phase2b_outputs: List of outputs from Phase 2B (one per driver requirement)
        package_name: Package name for execution guidance

    Returns:
        MergedTier2Output compatible with existing downstream consumers
    """
    # Merge all steps from Phase 2B outputs
    all_steps = []
    all_manual_steps = []

    for p2b in phase2b_outputs:
        all_steps.extend([s.to_dict() for s in p2b.steps])
        all_manual_steps.extend([s.to_dict() for s in p2b.manual_steps])

    # Build execution_guidance in legacy format
    execution_guidance = {
        "package_name": package_name,
        "steps": all_steps,
        "manual_steps": all_manual_steps,
        "overall_feasibility": _compute_overall_feasibility(phase2b_outputs),
    }

    req_by_id = {req.requirement_id: req for req in phase2a.driver_requirements}
    execution_guidance_by_seed: List[Dict[str, Any]] = []
    for p2b in phase2b_outputs:
        req = req_by_id.get(p2b.requirement_id)
        seed_id = p2b.seed_id or (req.seed_id if req else "")
        category_id = (req.threat_category if req else "unknown") or "unknown"
        execution_guidance_by_seed.append({
            "case_id": phase2a.case_id,
            "primary_seed_id": seed_id,
            "seed_ids": [seed_id] if seed_id else [],
            "category_id": category_id,
            "package_name": package_name,
            "target_capability": category_id,
            "environment_capabilities": {"adb_root": True, "frida_available": True},
            "prerequisites": [],
            "steps": [s.to_dict() for s in p2b.steps],
            "manual_steps": [s.to_dict() for s in p2b.manual_steps],
            "success_criteria": [],
            "cleanup": [],
            "automation_feasibility": p2b.automation_feasibility,
            "requirement_id": p2b.requirement_id,
            "component_name": req.component_name if req else "",
            "component_type": req.component_type if req else "",
            "intent_action": req.intent_action if req else None,
            "expected_behavior": req.expected_behavior if req else "",
        })

    return MergedTier2Output(
        case_id=phase2a.case_id,
        intent_verdict=phase2a.intent_verdict.value,
        attack_chain_summary=phase2a.attack_chain_summary,
        evidence=phase2a.evidence,
        threat_categories=phase2a.threat_categories,
        execution_guidance=execution_guidance,
        execution_guidance_by_seed=execution_guidance_by_seed,
        _phases={
            "2a": phase2a.to_dict(),
            "2b": [p.to_dict() for p in phase2b_outputs],
        },
    )


def _compute_overall_feasibility(phase2b_outputs: List[Phase2BOutput]) -> str:
    """Compute overall feasibility from all Phase 2B outputs."""
    if not phase2b_outputs:
        return "manual_investigation_required"

    feasibilities = [p.automation_feasibility for p in phase2b_outputs]

    if all(f == "full" for f in feasibilities):
        return "full"
    if any(f == "manual_investigation_required" for f in feasibilities):
        return "partial"  # Some are automatable, some aren't
    return "partial"

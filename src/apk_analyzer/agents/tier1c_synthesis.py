"""Tier1 Phase 1C: Evidence Synthesis Agent.

This module implements Phase 1C of the three-phase Tier1 analysis:
- Structural fields from 1A deterministics
- Behavioral fields from 1B claims (translation only)
- Deterministic confidence calculation

Fix 2: 1C can populate structural from 1A, behavioral from 1B only.
Fix 4: Explicit claim_id reference (not string matching).
Fix 15: Deterministic confidence formula.
Fix 16: Permission scope tracking.
Fix 18: Source fields for structural values.
Fix 23: Unified permission contracts via RequiredPermission.
Improvement C: from_deterministic fact type.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from apk_analyzer.models.analysis_context import TriggerSurface
from apk_analyzer.models.tier1_phases import (
    ExtractedStructure,
    Fact,
    InterpretedBehavior,
    InterpretedClaim,
    ObservableEffect,
    PathConstraint,
    PhaseStatus,
    RequiredInput,
)
from apk_analyzer.utils.confidence import compute_tier1_confidence

if TYPE_CHECKING:
    from apk_analyzer.agents.tier1_tool_registry import Tier1ToolRegistry

logger = logging.getLogger(__name__)


class Tier1CSynthesisAgent:
    """Phase 1C: Evidence Synthesis Agent.

    Synthesizes Tier1 output from 1A and 1B results.
    Fix 2: Structural from 1A, behavioral from 1B only.
    """

    def __init__(
        self,
        tool_registry: Optional["Tier1ToolRegistry"] = None,
    ) -> None:
        """Initialize the synthesis agent.

        Args:
            tool_registry: Optional tool registry for output writing.
        """
        self.tool_registry = tool_registry

    def run(
        self,
        seed_id: str,
        extracted: ExtractedStructure,
        interpreted: InterpretedBehavior,
    ) -> Dict[str, Any]:
        """Run Phase 1C synthesis.

        Fix 2: Structural fields from 1A, behavioral from 1B.
        Fix 15: Deterministic confidence formula.

        Args:
            seed_id: The seed ID.
            extracted: Phase 1A output.
            interpreted: Phase 1B output.

        Returns:
            Tier1 output dict.
        """
        logger.info(f"Phase 1C: Synthesizing output for seed {seed_id}")

        # Build structural fields from 1A (Fix 2)
        trigger_surface = self._build_trigger_surface(extracted)
        required_inputs = self._build_required_inputs(extracted, interpreted)

        # Build behavioral fields from 1B (Fix 2)
        path_constraints = self._build_path_constraints(interpreted)
        observable_effects = self._build_observable_effects(interpreted)

        # Build facts with proper lineage (Fix 4, Improvement C)
        facts = self._build_facts(extracted, interpreted)

        # Build uncertainties
        uncertainties = self._build_uncertainties(extracted, interpreted)

        # Compute confidence deterministically (Fix 15)
        confidence = compute_tier1_confidence(extracted, interpreted, facts)

        # Build function summary
        function_summary = self._build_function_summary(
            extracted, interpreted, observable_effects
        )

        # Assemble output
        output = {
            "seed_id": seed_id,
            "function_summary": function_summary,
            "trigger_surface": self._trigger_surface_to_dict(trigger_surface),
            "required_inputs": [self._required_input_to_dict(ri) for ri in required_inputs],
            "path_constraints": [self._path_constraint_to_dict(pc) for pc in path_constraints],
            "observable_effects": [self._observable_effect_to_dict(oe) for oe in observable_effects],
            "facts": [self._fact_to_dict(f) for f in facts],
            "uncertainties": uncertainties,
            "confidence": confidence,
            "phase_status": interpreted.phase_status.value,
            "extraction_coverage": extracted.extraction_coverage.value,
        }

        logger.info(
            f"Phase 1C complete for {seed_id}: "
            f"effects={len(observable_effects)}, facts={len(facts)}, "
            f"confidence={confidence}"
        )

        return output

    # =========================================================================
    # Structural Field Builders (from 1A)
    # =========================================================================

    def _build_trigger_surface(
        self,
        extracted: ExtractedStructure,
    ) -> TriggerSurface:
        """Build trigger surface from 1A component hints.

        Fix 2: Structural from 1A deterministics.
        Fix 18: Source fields for every value.
        """
        if extracted.component_hints:
            return TriggerSurface.from_hints(extracted.component_hints)

        # Fallback for missing hints
        return TriggerSurface(
            component_name="Unknown",
            component_name_source="inferred",
            component_type="Unknown",
            component_type_source="inferred",
            entrypoint_method="",
            entrypoint_method_source="inferred",
        )

    def _build_required_inputs(
        self,
        extracted: ExtractedStructure,
        interpreted: InterpretedBehavior,
    ) -> List[RequiredInput]:
        """Build required inputs from permissions and claims.

        Fix 16: Permission scope tracking.
        Fix 23: Use RequiredPermission as canonical source.
        """
        inputs: List[RequiredInput] = []

        # Add permissions from 1A (Fix 23)
        for perm in extracted.permissions:
            inputs.append(
                RequiredInput(
                    input_type="permission",
                    name=perm.permission,
                    scope=perm.scope,
                    evidence_unit_ids=perm.evidence_unit_ids,
                )
            )

        # Add inputs from 1B claims
        for claim in interpreted.claims:
            if claim.tier1_field == "required_inputs":
                inputs.append(
                    RequiredInput(
                        input_type="claim_input",
                        name=claim.interpretation,
                        evidence_unit_ids=claim.source_unit_ids,
                    )
                )

        return inputs

    # =========================================================================
    # Behavioral Field Builders (from 1B)
    # =========================================================================

    def _build_path_constraints(
        self,
        interpreted: InterpretedBehavior,
    ) -> List[PathConstraint]:
        """Build path constraints from 1B claims.

        Fix 2: Behavioral from 1B claims only.
        Fix 4: Use claim_id for lineage.
        """
        constraints: List[PathConstraint] = []

        for claim in interpreted.claims:
            if claim.tier1_field == "path_constraints" or claim.claim_type == "constraint":
                constraints.append(
                    PathConstraint(
                        constraint=claim.interpretation,
                        unit_ids=claim.source_unit_ids,
                        claim_id=claim.claim_id,
                    )
                )

        return constraints

    def _build_observable_effects(
        self,
        interpreted: InterpretedBehavior,
    ) -> List[ObservableEffect]:
        """Build observable effects from 1B claims.

        Fix 2: Behavioral from 1B claims only.
        Fix 4: Use claim_id for lineage.
        """
        effects: List[ObservableEffect] = []

        for claim in interpreted.claims:
            if claim.tier1_field == "observable_effects" or claim.claim_type == "effect":
                effects.append(
                    ObservableEffect(
                        effect=claim.interpretation,
                        unit_ids=claim.source_unit_ids,
                        claim_id=claim.claim_id,
                    )
                )

        return effects

    # =========================================================================
    # Fact Builders
    # =========================================================================

    def _build_facts(
        self,
        extracted: ExtractedStructure,
        interpreted: InterpretedBehavior,
    ) -> List[Fact]:
        """Build facts from 1A deterministics and 1B claims.

        Fix 4: Explicit claim_id reference.
        Improvement C: from_deterministic fact type.
        """
        facts: List[Fact] = []

        # Structural facts from 1A (Improvement C)
        if extracted.component_hints:
            facts.append(
                Fact(
                    statement=f"Component type is {extracted.component_hints.component_type}",
                    support_unit_ids=[],
                    claim_id=None,
                    from_deterministic=True,
                    fact_category="structural",
                    confidence=0.95,
                )
            )
            facts.append(
                Fact(
                    statement=f"Component name is {extracted.component_hints.component_name}",
                    support_unit_ids=[],
                    claim_id=None,
                    from_deterministic=True,
                    fact_category="structural",
                    confidence=0.95,
                )
            )

        # Permission facts from 1A
        for perm in extracted.permissions:
            facts.append(
                Fact(
                    statement=f"Requires permission: {perm.permission}",
                    support_unit_ids=perm.evidence_unit_ids,
                    claim_id=None,
                    from_deterministic=True,
                    fact_category="structural",
                    confidence=perm.confidence,
                )
            )

        # Behavioral facts from 1B claims (Fix 4)
        for claim in interpreted.claims:
            if not claim.needs_investigation:
                facts.append(
                    Fact(
                        statement=claim.interpretation,
                        support_unit_ids=claim.source_unit_ids,
                        claim_id=claim.claim_id,  # Explicit reference
                        from_deterministic=False,
                        fact_category="behavioral",
                        confidence=claim.confidence,
                    )
                )

        return facts

    def _build_uncertainties(
        self,
        extracted: ExtractedStructure,
        interpreted: InterpretedBehavior,
    ) -> List[str]:
        """Build uncertainty list."""
        uncertainties: List[str] = []

        # Add flagged items from extraction
        uncertainties.extend(extracted.flagged_for_review)

        # Add unresolved items from interpretation
        if interpreted.unresolved:
            uncertainties.append(
                f"Unresolved units: {len(interpreted.unresolved)}"
            )

        # Add unclaimed APIs
        if interpreted.unclaimed_apis:
            uncertainties.append(
                f"APIs without claims: {len(interpreted.unclaimed_apis)}"
            )

        # Add claims needing investigation
        needs_investigation = [c for c in interpreted.claims if c.needs_investigation]
        if needs_investigation:
            uncertainties.append(
                f"Unknown APIs requiring investigation: {len(needs_investigation)}"
            )

        return uncertainties

    def _build_function_summary(
        self,
        extracted: ExtractedStructure,
        interpreted: InterpretedBehavior,
        effects: List[ObservableEffect],
    ) -> str:
        """Build a function summary string."""
        if interpreted.phase_status == PhaseStatus.FAILED:
            return "Analysis incomplete: behavioral interpretation failed"

        if not effects:
            return "No observable effects identified"

        # Summarize main effects
        effect_summaries = [e.effect for e in effects[:3]]
        summary = "; ".join(effect_summaries)

        if len(effects) > 3:
            summary += f"; and {len(effects) - 3} more effects"

        return summary

    # =========================================================================
    # Serialization Helpers
    # =========================================================================

    def _trigger_surface_to_dict(self, ts: TriggerSurface) -> Dict[str, Any]:
        """Convert TriggerSurface to dict."""
        return {
            "component_name": ts.component_name,
            "component_name_source": ts.component_name_source,
            "component_type": ts.component_type,
            "component_type_source": ts.component_type_source,
            "entrypoint_method": ts.entrypoint_method,
            "entrypoint_method_source": ts.entrypoint_method_source,
        }

    def _required_input_to_dict(self, ri: RequiredInput) -> Dict[str, Any]:
        """Convert RequiredInput to dict."""
        return {
            "input_type": ri.input_type,
            "name": ri.name,
            "scope": ri.scope,
            "evidence_unit_ids": ri.evidence_unit_ids,
        }

    def _path_constraint_to_dict(self, pc: PathConstraint) -> Dict[str, Any]:
        """Convert PathConstraint to dict."""
        return {
            "constraint": pc.constraint,
            "unit_ids": pc.unit_ids,
            "claim_id": pc.claim_id,
        }

    def _observable_effect_to_dict(self, oe: ObservableEffect) -> Dict[str, Any]:
        """Convert ObservableEffect to dict."""
        return {
            "effect": oe.effect,
            "unit_ids": oe.unit_ids,
            "claim_id": oe.claim_id,
        }

    def _fact_to_dict(self, f: Fact) -> Dict[str, Any]:
        """Convert Fact to dict."""
        return {
            "statement": f.statement,
            "fact": f.statement,
            "support_unit_ids": f.support_unit_ids,
            "claim_id": f.claim_id,
            "from_deterministic": f.from_deterministic,
            "fact_category": f.fact_category,
            "confidence": f.confidence,
        }

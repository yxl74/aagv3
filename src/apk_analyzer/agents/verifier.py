"""Verifier Agent for Tier1 output validation.

Fix 10: SliceProvider interface for flexible slice access.
Supports both legacy context_bundle and new tool registry flows.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from apk_analyzer.agents.base import LLMClient
from apk_analyzer.analyzers.consistency_checker import consistency_check

if TYPE_CHECKING:
    from apk_analyzer.agents.tier1_tool_registry import Tier1ToolRegistry
    from apk_analyzer.utils.slice_provider import SliceProvider


class VerifierAgent:
    """Verifier agent for Tier1 output consistency checking.

    Supports two flows:
    - Legacy: run(tier1_summary, context_bundle) - uses BundleSliceProvider
    - New: run_by_seed_id(tier1_output, seed_id, tool_registry) - uses ToolRegistrySliceProvider
    """

    def __init__(self, prompt_path: str | Path, llm_client: Optional[LLMClient] = None) -> None:
        self.prompt_path = Path(prompt_path)
        self.llm_client = llm_client
        self.prompt = self.prompt_path.read_text(encoding="utf-8") if self.prompt_path.exists() else ""

    def run(self, tier1_summary: Dict[str, Any], context_bundle: Dict[str, Any]) -> Dict[str, Any]:
        """Legacy entry point using context bundle.

        Args:
            tier1_summary: Tier1 output to verify.
            context_bundle: Pre-loaded slice data bundle.

        Returns:
            Verification result dict.
        """
        check = consistency_check(tier1_summary, context_bundle)
        if not check["ok"]:
            return {
                "seed_id": tier1_summary.get("seed_id"),
                "status": "FAILED",
                "validated_facts": [],
                "rejected_facts": [f.get("fact") for f in tier1_summary.get("facts", [])],
                "repair_hint": check.get("repair_hint"),
                "missing_unit_ids": check.get("missing_unit_ids"),
                "mismatched_facts": check.get("mismatched_facts"),
            }
        return {
            "seed_id": tier1_summary.get("seed_id"),
            "status": "VERIFIED",
            "validated_facts": [f.get("fact") for f in tier1_summary.get("facts", [])],
            "rejected_facts": [],
            "mitre_candidates": [],
        }

    def run_by_seed_id(
        self,
        tier1_output: Dict[str, Any],
        seed_id: str,
        tool_registry: "Tier1ToolRegistry",
    ) -> Dict[str, Any]:
        """New entry point using tool registry (Fix 10).

        Args:
            tier1_output: Tier1 phase output to verify.
            seed_id: The seed ID for slice access.
            tool_registry: Tool registry for data access.

        Returns:
            Verification result dict.
        """
        from apk_analyzer.utils.slice_provider import ToolRegistrySliceProvider

        provider = ToolRegistrySliceProvider(seed_id, tool_registry)
        return self.consistency_check_with_provider(tier1_output, provider)

    def consistency_check_with_provider(
        self,
        tier1_output: Dict[str, Any],
        provider: "SliceProvider",
    ) -> Dict[str, Any]:
        """Consistency check using SliceProvider interface (Fix 10).

        Args:
            tier1_output: Tier1 output to verify.
            provider: SliceProvider implementation.

        Returns:
            Verification result dict with status and details.
        """
        seed_id = tier1_output.get("seed_id", "")
        facts = tier1_output.get("facts", [])

        # Collect all unit IDs referenced in facts
        all_unit_ids: List[str] = []
        for fact in facts:
            unit_ids = fact.get("support_unit_ids", [])
            all_unit_ids.extend(unit_ids)

        # Verify each unit exists in slice
        missing_unit_ids: List[str] = []
        mismatched_facts: List[Dict[str, Any]] = []

        for unit_id in set(all_unit_ids):
            unit_data = provider.get_unit(unit_id)
            if unit_data is None:
                missing_unit_ids.append(unit_id)

        # Check observable effects have corresponding slice data
        for effect in tier1_output.get("observable_effects", []):
            effect_unit_ids = effect.get("unit_ids", [])
            for uid in effect_unit_ids:
                if provider.get_unit(uid) is None:
                    if uid not in missing_unit_ids:
                        missing_unit_ids.append(uid)

        # Check path constraints have valid unit references
        for constraint in tier1_output.get("path_constraints", []):
            constraint_unit_ids = constraint.get("unit_ids", [])
            for uid in constraint_unit_ids:
                if provider.get_unit(uid) is None:
                    if uid not in missing_unit_ids:
                        missing_unit_ids.append(uid)

        if missing_unit_ids:
            return {
                "seed_id": seed_id,
                "status": "FAILED",
                "validated_facts": [],
                "rejected_facts": [f.get("statement") or f.get("fact") for f in facts],
                "repair_hint": f"Missing {len(missing_unit_ids)} unit IDs from slice",
                "missing_unit_ids": missing_unit_ids,
                "mismatched_facts": mismatched_facts,
            }

        return {
            "seed_id": seed_id,
            "status": "VERIFIED",
            "validated_facts": [f.get("statement") or f.get("fact") for f in facts],
            "rejected_facts": [],
            "mitre_candidates": [],
        }

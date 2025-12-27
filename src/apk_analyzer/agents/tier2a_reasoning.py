"""
Phase 2A: Attack Chain Reasoning Agent.

This agent analyzes consolidated Tier1 outputs to:
1. Determine overall malicious intent
2. Synthesize attack chain narrative
3. Extract structured driver requirements for Phase 2B
4. Aggregate and cite evidence

It does NOT generate execution commands - that's Phase 2B's job.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from apk_analyzer.agents.base import LLMClient
from apk_analyzer.models.tier2_phases import (
    DriverRequirement,
    EvidenceCitation,
    IntentVerdict,
    Phase2AOutput,
)
from apk_analyzer.observability.logger import EventLogger
from apk_analyzer.utils.llm_json import coerce_llm_dict, describe_llm_failure


class Tier2AReasoningAgent:
    """
    Phase 2A agent for attack chain reasoning.

    Processes consolidated Tier1 outputs to produce:
    - Intent verdict with confidence
    - Attack chain summary
    - Aggregated evidence with citations
    - Structured driver requirements for Phase 2B
    """

    def __init__(
        self,
        prompt_path: str | Path,
        llm_client: Optional[LLMClient] = None,
        model: Optional[str] = None,
        event_logger: EventLogger | None = None,
    ) -> None:
        self.prompt_path = Path(prompt_path)
        self.llm_client = llm_client
        self.model = model
        self.event_logger = event_logger
        self.prompt = self.prompt_path.read_text(encoding="utf-8") if self.prompt_path.exists() else ""

    def run(self, payload: Dict[str, Any]) -> Phase2AOutput:
        """
        Run Phase 2A reasoning on consolidated Tier1 outputs.

        Args:
            payload: Dict with:
                - case_id: Unique case identifier
                - package_name: APK package name
                - seeds: List of Tier1 outputs (with facts preserved)
                - validation: Pre-validation results (optional)

        Returns:
            Phase2AOutput with reasoning results and driver requirements
        """
        case_id = payload.get("case_id", "unknown")
        seeds = payload.get("seeds", [])

        if not self.llm_client:
            if self.event_logger:
                self.event_logger.log(
                    "llm.fallback",
                    llm_step="tier2a",
                    case_id=case_id,
                    error_type="disabled",
                )
            return self._build_fallback(case_id, seeds, "LLM disabled")

        response = self.llm_client.complete(self.prompt, payload, model=self.model)

        # Required keys for Phase 2A output
        required_keys = (
            "intent_verdict",
            "attack_chain_summary",
            "driver_requirements",
        )

        fallback_dict = self._build_fallback_dict(case_id, seeds, "LLM output invalid")

        result_dict = coerce_llm_dict(response, fallback_dict, required_keys=required_keys)

        if result_dict is fallback_dict:
            if self.event_logger:
                info = describe_llm_failure(response, required_keys=required_keys)
                self.event_logger.log(
                    "llm.fallback",
                    llm_step="tier2a",
                    case_id=case_id,
                    **(info or {"error_type": "invalid_output"}),
                )
            return self._build_fallback(case_id, seeds, "LLM output invalid")

        return self._parse_output(result_dict, case_id, seeds)

    def _parse_output(
        self,
        result: Dict[str, Any],
        case_id: str,
        seeds: List[Dict[str, Any]],
    ) -> Phase2AOutput:
        """Parse LLM output into Phase2AOutput."""
        # Parse intent verdict
        verdict_str = result.get("intent_verdict", "insufficient_evidence")
        try:
            verdict = IntentVerdict(verdict_str.lower().replace(" ", "_"))
        except ValueError:
            verdict = IntentVerdict.INSUFFICIENT_EVIDENCE

        # Parse driver requirements
        driver_reqs = []
        for req_data in result.get("driver_requirements", []):
            citations = []
            for cit in req_data.get("evidence_citations", []):
                citations.append(EvidenceCitation(
                    unit_id=cit.get("unit_id", ""),
                    seed_id=cit.get("seed_id", ""),
                    statement=cit.get("statement", ""),
                    interpretation=cit.get("interpretation", ""),
                ))

            dr = DriverRequirement(
                requirement_id=req_data.get("requirement_id", f"req_{len(driver_reqs)}"),
                seed_id=req_data.get("seed_id", ""),
                component_name=req_data.get("component_name", ""),
                component_type=req_data.get("component_type", "unknown"),
                trigger_method=req_data.get("trigger_method", "adb_start"),
                intent_action=req_data.get("intent_action"),
                intent_extras=req_data.get("intent_extras", []),
                expected_behavior=req_data.get("expected_behavior", ""),
                observable_effects=req_data.get("observable_effects", []),
                evidence_citations=citations,
                threat_category=req_data.get("threat_category", "unknown"),
                automation_feasibility=req_data.get("automation_feasibility", "full"),
            )
            driver_reqs.append(dr)

        # Aggregate facts from seeds
        aggregated_facts = []
        for seed in seeds:
            for fact in seed.get("facts", []):
                aggregated_facts.append({
                    **fact,
                    "seed_id": seed.get("seed_id", "unknown"),
                })

        return Phase2AOutput(
            case_id=case_id,
            intent_verdict=verdict,
            confidence=result.get("confidence", 0.0),
            attack_chain_summary=result.get("attack_chain_summary", ""),
            attack_stages=result.get("attack_stages", []),
            evidence=result.get("evidence", []),
            driver_requirements=driver_reqs,
            aggregated_facts=aggregated_facts,
            uncertainties=result.get("uncertainties", []),
            threat_categories=result.get("threat_categories", []),
        )

    def _build_fallback(
        self,
        case_id: str,
        seeds: List[Dict[str, Any]],
        reason: str,
    ) -> Phase2AOutput:
        """Build fallback Phase2AOutput when LLM fails."""
        # Create driver requirements from seed trigger surfaces
        driver_reqs = []
        for seed in seeds:
            trigger = seed.get("trigger_surface", {})
            if trigger.get("component_name"):
                dr = DriverRequirement(
                    requirement_id=f"fallback_{seed.get('seed_id', 'unknown')}",
                    seed_id=seed.get("seed_id", "unknown"),
                    component_name=trigger.get("component_name", ""),
                    component_type=trigger.get("component_type", "unknown"),
                    trigger_method="adb_start",
                    expected_behavior=seed.get("function_summary", "Unknown behavior"),
                    automation_feasibility="manual_investigation_required",
                )
                driver_reqs.append(dr)

        return Phase2AOutput(
            case_id=case_id,
            intent_verdict=IntentVerdict.INSUFFICIENT_EVIDENCE,
            confidence=0.0,
            attack_chain_summary=f"Fallback: {reason}",
            driver_requirements=driver_reqs,
            uncertainties=[reason],
        )

    def _build_fallback_dict(
        self,
        case_id: str,
        seeds: List[Dict[str, Any]],
        reason: str,
    ) -> Dict[str, Any]:
        """Build fallback dict for coerce_llm_dict."""
        return {
            "case_id": case_id,
            "intent_verdict": "insufficient_evidence",
            "confidence": 0.0,
            "attack_chain_summary": f"Fallback: {reason}",
            "attack_stages": [],
            "evidence": [],
            "driver_requirements": [],
            "uncertainties": [reason],
            "threat_categories": [],
        }

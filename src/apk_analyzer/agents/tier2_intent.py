from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from apk_analyzer.agents.base import LLMClient
from apk_analyzer.observability.logger import EventLogger
from apk_analyzer.utils.llm_json import coerce_llm_dict, describe_llm_failure


class Tier2IntentAgent:
    """
    Tier-2 intent agent for case-level analysis.

    Processes cases (groups of related seeds) to produce unified driver guidance.
    Supports both single-seed and multi-seed case inputs.
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

    def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        # Extract case-level identifiers
        case_id = payload.get("case_id") or payload.get("seed_id", "unknown")
        primary_seed_id = payload.get("primary_seed_id") or payload.get("seed_id", "unknown")
        seeds = payload.get("seeds", [])
        seed_ids = [s.get("seed_id") for s in seeds] if seeds else [primary_seed_id]

        if not self.llm_client:
            if self.event_logger:
                self.event_logger.log(
                    "llm.fallback",
                    llm_step="tier2",
                    case_id=case_id,
                    seed_id=primary_seed_id,
                    error_type="disabled",
                )
            return self._build_fallback(
                case_id=case_id,
                primary_seed_id=primary_seed_id,
                seed_ids=seed_ids,
                reason="LLM disabled; no intent inference.",
                flowdroid_summary=payload.get("flowdroid_summary") or {},
                package_name=payload.get("static_context", {}).get("package_name", ""),
            )

        response = self.llm_client.complete(self.prompt, payload, model=self.model)

        fallback = self._build_fallback(
            case_id=case_id,
            primary_seed_id=primary_seed_id,
            seed_ids=seed_ids,
            reason="LLM output invalid; no intent inference.",
            flowdroid_summary=payload.get("flowdroid_summary") or {},
            package_name=payload.get("static_context", {}).get("package_name", ""),
        )

        # Required keys for case-level output
        # Note: Some keys are optional for backwards compatibility
        required_keys = (
            "intent_verdict",
            "rationale",
            "driver_plan",
        )

        result = coerce_llm_dict(response, fallback, required_keys=required_keys)

        # Ensure case-level fields are present
        if result is not fallback:
            result.setdefault("case_id", case_id)
            result.setdefault("primary_seed_id", primary_seed_id)
            result.setdefault("seed_ids_analyzed", seed_ids)
            result.setdefault("attack_chain_summary", "")
            result.setdefault("evidence", [])
            result.setdefault("environment_setup", [])
            result.setdefault("execution_checks", [])
            result.setdefault("taint_recommended", False)
            result.setdefault("taint_question", "")
            # Keep flowdroid_summary from input if not in output
            if "flowdroid_summary" not in result:
                result["flowdroid_summary"] = payload.get("flowdroid_summary") or {}
            # Ensure execution_guidance is present (skeleton if LLM omitted it)
            if "execution_guidance" not in result:
                result["execution_guidance"] = {
                    "case_id": case_id,
                    "primary_seed_id": primary_seed_id,
                    "seed_ids": seed_ids,
                    "category_id": "",
                    "package_name": payload.get("static_context", {}).get("package_name", ""),
                    "target_capability": "",
                    "environment_capabilities": {"adb_root": True, "frida_available": True},
                    "prerequisites": [],
                    "steps": [],
                    "success_criteria": [],
                    "cleanup": [],
                }

        if result is fallback and self.event_logger:
            info = describe_llm_failure(response, required_keys=required_keys)
            payload_info = info or {"error_type": "invalid_output"}
            self.event_logger.log(
                "llm.fallback",
                llm_step="tier2",
                case_id=case_id,
                seed_id=primary_seed_id,
                **payload_info,
            )

        return result

    def _build_fallback(
        self,
        case_id: str,
        primary_seed_id: str,
        seed_ids: List[str],
        reason: str,
        flowdroid_summary: Dict[str, Any],
        package_name: str = "",
    ) -> Dict[str, Any]:
        """Build fallback response for case-level Tier2."""
        return {
            # Case-level identifiers
            "case_id": case_id,
            "primary_seed_id": primary_seed_id,
            "seed_ids_analyzed": seed_ids,
            # Verdict and reasoning
            "intent_verdict": "unknown",
            "attack_chain_summary": "",
            "rationale": [reason],
            "evidence": [],
            # Driver guidance
            "driver_plan": [],
            "environment_setup": [],
            "execution_checks": [],
            # Taint analysis
            "taint_recommended": False,
            "taint_question": "",
            "flowdroid_summary": flowdroid_summary,
            # Execution guidance skeleton for Qwen runner
            "execution_guidance": {
                "case_id": case_id,
                "primary_seed_id": primary_seed_id,
                "seed_ids": seed_ids,
                "category_id": "",
                "package_name": package_name,
                "target_capability": "",
                "environment_capabilities": {"adb_root": True, "frida_available": True},
                "prerequisites": [],
                "steps": [],
                "success_criteria": [],
                "cleanup": [],
            },
        }

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from apk_analyzer.agents.base import LLMClient
from apk_analyzer.observability.logger import EventLogger
from apk_analyzer.utils.llm_json import coerce_llm_dict, describe_llm_failure


class Tier2IntentAgent:
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
        if not self.llm_client:
            if self.event_logger:
                self.event_logger.log(
                    "llm.fallback",
                    llm_step="tier2",
                    seed_id=payload.get("seed_id"),
                    error_type="disabled",
                )
            return {
                "seed_id": payload.get("seed_id"),
                "intent_verdict": "likely_legitimate",
                "rationale": ["LLM disabled; no intent inference."],
                "evidence": [],
                "driver_plan": [],
                "environment_setup": [],
                "execution_checks": [],
                "taint_recommended": False,
                "taint_question": "",
                "flowdroid_summary": payload.get("flowdroid_summary") or {},
            }
        response = self.llm_client.complete(self.prompt, payload, model=self.model)
        fallback = {
            "seed_id": payload.get("seed_id"),
            "intent_verdict": "unknown",
            "rationale": ["LLM output invalid; no intent inference."],
            "evidence": [],
            "driver_plan": [],
            "environment_setup": [],
            "execution_checks": [],
            "taint_recommended": False,
            "taint_question": "",
            "flowdroid_summary": payload.get("flowdroid_summary") or {},
        }
        result = coerce_llm_dict(
            response,
            fallback,
            required_keys=(
                "seed_id",
                "intent_verdict",
                "rationale",
                "evidence",
                "driver_plan",
                "environment_setup",
                "execution_checks",
                "taint_recommended",
                "taint_question",
                "flowdroid_summary",
            ),
        )
        if result is fallback and self.event_logger:
            info = describe_llm_failure(
                response,
                required_keys=(
                    "seed_id",
                    "intent_verdict",
                    "rationale",
                    "evidence",
                    "driver_plan",
                    "environment_setup",
                    "execution_checks",
                    "taint_recommended",
                    "taint_question",
                    "flowdroid_summary",
                ),
            )
            payload_info = info or {"error_type": "invalid_output"}
            self.event_logger.log(
                "llm.fallback",
                llm_step="tier2",
                seed_id=payload.get("seed_id"),
                **payload_info,
            )
        return result

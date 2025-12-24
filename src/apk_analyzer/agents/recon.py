from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from apk_analyzer.agents.base import LLMClient
from apk_analyzer.observability.logger import EventLogger
from apk_analyzer.utils.llm_json import coerce_llm_dict, describe_llm_failure, parse_llm_json


class ReconAgent:
    def __init__(
        self,
        prompt_path: str | Path,
        llm_client: Optional[LLMClient] = None,
        model: Optional[str] = None,
        tool_runner: Optional[Any] = None,
        max_tool_rounds: int = 2,
        event_logger: EventLogger | None = None,
    ) -> None:
        self.prompt_path = Path(prompt_path)
        self.llm_client = llm_client
        self.model = model
        self.tool_runner = tool_runner
        self.max_tool_rounds = max_tool_rounds
        self.event_logger = event_logger
        self.prompt = self.prompt_path.read_text(encoding="utf-8") if self.prompt_path.exists() else ""

    def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.llm_client:
            if self.event_logger:
                self.event_logger.log(
                    "llm.fallback",
                    llm_step="recon",
                    seed_id=None,
                    error_type="disabled",
                )
            return {
                "mode": "final",
                "risk_score": 0.1,
                "threat_level": "LOW",
                "cases": [],
                "investigation_plan": ["LLM disabled; skipping recon prioritization."],
                "_meta": {"llm_valid": False, "fallback_reason": "disabled"},
            }
        working_payload = dict(payload)
        tool_history: list[dict[str, Any]] = []
        fallback_invalid = {
            "mode": "final",
            "risk_score": 0.1,
            "threat_level": "LOW",
            "cases": [],
            "investigation_plan": ["LLM output invalid; using fallback."],
            "_meta": {"llm_valid": False, "fallback_reason": "invalid_json"},
        }
        fallback_missing = {
            "mode": "final",
            "risk_score": 0.1,
            "threat_level": "LOW",
            "cases": [],
            "investigation_plan": ["LLM output missing required keys; using fallback."],
            "_meta": {"llm_valid": False, "fallback_reason": "missing_keys"},
        }
        for _ in range(self.max_tool_rounds + 1):
            response = self.llm_client.complete(self.prompt, working_payload, model=self.model)
            data = parse_llm_json(response)
            if not isinstance(data, dict) or data.get("_error"):
                if self.event_logger:
                    info = describe_llm_failure(response)
                    payload_info = info or {"error_type": "invalid_output"}
                    self.event_logger.log(
                        "llm.fallback",
                        llm_step="recon",
                        seed_id=None,
                        **payload_info,
                    )
                return fallback_invalid
            mode = data.get("mode", "final")
            tool_requests = data.get("tool_requests") or []
            if mode == "tool_request" and self.tool_runner and tool_requests:
                results = self.tool_runner.run(tool_requests)
                tool_history.append({
                    "requests": tool_requests,
                    "results": results,
                })
                working_payload["tool_results"] = tool_history
                continue
            final = coerce_llm_dict(
                data,
                fallback_missing,
                required_keys=("risk_score", "threat_level", "cases", "investigation_plan"),
            )
            if final is fallback_missing and self.event_logger:
                info = describe_llm_failure(
                    data,
                    required_keys=("risk_score", "threat_level", "cases", "investigation_plan"),
                )
                payload_info = info or {"error_type": "missing_keys"}
                self.event_logger.log(
                    "llm.fallback",
                    llm_step="recon",
                    seed_id=None,
                    **payload_info,
                )
                return fallback_missing
            final.setdefault("mode", "final")
            final.setdefault("_meta", {"llm_valid": True})
            return final
        if self.event_logger:
            self.event_logger.log(
                "llm.fallback",
                llm_step="recon",
                seed_id=None,
                error_type="max_tool_rounds_exceeded",
            )
        return fallback_invalid

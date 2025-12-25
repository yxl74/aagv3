from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from apk_analyzer.agents.base import LLMClient
from apk_analyzer.observability.logger import EventLogger
from apk_analyzer.utils.llm_json import coerce_llm_dict, describe_llm_failure, parse_llm_json


REQUIRED_KEYS = (
    "seed_id",
    "function_summary",
    "path_constraints",
    "required_inputs",
    "trigger_surface",
    "observable_effects",
    "facts",
    "uncertainties",
    "confidence",
)


class Tier1SummarizerAgent:
    """
    Tier1 summarizer agent for analyzing code bundles.

    Supports optional tool access for repair passes when initial analysis
    fails verification or has low confidence.
    """

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

    def _make_fallback(self, payload: Dict[str, Any], reason: str) -> Dict[str, Any]:
        """Create a fallback response."""
        return {
            "seed_id": payload.get("seed_id"),
            "function_summary": f"LLM {reason}; no summary generated.",
            "path_constraints": [],
            "required_inputs": [],
            "trigger_surface": {},
            "observable_effects": [],
            "facts": [],
            "uncertainties": [f"LLM {reason}"],
            "confidence": 0.0,
        }

    def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run Tier1 analysis on a context bundle.

        If tool_runner is provided, supports tool request/response loop
        for fetching additional context (e.g., JADX source code).
        """
        seed_id = payload.get("seed_id")

        if not self.llm_client:
            if self.event_logger:
                self.event_logger.log(
                    "llm.fallback",
                    llm_step="tier1",
                    seed_id=seed_id,
                    error_type="disabled",
                )
            return self._make_fallback(payload, "disabled")

        working_payload = dict(payload)
        tool_history: List[Dict[str, Any]] = []
        fallback_invalid = self._make_fallback(payload, "output invalid")

        # Tool loop: handle tool_request mode
        for round_num in range(self.max_tool_rounds + 1):
            response = self.llm_client.complete(self.prompt, working_payload, model=self.model)
            data = parse_llm_json(response)

            # Handle parse errors
            if not isinstance(data, dict) or data.get("_error"):
                if self.event_logger:
                    info = describe_llm_failure(response)
                    self.event_logger.log(
                        "llm.fallback",
                        llm_step="tier1",
                        seed_id=seed_id,
                        round=round_num,
                        **(info or {"error_type": "invalid_json"}),
                    )
                return fallback_invalid

            mode = data.get("mode", "final")
            tool_requests = data.get("tool_requests") or []

            # Handle tool requests
            if mode == "tool_request" and self.tool_runner and tool_requests:
                results = self.tool_runner.run(tool_requests, seed_id=seed_id)
                tool_history.append({
                    "round": round_num,
                    "requests": tool_requests,
                    "results": results,
                })
                working_payload["tool_results"] = results
                continue

            # Final result - validate and return
            result = coerce_llm_dict(data, fallback_invalid, required_keys=REQUIRED_KEYS)

            if result is fallback_invalid:
                if self.event_logger:
                    info = describe_llm_failure(data, required_keys=REQUIRED_KEYS)
                    self.event_logger.log(
                        "llm.fallback",
                        llm_step="tier1",
                        seed_id=seed_id,
                        **(info or {"error_type": "missing_keys"}),
                    )
                return fallback_invalid

            # Attach metadata
            result.setdefault("mode", "final")
            meta = result.setdefault("_meta", {})
            meta["llm_valid"] = True
            if tool_history:
                meta["tool_history"] = tool_history

            return result

        # Max rounds exceeded
        if self.event_logger:
            self.event_logger.log(
                "llm.fallback",
                llm_step="tier1",
                seed_id=seed_id,
                error_type="max_tool_rounds_exceeded",
                tool_rounds=len(tool_history),
            )
        return fallback_invalid

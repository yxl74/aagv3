from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from apk_analyzer.agents.base import LLMClient
from apk_analyzer.observability.logger import EventLogger
from apk_analyzer.utils.llm_json import coerce_llm_dict, describe_llm_failure, parse_llm_json


class PackageScopeAgent:
    """
    Optional agent that selects which package prefixes should be treated as "in-scope" app code.

    This is intended to reduce false negatives when APK package_name doesn't match the Java
    implementation packages, and to avoid flooding downstream stages with generic SDK code.
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
        if not self.llm_client:
            if self.event_logger:
                self.event_logger.log(
                    "llm.fallback",
                    llm_step="package_scope",
                    seed_id=None,
                    error_type="disabled",
                )
            return {
                "mode": "final",
                "analyze_prefixes": [],
                "ignore_prefixes": [],
                "confidence": 0.0,
                "rationale": "LLM disabled; using heuristic package scope.",
                "_meta": {"llm_valid": False, "fallback_reason": "disabled"},
            }

        fallback_invalid = {
            "mode": "final",
            "analyze_prefixes": [],
            "ignore_prefixes": [],
            "confidence": 0.0,
            "rationale": "LLM output invalid; using heuristic package scope.",
            "_meta": {"llm_valid": False, "fallback_reason": "invalid_json"},
        }
        fallback_missing = {
            "mode": "final",
            "analyze_prefixes": [],
            "ignore_prefixes": [],
            "confidence": 0.0,
            "rationale": "LLM output missing required keys; using heuristic package scope.",
            "_meta": {"llm_valid": False, "fallback_reason": "missing_keys"},
        }

        response = self.llm_client.complete(self.prompt, payload, model=self.model)
        data = parse_llm_json(response)
        if not isinstance(data, dict) or data.get("_error"):
            if self.event_logger:
                info = describe_llm_failure(response)
                payload_info = info or {"error_type": "invalid_output"}
                self.event_logger.log(
                    "llm.fallback",
                    llm_step="package_scope",
                    seed_id=None,
                    **payload_info,
                )
            return fallback_invalid

        final = coerce_llm_dict(
            data,
            fallback_missing,
            required_keys=("analyze_prefixes", "ignore_prefixes", "confidence", "rationale"),
        )
        if final is fallback_missing and self.event_logger:
            info = describe_llm_failure(
                data,
                required_keys=("analyze_prefixes", "ignore_prefixes", "confidence", "rationale"),
            )
            payload_info = info or {"error_type": "missing_keys"}
            self.event_logger.log(
                "llm.fallback",
                llm_step="package_scope",
                seed_id=None,
                **payload_info,
            )
            return fallback_missing

        final.setdefault("mode", "final")
        meta = final.setdefault("_meta", {})
        if isinstance(meta, dict):
            meta.setdefault("llm_valid", True)
        return final

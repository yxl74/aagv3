from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from apk_analyzer.agents.base import LLMClient
from apk_analyzer.observability.logger import EventLogger
from apk_analyzer.utils.llm_json import coerce_llm_dict, describe_llm_failure


class ReportAgent:
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
                    llm_step="report",
                    seed_id=payload.get("analysis_id"),
                    error_type="disabled",
                )
            return {
                "analysis_id": payload.get("analysis_id"),
                "verdict": payload.get("verdict", "UNKNOWN"),
                "summary": payload.get("summary", "Report generated without LLM."),
                "seed_summaries": payload.get("seed_summaries", []),
                "evidence_support_index": payload.get("evidence_support_index", {}),
                "analysis_artifacts": payload.get("analysis_artifacts", {}),
                "mitre_candidates": payload.get("mitre_candidates", []),
                "driver_guidance": payload.get("driver_guidance", []),
            }
        response = self.llm_client.complete(self.prompt, payload, model=self.model)
        fallback = {
            "analysis_id": payload.get("analysis_id"),
            "verdict": payload.get("verdict", "UNKNOWN"),
            "summary": payload.get("summary", "LLM output invalid; report fallback."),
            "seed_summaries": payload.get("seed_summaries", []),
            "evidence_support_index": payload.get("evidence_support_index", {}),
            "analysis_artifacts": payload.get("analysis_artifacts", {}),
            "mitre_candidates": payload.get("mitre_candidates", []),
            "driver_guidance": payload.get("driver_guidance", []),
        }
        result = coerce_llm_dict(
            response,
            fallback,
            required_keys=(
                "analysis_id",
                "verdict",
                "summary",
                "seed_summaries",
                "evidence_support_index",
                "analysis_artifacts",
                "mitre_candidates",
                "driver_guidance",
            ),
        )
        if result is fallback and self.event_logger:
            info = describe_llm_failure(
                response,
                required_keys=(
                    "analysis_id",
                    "verdict",
                    "summary",
                    "seed_summaries",
                    "evidence_support_index",
                    "analysis_artifacts",
                    "mitre_candidates",
                    "driver_guidance",
                ),
            )
            payload_info = info or {"error_type": "invalid_output"}
            self.event_logger.log(
                "llm.fallback",
                llm_step="report",
                seed_id=payload.get("analysis_id"),
                **payload_info,
            )
        return result

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from apk_analyzer.agents.base import LLMClient
from apk_analyzer.observability.logger import EventLogger
from apk_analyzer.utils.llm_json import coerce_llm_dict, describe_llm_failure


def _compact_seed_summaries(seed_summaries: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    compact = []
    for summary in seed_summaries or []:
        tier1 = summary.get("tier1") or {}
        tier2 = summary.get("tier2") or {}
        compact.append({
            "seed_id": summary.get("seed_id"),
            "case_id": summary.get("case_id"),
            "category_id": summary.get("category_id"),
            "tier1": {
                "function_summary": tier1.get("function_summary"),
                "facts": tier1.get("facts", []),
                "confidence": tier1.get("confidence"),
            },
            "tier2": {
                "intent_verdict": tier2.get("intent_verdict"),
                "attack_chain_summary": tier2.get("attack_chain_summary"),
                "rationale": tier2.get("rationale", []),
                "evidence": tier2.get("evidence", []),
            },
        })
    return compact


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
        report = dict(payload)
        if not self.llm_client:
            if self.event_logger:
                self.event_logger.log(
                    "llm.fallback",
                    llm_step="report",
                    seed_id=payload.get("analysis_id"),
                    error_type="disabled",
                )
            report.setdefault("verdict", payload.get("verdict", "UNKNOWN"))
            report.setdefault("summary", payload.get("summary", "Report generated without LLM."))
            return report

        llm_payload = {
            "verdict": payload.get("verdict", "UNKNOWN"),
            "summary": payload.get("summary", ""),
            "analysis_id": payload.get("analysis_id"),
            "seed_summaries": _compact_seed_summaries(payload.get("seed_summaries", [])),
            "evidence_support_index": payload.get("evidence_support_index", {}),
            "analysis_artifacts": payload.get("analysis_artifacts", {}),
            "mitre_candidates": payload.get("mitre_candidates", []),
        }

        response = self.llm_client.complete(self.prompt, llm_payload, model=self.model)
        fallback = {
            "verdict": payload.get("verdict", "UNKNOWN"),
            "summary": payload.get("summary", "LLM output invalid; report fallback."),
            "insights": [],
        }
        result = coerce_llm_dict(
            response,
            fallback,
            required_keys=("verdict", "summary"),
        )
        if result is fallback and self.event_logger:
            info = describe_llm_failure(
                response,
                required_keys=("verdict", "summary"),
            )
            payload_info = info or {"error_type": "invalid_output"}
            self.event_logger.log(
                "llm.fallback",
                llm_step="report",
                seed_id=payload.get("analysis_id"),
                **payload_info,
            )

        report["verdict"] = result.get("verdict", report.get("verdict"))
        report["summary"] = result.get("summary", report.get("summary"))
        if "insights" in result:
            report["insights"] = result["insights"]
        return report

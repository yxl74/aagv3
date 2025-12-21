from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from apk_analyzer.agents.base import LLMClient


class ReportAgent:
    def __init__(self, prompt_path: str | Path, llm_client: Optional[LLMClient] = None) -> None:
        self.prompt_path = Path(prompt_path)
        self.llm_client = llm_client
        self.prompt = self.prompt_path.read_text(encoding="utf-8") if self.prompt_path.exists() else ""

    def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.llm_client:
            return {
                "analysis_id": payload.get("analysis_id"),
                "verdict": payload.get("verdict", "UNKNOWN"),
                "summary": payload.get("summary", "Report generated without LLM."),
                "seed_summaries": payload.get("seed_summaries", []),
                "evidence_support_index": payload.get("evidence_support_index", {}),
                "analysis_artifacts": payload.get("analysis_artifacts", {}),
            }
        response = self.llm_client.complete(self.prompt, payload)
        if isinstance(response, str):
            return json.loads(response)
        return response

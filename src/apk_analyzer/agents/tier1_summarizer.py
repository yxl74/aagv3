from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from apk_analyzer.agents.base import LLMClient


class Tier1SummarizerAgent:
    def __init__(self, prompt_path: str | Path, llm_client: Optional[LLMClient] = None) -> None:
        self.prompt_path = Path(prompt_path)
        self.llm_client = llm_client
        self.prompt = self.prompt_path.read_text(encoding="utf-8") if self.prompt_path.exists() else ""

    def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.llm_client:
            return {
                "seed_id": payload.get("seed_id"),
                "function_summary": "LLM disabled; no summary generated.",
                "facts": [],
                "uncertainties": ["LLM disabled"],
                "confidence": 0.0,
            }
        response = self.llm_client.complete(self.prompt, payload)
        if isinstance(response, str):
            return json.loads(response)
        return response

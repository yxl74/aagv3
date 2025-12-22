from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from apk_analyzer.agents.base import LLMClient
from apk_analyzer.utils.llm_json import coerce_llm_dict


class ReconAgent:
    def __init__(
        self,
        prompt_path: str | Path,
        llm_client: Optional[LLMClient] = None,
        model: Optional[str] = None,
    ) -> None:
        self.prompt_path = Path(prompt_path)
        self.llm_client = llm_client
        self.model = model
        self.prompt = self.prompt_path.read_text(encoding="utf-8") if self.prompt_path.exists() else ""

    def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.llm_client:
            return {
                "risk_score": 0.1,
                "threat_level": "LOW",
                "prioritized_seeds": [],
                "investigation_plan": ["LLM disabled; skipping recon prioritization."],
            }
        response = self.llm_client.complete(self.prompt, payload, model=self.model)
        fallback = {
            "risk_score": 0.1,
            "threat_level": "LOW",
            "prioritized_seeds": [],
            "investigation_plan": ["LLM output invalid; using fallback."],
        }
        return coerce_llm_dict(
            response,
            fallback,
            required_keys=("risk_score", "threat_level", "prioritized_seeds", "investigation_plan"),
        )

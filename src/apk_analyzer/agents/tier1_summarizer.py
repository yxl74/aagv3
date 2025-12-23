from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from apk_analyzer.agents.base import LLMClient
from apk_analyzer.utils.llm_json import coerce_llm_dict


class Tier1SummarizerAgent:
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
                "seed_id": payload.get("seed_id"),
                "function_summary": "LLM disabled; no summary generated.",
                "path_constraints": [],
                "required_inputs": [],
                "trigger_surface": {},
                "observable_effects": [],
                "facts": [],
                "uncertainties": ["LLM disabled"],
                "confidence": 0.0,
            }
        response = self.llm_client.complete(self.prompt, payload, model=self.model)
        fallback = {
            "seed_id": payload.get("seed_id"),
            "function_summary": "LLM output invalid; no summary generated.",
            "path_constraints": [],
            "required_inputs": [],
            "trigger_surface": {},
            "observable_effects": [],
            "facts": [],
            "uncertainties": ["LLM output invalid"],
            "confidence": 0.0,
        }
        return coerce_llm_dict(
            response,
            fallback,
            required_keys=(
                "seed_id",
                "function_summary",
                "path_constraints",
                "required_inputs",
                "trigger_surface",
                "observable_effects",
                "facts",
                "uncertainties",
                "confidence",
            ),
        )

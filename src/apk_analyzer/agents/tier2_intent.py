from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from apk_analyzer.agents.base import LLMClient
from apk_analyzer.utils.llm_json import coerce_llm_dict


class Tier2IntentAgent:
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
                "intent_verdict": "likely_legitimate",
                "rationale": ["LLM disabled; no intent inference."],
                "evidence": [],
                "taint_recommended": False,
                "taint_question": "",
            }
        response = self.llm_client.complete(self.prompt, payload, model=self.model)
        fallback = {
            "seed_id": payload.get("seed_id"),
            "intent_verdict": "unknown",
            "rationale": ["LLM output invalid; no intent inference."],
            "evidence": [],
            "taint_recommended": False,
            "taint_question": "",
        }
        return coerce_llm_dict(
            response,
            fallback,
            required_keys=(
                "seed_id",
                "intent_verdict",
                "rationale",
                "evidence",
                "taint_recommended",
                "taint_question",
            ),
        )

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from apk_analyzer.agents.base import LLMClient
from apk_analyzer.analyzers.consistency_checker import consistency_check


class VerifierAgent:
    def __init__(self, prompt_path: str | Path, llm_client: Optional[LLMClient] = None) -> None:
        self.prompt_path = Path(prompt_path)
        self.llm_client = llm_client
        self.prompt = self.prompt_path.read_text(encoding="utf-8") if self.prompt_path.exists() else ""

    def run(self, tier1_summary: Dict[str, Any], context_bundle: Dict[str, Any]) -> Dict[str, Any]:
        check = consistency_check(tier1_summary, context_bundle)
        if not check["ok"]:
            return {
                "seed_id": tier1_summary.get("seed_id"),
                "status": "FAILED",
                "validated_facts": [],
                "rejected_facts": [f.get("fact") for f in tier1_summary.get("facts", [])],
                "repair_hint": check.get("repair_hint"),
                "missing_unit_ids": check.get("missing_unit_ids"),
                "mismatched_facts": check.get("mismatched_facts"),
            }
        return {
            "seed_id": tier1_summary.get("seed_id"),
            "status": "VERIFIED",
            "validated_facts": [f.get("fact") for f in tier1_summary.get("facts", [])],
            "rejected_facts": [],
            "mitre_candidates": [],
        }

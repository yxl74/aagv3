from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List


def load_rules(path: str | Path) -> Dict[str, Any]:
    path = Path(path)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_technique_index(path: str | Path) -> Dict[str, Any]:
    path = Path(path)
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def map_evidence(
    evidence_items: Iterable[Dict[str, Any]],
    rules: Dict[str, Any],
    technique_index: Dict[str, Any],
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    category_rules = rules.get("category_rules", {})
    keyword_rules = rules.get("keyword_rules", {})

    for item in evidence_items:
        category = item.get("category")
        claim = (item.get("claim") or item.get("fact") or "").lower()
        support_unit_ids = item.get("support_unit_ids", [])

        if category and category in category_rules:
            for rule in category_rules[category]:
                results.append({
                    "technique_id": rule.get("technique_id"),
                    "why": rule.get("why"),
                    "support_unit_ids": support_unit_ids,
                })
        for keyword, rule in keyword_rules.items():
            if keyword in claim:
                results.append({
                    "technique_id": rule.get("technique_id"),
                    "why": rule.get("why"),
                    "support_unit_ids": support_unit_ids,
                })

    # Enrich with technique names if available
    for result in results:
        info = technique_index.get(result["technique_id"], {})
        if info:
            result.setdefault("technique_name", info.get("name"))
            result.setdefault("tactics", info.get("tactics"))
    return results

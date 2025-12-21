from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")


def _tokenize(text: str) -> List[str]:
    tokens = re.findall(r"[a-zA-Z0-9_.$]+", text.lower())
    return [t for t in tokens if len(t) > 2]


def consistency_check(tier1_summary: Dict[str, Any], context_bundle: Dict[str, Any]) -> Dict[str, Any]:
    slice_units = context_bundle.get("sliced_cfg", {}).get("units", [])
    unit_map = {u.get("unit_id"): u.get("stmt", "") for u in slice_units}
    missing_unit_ids = []
    mismatched_facts = []
    strings_nearby = set(context_bundle.get("static_context", {}).get("strings_nearby", []))

    for fact in tier1_summary.get("facts", []):
        fact_text = fact.get("fact", "")
        support_ids = fact.get("support_unit_ids", [])
        for uid in support_ids:
            if uid not in unit_map:
                missing_unit_ids.append(uid)
        if support_ids:
            combined_stmt = " ".join([unit_map.get(uid, "") for uid in support_ids])
        else:
            combined_stmt = ""
        fact_tokens = _tokenize(fact_text)
        if fact_tokens and combined_stmt:
            if not any(token in combined_stmt.lower() for token in fact_tokens):
                mismatched_facts.append({"fact": fact_text, "reason": "No token overlap with supporting statements"})
        for regex, label in ((
            _URL_RE,
            "url",
        ), (_IP_RE, "ip"), (_DOMAIN_RE, "domain")):
            matches = regex.findall(fact_text)
            if matches:
                for match in matches:
                    if match not in strings_nearby and match not in combined_stmt:
                        mismatched_facts.append({
                            "fact": fact_text,
                            "reason": f"{label} '{match}' not present in slice or strings",
                        })

    ok = not missing_unit_ids and not mismatched_facts
    repair_hint = ""
    if not ok:
        repair_hint = "Only claim facts directly supported by unit_ids and matching statement text."
    return {
        "ok": ok,
        "missing_unit_ids": sorted(set(missing_unit_ids)),
        "mismatched_facts": mismatched_facts,
        "repair_hint": repair_hint,
    }

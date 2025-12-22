from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from apk_analyzer.utils.signature_normalize import normalize_signature


@dataclass(frozen=True)
class ApiCategory:
    category_id: str
    priority: str
    description: str
    weight: float
    mitre_primary: str
    mitre_aliases: List[str]
    requires_slice: bool
    pha_tags: List[str]
    permission_hints: List[str]
    method_sigs: set[str]
    field_sigs: set[str]
    string_indicators: set[str]


class ApiCatalog:
    def __init__(self, version: str, categories: Dict[str, ApiCategory]) -> None:
        self.version = version
        self.categories = categories
        self._method_index: Dict[str, List[ApiCategory]] = {}
        self._string_index: Dict[str, List[ApiCategory]] = {}
        for category in categories.values():
            for sig in category.method_sigs:
                self._method_index.setdefault(sig, []).append(category)
            for indicator in category.string_indicators:
                self._string_index.setdefault(indicator, []).append(category)

    @staticmethod
    def load(path: str | Path) -> "ApiCatalog":
        path = Path(path)
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        version = data.get("version")
        if not version:
            raise ValueError("Sensitive API catalog missing version")
        raw_categories = data.get("categories")
        if not isinstance(raw_categories, dict) or not raw_categories:
            raise ValueError("Sensitive API catalog missing categories")
        categories: Dict[str, ApiCategory] = {}
        for category_id, raw in raw_categories.items():
            categories[category_id] = _parse_category(category_id, raw)
        return ApiCatalog(version=version, categories=categories)

    def match_method(self, soot_sig: str) -> List[ApiCategory]:
        key = normalize_signature(soot_sig)
        return self._method_index.get(key, [])

    def match_string(self, value: str) -> List[ApiCategory]:
        return self._string_index.get(value, [])

    def categories_for_ids(self, category_ids: Iterable[str]) -> List[ApiCategory]:
        return [self.categories[cid] for cid in category_ids if cid in self.categories]


def _parse_category(category_id: str, raw: Dict[str, object]) -> ApiCategory:
    priority = str(raw.get("priority", "")).upper()
    description = str(raw.get("description", ""))
    if not priority or "signatures" not in raw:
        raise ValueError(f"Category {category_id} missing required fields")
    mitre = raw.get("mitre", {}) if isinstance(raw.get("mitre", {}), dict) else {}
    mitre_primary = str(mitre.get("primary", "")) if mitre else ""
    mitre_aliases = list(mitre.get("aliases", []) or []) if mitre else []
    signatures = raw.get("signatures", {}) if isinstance(raw.get("signatures", {}), dict) else {}
    method_sigs = {normalize_signature(sig) for sig in signatures.get("methods", []) or []}
    field_sigs = set(signatures.get("fields", []) or [])
    string_indicators = set(signatures.get("strings", []) or [])
    return ApiCategory(
        category_id=category_id,
        priority=priority,
        description=description,
        weight=float(raw.get("weight", 0.0) or 0.0),
        mitre_primary=mitre_primary,
        mitre_aliases=mitre_aliases,
        requires_slice=bool(raw.get("requires_slice", False)),
        pha_tags=list(raw.get("pha_tags", []) or []),
        permission_hints=list(raw.get("permission_hints", []) or []),
        method_sigs=method_sigs,
        field_sigs=field_sigs,
        string_indicators=string_indicators,
    )

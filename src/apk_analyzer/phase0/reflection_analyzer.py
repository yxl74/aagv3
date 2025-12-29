from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from apk_analyzer.analyzers.jadx_extractors import extract_method_source
from apk_analyzer.knowledge.api_catalog import ApiCatalog


_FORNAME_LITERAL_RE = re.compile(
    r'(?:\bClass|\bjava\.lang\.Class)\.forName\s*\(\s*"([^"]+)"\s*\)'
)
_FORNAME_CALL_RE = re.compile(r"(?:\bClass|\bjava\.lang\.Class)\.forName\s*\(")
_FORNAME_NON_LITERAL_RE = re.compile(r'(?:\bClass|\bjava\.lang\.Class)\.forName\s*\(\s*[^"\s]')


@dataclass(frozen=True)
class ReflectionAnalysis:
    hit_id: str
    high_signal: bool
    high_signal_reason: Optional[str]
    resolved_target: Optional[str]
    resolution_source: str


def build_sensitive_targets_from_catalog(catalog: ApiCatalog) -> frozenset[str]:
    skip_categories = {"EVASION_REFLECTION", "EVASION_CRYPTO_OBFUSCATION"}
    targets: set[str] = set()
    for category_id, category in catalog.categories.items():
        if category_id in skip_categories:
            continue
        for sig in category.method_sigs:
            class_name = _extract_class_from_signature(sig)
            if class_name:
                targets.add(class_name)
    return frozenset(targets)


def analyze_reflection_hits(
    sensitive_hits: Dict[str, Any],
    catalog: ApiCatalog,
    jadx_root: Optional[Path] = None,
) -> Dict[str, ReflectionAnalysis]:
    sensitive_targets = build_sensitive_targets_from_catalog(catalog)
    all_hits = sensitive_hits.get("hits", []) or []

    hits_by_caller: Dict[str, List[Dict[str, Any]]] = {}
    for hit in all_hits:
        caller = hit.get("caller", {}).get("method", "")
        hits_by_caller.setdefault(caller, []).append(hit)

    results: Dict[str, ReflectionAnalysis] = {}
    for caller_method, caller_hits in hits_by_caller.items():
        reflection_hits = [
            hit for hit in caller_hits
            if hit.get("category_id") == "EVASION_REFLECTION"
        ]
        if not reflection_hits:
            continue

        has_chain = _has_reflection_chain(reflection_hits)
        has_crypto = _has_crypto_cooccurrence(caller_hits)
        caller_is_app = _caller_is_app(caller_hits)
        resolved_targets: List[str] = []
        saw_forname = False
        literals_only = False
        if jadx_root:
            resolved_targets, saw_forname, literals_only = _resolve_reflection_targets(
                jadx_root, caller_method
            )

        resolved_target = _select_resolved_target(resolved_targets, sensitive_targets)
        high_signal = False
        high_signal_reason = None

        if resolved_target and resolved_target in sensitive_targets:
            high_signal = True
            high_signal_reason = "sensitive_target"
        elif caller_is_app and has_chain and saw_forname and not literals_only:
            high_signal = True
            high_signal_reason = "obfuscated_chain"
        elif caller_is_app and has_chain and has_crypto:
            high_signal = True
            high_signal_reason = "crypto_chain"

        resolution_source = "jadx_literal" if resolved_targets else "unresolved"
        for hit in reflection_hits:
            hit_id = hit.get("hit_id", "")
            if not hit_id:
                continue
            results[hit_id] = ReflectionAnalysis(
                hit_id=hit_id,
                high_signal=high_signal,
                high_signal_reason=high_signal_reason,
                resolved_target=resolved_target,
                resolution_source=resolution_source,
            )

    return results


def filter_reflection_hits(
    sensitive_hits: Dict[str, Any],
    analysis: Dict[str, ReflectionAnalysis],
    catalog: ApiCatalog,
    filter_low_signal: bool = True,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    kept_hits: List[Dict[str, Any]] = []
    suppressed_hits: List[Dict[str, Any]] = []

    for hit in sensitive_hits.get("hits", []) or []:
        if hit.get("category_id") != "EVASION_REFLECTION":
            kept_hits.append(hit)
            continue

        hit_analysis = analysis.get(hit.get("hit_id", ""))
        if not filter_low_signal or (hit_analysis and hit_analysis.high_signal):
            if hit_analysis:
                hit["reflection_analysis"] = {
                    "high_signal": hit_analysis.high_signal,
                    "reason": hit_analysis.high_signal_reason,
                    "resolved_target": hit_analysis.resolved_target,
                    "resolution_source": hit_analysis.resolution_source,
                }
            kept_hits.append(hit)
        else:
            suppressed_hits.append(hit)

    summary = dict(sensitive_hits.get("summary", {}) or {})
    summary.update(_summarize_hits(kept_hits, catalog))
    summary["reflection_kept"] = sum(
        1 for hit in kept_hits if hit.get("category_id") == "EVASION_REFLECTION"
    )
    summary["reflection_suppressed"] = len(suppressed_hits)

    result = dict(sensitive_hits)
    result["hits"] = kept_hits
    result["summary"] = summary
    return result, suppressed_hits


def _extract_class_from_signature(sig: str) -> Optional[str]:
    if sig.startswith("<") and ":" in sig:
        return sig[1:sig.index(":", 1)].strip()
    return None


def _resolve_reflection_targets(
    jadx_root: Path,
    caller_method_sig: str,
) -> Tuple[List[str], bool, bool]:
    source = extract_method_source(jadx_root, caller_method_sig)
    if not source:
        return [], False, False

    literal_targets = _FORNAME_LITERAL_RE.findall(source)
    saw_forname = bool(_FORNAME_CALL_RE.search(source))
    non_literal = bool(_FORNAME_NON_LITERAL_RE.search(source))
    literals_only = bool(saw_forname) and not non_literal and bool(literal_targets)

    deduped: List[str] = []
    seen = set()
    for target in literal_targets:
        if target in seen:
            continue
        seen.add(target)
        deduped.append(target)

    return deduped, saw_forname, literals_only


def _select_resolved_target(targets: List[str], sensitive_targets: frozenset[str]) -> Optional[str]:
    for target in targets:
        if target in sensitive_targets:
            return target
    return targets[0] if targets else None


def _has_reflection_chain(caller_hits: List[Dict[str, Any]]) -> bool:
    sigs = [hit.get("signature", "") for hit in caller_hits]
    has_forname = any("forName" in sig for sig in sigs)
    has_getmethod = any(
        "getMethod" in sig or "getDeclaredMethod" in sig for sig in sigs
    )
    has_invoke = any("invoke" in sig for sig in sigs)
    return has_forname and has_getmethod and has_invoke


def _has_crypto_cooccurrence(caller_hits: List[Dict[str, Any]]) -> bool:
    return any(
        hit.get("category_id") == "EVASION_CRYPTO_OBFUSCATION"
        for hit in caller_hits
    )


def _caller_is_app(caller_hits: List[Dict[str, Any]]) -> bool:
    for hit in caller_hits:
        if hit.get("caller_is_app") is True:
            return True
    return False


def _summarize_hits(hits: List[Dict[str, Any]], catalog: ApiCatalog) -> Dict[str, Any]:
    by_category: Dict[str, Dict[str, Any]] = {}
    for hit in hits:
        category_id = hit.get("category_id")
        category = catalog.categories.get(category_id)
        if not category:
            continue
        info = by_category.setdefault(category_id, {
            "count": 0,
            "priority": category.priority,
            "weight": category.weight,
        })
        info["count"] += 1
    return {
        "total_hits": len(hits),
        "by_category": by_category,
    }

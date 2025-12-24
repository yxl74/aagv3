from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from apk_analyzer.knowledge.api_catalog import ApiCatalog, ApiCategory
from apk_analyzer.utils.signature_normalize import method_name_from_signature, normalize_signature


_SOOT_SIG_RE = re.compile(r"^<([^:]+):\s+([^\s]+)\s+([^(]+)\((.*)\)>$")

# Framework prefixes (always filtered as callers)
_LIBRARY_PREFIXES = (
    "android.",
    "java.",
    "javax.",
    "dalvik.",
    "sun.",
)

# Common library prefixes (filtered when filter_common_libraries=True)
# These are AndroidX, Google Android libraries, and Kotlin ecosystem
_COMMON_LIBRARY_PREFIXES = (
    # AndroidX & Legacy Support
    "androidx.",
    "android.support.",
    # Google Android Libraries
    "com.google.android.material.",
    "com.google.android.gms.",
    "com.google.android.play.",
    "com.android.billingclient.",
    "com.google.android.datatransport.",
    "com.google.firebase.",
    "com.google.mlkit.",
    # Kotlin Ecosystem
    "kotlin.",
    "kotlinx.",
    "org.jetbrains.kotlin.",
    "org.jetbrains.annotations.",
)


ENTRYPOINT_METHODS: Dict[str, set[str]] = {
    "Activity": {
        "onCreate",
        "onStart",
        "onResume",
        "onPause",
        "onStop",
        "onDestroy",
        "onNewIntent",
        "onActivityResult",
    },
    "Service": {"onCreate", "onStartCommand", "onBind", "onHandleIntent", "onDestroy"},
    "Receiver": {"onReceive"},
    "Provider": {"onCreate", "query", "insert", "update", "delete"},
}

PRIORITY_RANK = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}


def build_sensitive_api_hits(
    callgraph: Dict[str, Any],
    catalog: ApiCatalog,
    manifest: Dict[str, Any],
    apk_path: Optional[str | Path] = None,
    max_example_path: int = 20,
    class_hierarchy: Optional[Dict[str, Any]] = None,
    entrypoints_override: Optional[List[str]] = None,
    allow_third_party_callers: bool = True,
    filter_common_libraries: bool = True,
) -> Dict[str, Any]:
    component_map = _extract_component_map(manifest)
    app_prefixes = _build_app_prefixes(manifest, component_map)
    entrypoints = entrypoints_override or _entrypoints_from_callgraph(callgraph, component_map)
    entrypoints_source = "soot" if entrypoints_override else "manifest"
    adjacency = _build_adjacency(callgraph.get("edges", []))
    distances, predecessors = _bfs_from_entrypoints(adjacency, entrypoints)
    hierarchy_map = _build_hierarchy_map(class_hierarchy)
    compat_index = _build_compat_index(catalog) if hierarchy_map else {}
    method_is_framework = _build_framework_index(callgraph)

    hits: List[Dict[str, Any]] = []
    filtered_framework = 0
    filtered_common_library = 0
    filtered_non_app = 0
    for edge in callgraph.get("edges", []) or []:
        caller_sig = normalize_signature(edge.get("caller", ""))
        callee_sig = normalize_signature(edge.get("callee", ""))
        if not caller_sig or not callee_sig:
            continue
        if _is_framework_method(caller_sig, method_is_framework):
            filtered_framework += 1
            continue
        caller_class = _class_name_from_signature(caller_sig)
        if filter_common_libraries and _is_common_library_caller(caller_class):
            filtered_common_library += 1
            continue
        if not allow_third_party_callers:
            if app_prefixes and not _is_app_caller(caller_class, component_map, app_prefixes):
                filtered_non_app += 1
                continue
        categories = catalog.match_method(callee_sig)
        match_type = "exact" if categories else None
        if not categories and hierarchy_map:
            parts = _parse_soot_signature(callee_sig)
            if parts:
                callee_class, ret_type, method_name, params = parts
                key = (method_name, ret_type, tuple(params))
                for catalog_class, category in compat_index.get(key, []):
                    if _is_class_compatible(callee_class, catalog_class, hierarchy_map):
                        categories.append(category)
                if categories:
                    match_type = "hierarchy"
        if categories:
            deduped = []
            seen = set()
            for category in categories:
                if category.category_id in seen:
                    continue
                seen.add(category.category_id)
                deduped.append(category)
            categories = deduped
        if not categories:
            continue
        for category in categories:
            hit_id = _hit_id(category.category_id, caller_sig, callee_sig)
            component_context = _component_context(caller_class, component_map, entrypoints)
            example_path, reachable, path_len = _reachability_path(
                caller_sig,
                callee_sig,
                distances,
                predecessors,
                max_example_path,
            )
            hits.append({
                "hit_id": hit_id,
                "category_id": category.category_id,
                "priority": category.priority,
                "weight": category.weight,
                "mitre_primary": category.mitre_primary,
                "mitre_aliases": category.mitre_aliases,
                "pha_tags": category.pha_tags,
                "permission_hints": category.permission_hints,
                "signature": callee_sig,
                "match_type": match_type or "exact",
                "caller": {
                    "class": caller_class,
                    "method": caller_sig,
                },
                "caller_is_app": _is_app_caller(caller_class, component_map, app_prefixes),
                "component_context": component_context,
                "reachability": {
                    "reachable_from_entrypoint": reachable,
                    "shortest_path_len": path_len,
                    "example_path": example_path,
                },
                "requires_slice": category.requires_slice,
                "slice_hints": _slice_hints(category),
            })

    # Deduplicate hits: merge hits with same (caller, callee, category_id)
    hits_before_dedup = len(hits)
    hits = _deduplicate_hits(hits)
    hits_after_dedup = len(hits)

    hits.sort(key=_hit_sort_key)
    summary = _summarize_hits(hits, catalog)
    summary["filters"] = {
        "framework_callers": filtered_framework,
        "common_library_callers": filtered_common_library,
        "non_app_callers": filtered_non_app if not allow_third_party_callers else 0,
        "third_party_callers_allowed": allow_third_party_callers,
        "filter_common_libraries_enabled": filter_common_libraries,
        "duplicates_removed": hits_before_dedup - hits_after_dedup,
    }
    return {
        "catalog_version": catalog.version,
        "apk": _apk_summary(manifest, apk_path),
        "summary": summary,
        "hits": hits,
        "callgraph_summary": _callgraph_summary(callgraph, entrypoints, entrypoints_source),
    }


def load_callgraph(path: str | Path) -> Dict[str, Any]:
    path = Path(path)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _hit_id(category_id: str, caller_sig: str, callee_sig: str) -> str:
    raw = f"{category_id}|{caller_sig}|{callee_sig}".encode("utf-8")
    return f"hit-{hashlib.sha1(raw).hexdigest()}"


def _class_name_from_signature(signature: str) -> str:
    if signature.startswith("<") and ":" in signature:
        return signature[1: signature.index(":", 1)].strip()
    return signature.split(":", 1)[0].strip("<>")


def _parse_soot_signature(signature: str) -> Optional[Tuple[str, str, str, List[str]]]:
    match = _SOOT_SIG_RE.match(signature.strip())
    if not match:
        return None
    class_name, ret_type, method_name, params = match.groups()
    params = params.strip()
    if not params:
        param_list: List[str] = []
    else:
        param_list = [p.strip() for p in params.split(",") if p.strip()]
    return class_name, ret_type.strip(), method_name.strip(), param_list


def _build_compat_index(catalog: ApiCatalog) -> Dict[Tuple[str, str, Tuple[str, ...]], List[Tuple[str, ApiCategory]]]:
    index: Dict[Tuple[str, str, Tuple[str, ...]], List[Tuple[str, ApiCategory]]] = {}
    for category in catalog.categories.values():
        for sig in category.method_sigs:
            parts = _parse_soot_signature(sig)
            if not parts:
                continue
            class_name, ret_type, method_name, params = parts
            key = (method_name, ret_type, tuple(params))
            index.setdefault(key, []).append((class_name, category))
    return index


def _build_hierarchy_map(class_hierarchy: Optional[Dict[str, Any]]) -> Dict[str, set[str]]:
    if not class_hierarchy:
        return {}
    classes = class_hierarchy.get("classes", {}) if isinstance(class_hierarchy, dict) else {}
    hierarchy_map: Dict[str, set[str]] = {}
    if isinstance(classes, dict):
        for class_name, info in classes.items():
            if not isinstance(info, dict):
                continue
            supertypes = info.get("supertypes", []) or []
            hierarchy_map[class_name] = {str(t) for t in supertypes if t}
    return hierarchy_map


def _is_class_compatible(callee_class: str, catalog_class: str, hierarchy_map: Dict[str, set[str]]) -> bool:
    if not callee_class or not catalog_class:
        return False
    if callee_class == catalog_class:
        return True
    callee_supers = hierarchy_map.get(callee_class, set())
    if catalog_class in callee_supers:
        return True
    catalog_supers = hierarchy_map.get(catalog_class, set())
    return callee_class in catalog_supers


def _extract_component_map(manifest: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    package_name = manifest.get("package_name") or manifest.get("package") or ""
    components: Dict[str, Dict[str, str]] = {}
    for component_type, key in (
        ("Activity", "activities"),
        ("Service", "services"),
        ("Receiver", "receivers"),
        ("Provider", "providers"),
    ):
        for entry in manifest.get(key, []) or []:
            name = entry.get("name") if isinstance(entry, dict) else entry
            if not name:
                continue
            normalized = _normalize_component_name(name, package_name)
            components[normalized] = {
                "component_type": component_type,
                "component_name": normalized,
            }
    return components


def _normalize_component_name(name: str, package_name: str) -> str:
    if name.startswith(".") and package_name:
        return f"{package_name}{name}"
    if "." not in name and package_name:
        return f"{package_name}.{name}"
    return name


def _entrypoints_from_callgraph(callgraph: Dict[str, Any], component_map: Dict[str, Dict[str, str]]) -> List[str]:
    entrypoints: List[str] = []
    nodes = callgraph.get("nodes", []) or []
    for node in nodes:
        method_sig = normalize_signature(node.get("method", ""))
        if not method_sig:
            continue
        class_name = node.get("class") or _class_name_from_signature(method_sig)
        component = component_map.get(class_name)
        if not component:
            continue
        method_name = method_name_from_signature(method_sig)
        allowed = ENTRYPOINT_METHODS.get(component["component_type"], set())
        if method_name in allowed:
            entrypoints.append(method_sig)
    return sorted(set(entrypoints))


def _build_adjacency(edges: Iterable[Dict[str, Any]]) -> Dict[str, List[str]]:
    adjacency: Dict[str, List[str]] = {}
    for edge in edges:
        caller = normalize_signature(edge.get("caller", ""))
        callee = normalize_signature(edge.get("callee", ""))
        if not caller or not callee:
            continue
        adjacency.setdefault(caller, []).append(callee)
    return adjacency


def _bfs_from_entrypoints(
    adjacency: Dict[str, List[str]],
    entrypoints: List[str],
) -> Tuple[Dict[str, int], Dict[str, Optional[str]]]:
    distances: Dict[str, int] = {}
    predecessors: Dict[str, Optional[str]] = {}
    queue = deque()
    for entry in entrypoints:
        distances[entry] = 0
        predecessors[entry] = None
        queue.append(entry)
    while queue:
        current = queue.popleft()
        for callee in adjacency.get(current, []):
            if callee in distances:
                continue
            distances[callee] = distances[current] + 1
            predecessors[callee] = current
            queue.append(callee)
    return distances, predecessors


def _reachability_path(
    caller_sig: str,
    callee_sig: str,
    distances: Dict[str, int],
    predecessors: Dict[str, Optional[str]],
    max_example_path: int,
) -> Tuple[List[str], bool, Optional[int]]:
    if caller_sig not in distances:
        return [], False, None
    path = []
    cursor: Optional[str] = caller_sig
    while cursor is not None:
        path.append(cursor)
        cursor = predecessors.get(cursor)
    path.reverse()
    if path and path[-1] != callee_sig:
        path.append(callee_sig)
    if max_example_path and len(path) > max_example_path:
        path = path[:max_example_path]
    return path, True, distances[caller_sig] + 1


def _component_context(
    caller_class: str,
    component_map: Dict[str, Dict[str, str]],
    entrypoints: List[str],
) -> Dict[str, Any]:
    component = component_map.get(caller_class)
    if not component:
        return {
            "component_type": "Unknown",
            "component_name": caller_class,
            "entrypoint_method": None,
        }
    entrypoint_method = None
    for entry in entrypoints:
        if _class_name_from_signature(entry) == caller_class:
            entrypoint_method = entry
            break
    return {
        "component_type": component.get("component_type", "Unknown"),
        "component_name": component.get("component_name", caller_class),
        "entrypoint_method": entrypoint_method,
    }


def _slice_hints(category: ApiCategory) -> Dict[str, Any]:
    if not category.requires_slice:
        return {}
    return {
        "reason": "Requires argument or string context",
        "focus": "callee_args",
        "max_depth": 20,
    }


def _summarize_hits(hits: List[Dict[str, Any]], catalog: ApiCatalog) -> Dict[str, Any]:
    by_category: Dict[str, Dict[str, Any]] = {}
    for hit in hits:
        category_id = hit["category_id"]
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


def _apk_summary(manifest: Dict[str, Any], apk_path: Optional[str | Path]) -> Dict[str, Any]:
    summary = {
        "package_name": manifest.get("package_name"),
        "min_sdk": manifest.get("min_sdk_version"),
        "target_sdk": manifest.get("target_sdk_version"),
    }
    if apk_path:
        path = Path(apk_path)
        if path.exists():
            summary["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return summary


def _callgraph_summary(callgraph: Dict[str, Any], entrypoints: List[str], entrypoints_source: str) -> Dict[str, Any]:
    nodes = callgraph.get("nodes", []) or []
    edges = callgraph.get("edges", []) or []
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "entrypoint_count": len(entrypoints),
        "entrypoints": entrypoints[:50],
        "entrypoints_source": entrypoints_source,
    }


def _build_app_prefixes(manifest: Dict[str, Any], component_map: Dict[str, Dict[str, str]]) -> List[str]:
    prefixes: List[str] = []
    package_name = manifest.get("package_name") or manifest.get("package") or ""
    if package_name:
        prefixes.append(package_name)
        prefixes.append(f"{package_name}.")
        return list(dict.fromkeys([p for p in prefixes if p]))
    for class_name in component_map.keys():
        if not class_name or class_name.startswith(_LIBRARY_PREFIXES):
            continue
        prefixes.append(class_name)
        if "." in class_name:
            prefixes.append(class_name.rsplit(".", 1)[0] + ".")
    return list(dict.fromkeys([p for p in prefixes if p]))


def _is_app_caller(
    caller_class: str,
    component_map: Dict[str, Dict[str, str]],
    app_prefixes: List[str],
) -> bool:
    if not caller_class:
        return False
    for prefix in app_prefixes:
        if caller_class == prefix or caller_class.startswith(prefix):
            return True
    return False


def _build_framework_index(callgraph: Dict[str, Any]) -> Dict[str, bool]:
    index: Dict[str, bool] = {}
    for node in callgraph.get("nodes", []) or []:
        method = normalize_signature(node.get("method", ""))
        if not method:
            continue
        index[method] = bool(node.get("is_android_framework"))
    return index


def _is_framework_method(signature: str, method_is_framework: Dict[str, bool]) -> bool:
    if signature in method_is_framework:
        return method_is_framework[signature]
    class_name = _class_name_from_signature(signature)
    return class_name.startswith(_LIBRARY_PREFIXES)


def _is_common_library_caller(caller_class: str) -> bool:
    """Check if caller class is from a common library (androidx, google, kotlin, etc.)"""
    if not caller_class:
        return False
    return caller_class.startswith(_COMMON_LIBRARY_PREFIXES)


def _deduplicate_hits(hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate hits with the same (caller_method, callee_signature, category_id).
    Keeps the first occurrence (which will have highest priority/weight after sorting).
    """
    seen: set[Tuple[str, str, str]] = set()
    deduped: List[Dict[str, Any]] = []

    for hit in hits:
        caller_method = hit.get("caller", {}).get("method", "")
        callee_sig = hit.get("signature", "")
        category_id = hit.get("category_id", "")

        key = (caller_method, callee_sig, category_id)
        if key in seen:
            continue

        seen.add(key)
        deduped.append(hit)

    return deduped


def _hit_sort_key(hit: Dict[str, Any]) -> Tuple[int, float]:
    priority = hit.get("priority", "LOW")
    rank = PRIORITY_RANK.get(priority, 99)
    weight = float(hit.get("weight") or 0.0)
    return (rank, -weight)

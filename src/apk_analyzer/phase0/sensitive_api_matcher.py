from __future__ import annotations

import hashlib
import json
from collections import deque
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from apk_analyzer.knowledge.api_catalog import ApiCatalog, ApiCategory
from apk_analyzer.utils.signature_normalize import method_name_from_signature, normalize_signature


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
) -> Dict[str, Any]:
    component_map = _extract_component_map(manifest)
    entrypoints = _entrypoints_from_callgraph(callgraph, component_map)
    adjacency = _build_adjacency(callgraph.get("edges", []))
    distances, predecessors = _bfs_from_entrypoints(adjacency, entrypoints)

    hits: List[Dict[str, Any]] = []
    for edge in callgraph.get("edges", []) or []:
        caller_sig = normalize_signature(edge.get("caller", ""))
        callee_sig = normalize_signature(edge.get("callee", ""))
        if not caller_sig or not callee_sig:
            continue
        categories = catalog.match_method(callee_sig)
        if not categories:
            continue
        for category in categories:
            hit_id = _hit_id(category.category_id, caller_sig, callee_sig)
            caller_class = _class_name_from_signature(caller_sig)
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
                "caller": {
                    "class": caller_class,
                    "method": caller_sig,
                },
                "component_context": component_context,
                "reachability": {
                    "reachable_from_entrypoint": reachable,
                    "shortest_path_len": path_len,
                    "example_path": example_path,
                },
                "requires_slice": category.requires_slice,
                "slice_hints": _slice_hints(category),
            })

    hits.sort(key=_hit_sort_key)
    summary = _summarize_hits(hits, catalog)
    return {
        "catalog_version": catalog.version,
        "apk": _apk_summary(manifest, apk_path),
        "summary": summary,
        "hits": hits,
        "callgraph_summary": _callgraph_summary(callgraph, entrypoints),
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


def _callgraph_summary(callgraph: Dict[str, Any], entrypoints: List[str]) -> Dict[str, Any]:
    nodes = callgraph.get("nodes", []) or []
    edges = callgraph.get("edges", []) or []
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "entrypoint_count": len(entrypoints),
        "entrypoints": entrypoints[:50],
    }


def _hit_sort_key(hit: Dict[str, Any]) -> Tuple[int, float]:
    priority = hit.get("priority", "LOW")
    rank = PRIORITY_RANK.get(priority, 99)
    weight = float(hit.get("weight") or 0.0)
    return (rank, -weight)

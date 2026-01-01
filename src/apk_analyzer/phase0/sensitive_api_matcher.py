from __future__ import annotations

import hashlib
import heapq
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
# These are AndroidX, Google Android libraries, Kotlin ecosystem, and popular third-party libs
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
    # Networking Libraries
    "okhttp3.",
    "okio.",
    "retrofit2.",
    "com.squareup.okhttp.",
    "com.squareup.okhttp3.",
    "com.squareup.retrofit.",
    "com.squareup.retrofit2.",
    "com.squareup.picasso.",
    "com.squareup.moshi.",
    # JSON/Serialization
    "com.fasterxml.jackson.",
    "com.google.gson.",
    "org.json.",
    # Logging
    "org.slf4j.",
    "org.apache.logging.",
    "ch.qos.logback.",
    "timber.log.",
    # Apache Commons
    "org.apache.commons.",
    "org.apache.http.",
    # Reactive/Async
    "io.reactivex.",
    "rx.",
    "io.reactivex.rxjava3.",
    # Dependency Injection
    "dagger.",
    "javax.inject.",
    "com.google.dagger.",
    # UI Libraries
    "butterknife.",
    "com.jakewharton.",
    "com.bumptech.glide.",
    "com.github.bumptech.glide.",
    # Testing (should never be in prod, but filter anyway)
    "org.junit.",
    "org.mockito.",
    "org.robolectric.",
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
    "Provider": {"onCreate", "query", "insert", "update", "delete", "call"},
}

PRIORITY_RANK = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}

_ACCESSIBILITY_SERVICE_SUPERTYPE = "android.accessibilityservice.AccessibilityService"
_ACCESSIBILITY_SERVICE_ENTRYPOINTS = {"onAccessibilityEvent", "onInterrupt", "onServiceConnected"}

# FlowDroid callback graphs often contain "parent -> override" edges for lifecycle methods
# (e.g., android.app.Service.onCreate -> com.example.MyService.onCreate). These are useful
# as a *relationship* signal but are not true registration-site edges, and they can create
# spurious reachability for non-manifest components. We treat such edges as non-edges for
# reachability/path reconstruction.
_LIFECYCLE_ENTRYPOINT_METHOD_NAMES: set[str] = set().union(*ENTRYPOINT_METHODS.values(), _ACCESSIBILITY_SERVICE_ENTRYPOINTS)


def _is_component_lifecycle_signature(method_sig: str) -> bool:
    return method_name_from_signature(method_sig) in _LIFECYCLE_ENTRYPOINT_METHOD_NAMES

# =============================================================================
# Investigability Scoring (for prioritizing analyzable seeds)
# =============================================================================

# Reflection patterns that indicate static analysis limitations
REFLECTION_PATTERNS = (
    "java.lang.reflect.Method",
    "java.lang.reflect.Constructor",
    "java.lang.reflect.Field",
    "java.lang.Class.forName",
    "java.lang.Class.getDeclaredMethod",
    "java.lang.Class.getMethod",
    "java.lang.Class.getDeclaredConstructor",
    "java.lang.Class.newInstance",
    "dalvik.system.DexClassLoader",
    "dalvik.system.PathClassLoader",
    "dalvik.system.InMemoryDexClassLoader",
    "java.lang.ClassLoader.loadClass",
)


def _path_contains_reflection(example_path: List[str]) -> Tuple[bool, List[str]]:
    """
    Check if a call path contains reflection or dynamic class loading.

    Args:
        example_path: List of method signatures in the call path.

    Returns:
        Tuple of (has_reflection, matched_patterns).
    """
    matched: List[str] = []
    for method_sig in example_path:
        for pattern in REFLECTION_PATTERNS:
            if pattern in method_sig and pattern not in matched:
                matched.append(pattern)
    return bool(matched), matched


def _compute_investigability(
    reachable: bool,
    path_len: Optional[int],
    example_path: List[str],
    component_type: str,
    caller_is_app: bool,
) -> Tuple[float, Dict[str, Any]]:
    """
    Compute an investigability score (0.0-1.0) for a hit.

    Higher scores indicate the hit is easier to analyze via static analysis.
    This helps prioritize seeds that will produce useful Tier1 results.

    Scoring factors:
    - Reachability from entrypoint: +0.25
    - Short path length (<=3 hops): +0.15, (<=6): +0.10, (<=10): +0.05
    - Known component type: +0.20
    - Caller is app code: +0.10
    - No reflection in path: +0.20

    Args:
        reachable: Whether the hit is reachable from an entrypoint.
        path_len: Length of the call path from entrypoint.
        example_path: The call path (for reflection detection).
        component_type: The resolved component type.
        caller_is_app: Whether the caller is app code (not library).

    Returns:
        Tuple of (score, factors_dict).
    """
    score = 0.0
    factors: Dict[str, Any] = {}

    # Reachability: Can we trace from entrypoint? (+0.25)
    factors["reachable"] = reachable
    if reachable:
        score += 0.25

    # Path length: shorter = more reliable (+0.15 max)
    factors["path_len"] = path_len
    if path_len is not None:
        if path_len <= 3:
            score += 0.15
        elif path_len <= 6:
            score += 0.10
        elif path_len <= 10:
            score += 0.05

    # Component known: can we trigger this? (+0.20)
    factors["component_known"] = component_type != "Unknown"
    if component_type != "Unknown":
        score += 0.20

    # App code caller: more relevant than library (+0.10)
    factors["caller_is_app"] = caller_is_app
    if caller_is_app:
        score += 0.10

    # No reflection in path: static analysis will work (+0.20)
    has_reflection, reflection_sites = _path_contains_reflection(example_path)
    factors["reflection_free"] = not has_reflection
    factors["reflection_sites"] = reflection_sites
    if not has_reflection:
        score += 0.20

    return min(score, 1.0), factors


def _infer_component_from_class_name(class_name: str) -> Dict[str, Any]:
    """
    Heuristic fallback for inferring component type from class name.

    Used when we can't find a component in the manifest ancestry.

    Args:
        class_name: The class name to analyze.

    Returns:
        Component context dict with inferred type.
    """
    if not class_name:
        return {
            "component_type": "Unknown",
            "component_name": class_name,
            "entrypoint_method": None,
            "resolution_method": "failed",
        }

    name_lower = class_name.lower()
    simple_name = class_name.split(".")[-1].lower() if "." in class_name else name_lower

    # Check simple class name for component type hints
    if "activity" in simple_name:
        comp_type = "Activity"
    elif "service" in simple_name:
        comp_type = "Service"
    elif "receiver" in simple_name or "broadcast" in simple_name:
        comp_type = "Receiver"
    elif "provider" in simple_name:
        comp_type = "Provider"
    else:
        comp_type = "Unknown"

    return {
        "component_type": comp_type,
        "component_name": class_name,
        "entrypoint_method": None,
        "resolution_method": "heuristic" if comp_type != "Unknown" else "failed",
    }


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
    hierarchy_map = _build_hierarchy_map(class_hierarchy)
    entrypoints = entrypoints_override or _entrypoints_from_callgraph(callgraph, component_map)
    entrypoints = _filter_valid_entrypoints(entrypoints, component_map, hierarchy_map)
    entrypoints_source = "soot" if entrypoints_override else "manifest"
    edges = callgraph.get("edges", []) or []
    strict_adjacency, strict_edge_info = _build_weighted_adjacency(
        edges,
        include_synthetic=False,
        weight_fn=_strict_edge_weight,
    )
    strict_distances, strict_predecessors, strict_pred_edges = _dijkstra_from_entrypoints(
        strict_adjacency,
        entrypoints,
    )
    augmented_adjacency, augmented_edge_info = _build_weighted_adjacency(
        edges,
        include_synthetic=True,
        weight_fn=_augmented_edge_weight,
    )
    augmented_distances, augmented_predecessors, augmented_pred_edges = _dijkstra_from_entrypoints(
        augmented_adjacency,
        entrypoints,
    )
    compat_index = _build_compat_index(catalog) if hierarchy_map else {}
    method_is_framework = _build_framework_index(callgraph)

    hits: List[Dict[str, Any]] = []
    filtered_framework = 0
    filtered_common_library = 0
    filtered_non_app = 0
    for edge in edges:
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
            # Compute reachability (strict preferred; augmented fallback)
            reachability = _compute_strict_preferred_reachability(
                caller_sig=caller_sig,
                callee_sig=callee_sig,
                strict_distances=strict_distances,
                strict_predecessors=strict_predecessors,
                strict_pred_edges=strict_pred_edges,
                strict_edge_info=strict_edge_info,
                augmented_distances=augmented_distances,
                augmented_predecessors=augmented_predecessors,
                augmented_pred_edges=augmented_pred_edges,
                augmented_edge_info=augmented_edge_info,
                max_example_path=max_example_path,
            )
            example_path = reachability["example_path"]
            reachable = reachability["reachable_from_entrypoint"]
            path_len = reachability["shortest_path_len"]
            # Enhanced component resolution with ancestor walking
            predecessors = (
                strict_predecessors
                if reachability.get("path_layer") == "strict"
                else augmented_predecessors
            )
            component_context = _component_context(
                caller_class,
                caller_sig,
                component_map,
                entrypoints,
                predecessors,
            )
            # Compute caller_is_app once (used in hit and investigability)
            caller_is_app = _is_app_caller(caller_class, component_map, app_prefixes)
            # Compute investigability score for prioritization
            investigability_score, investigability_factors = _compute_investigability(
                reachable=reachable,
                path_len=path_len,
                example_path=example_path,
                component_type=component_context.get("component_type", "Unknown"),
                caller_is_app=caller_is_app,
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
                "caller_is_app": caller_is_app,
                "component_context": component_context,
                "reachability": reachability,
                "requires_slice": category.requires_slice,
                "slice_hints": _slice_hints(category),
                # Investigability scoring for triaging
                "investigability_score": investigability_score,
                "investigability_factors": investigability_factors,
                "path_contains_reflection": len(investigability_factors.get("reflection_sites", [])) > 0,
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


def _filter_valid_entrypoints(
    entrypoints: List[str],
    component_map: Dict[str, Dict[str, str]],
    hierarchy_map: Optional[Dict[str, set[str]]] = None,
) -> List[str]:
    """
    Keep only manifest-startable component lifecycle methods.

    This protects reachability/path reconstruction from polluted entrypoint lists
    (e.g., callback methods, threads, or arbitrary app methods).
    """
    filtered: List[str] = []
    for method_sig in entrypoints or []:
        method_sig = normalize_signature(method_sig)
        if not method_sig:
            continue
        class_name = _class_name_from_signature(method_sig)
        component = component_map.get(class_name)
        if not component:
            continue
        method_name = method_name_from_signature(method_sig)
        allowed = set(ENTRYPOINT_METHODS.get(component.get("component_type", "Unknown"), set()))
        # AccessibilityService is declared as a Service in the manifest, but has additional
        # OS-delivered entrypoints that are crucial for malware analysis.
        if (
            component.get("component_type") == "Service"
            and method_name in _ACCESSIBILITY_SERVICE_ENTRYPOINTS
            and hierarchy_map
            and _ACCESSIBILITY_SERVICE_SUPERTYPE in hierarchy_map.get(class_name, set())
        ):
            filtered.append(method_sig)
            continue
        if method_name in allowed:
            filtered.append(method_sig)
    return sorted(set(filtered))


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


def _is_synthetic_edge(edge: Dict[str, Any]) -> bool:
    return edge.get("edge_layer") == "synthetic"


def _edge_source_tiebreak(edge_source: str) -> int:
    """
    Lower is better.

    Prefer more precise sources when weights are equal.
    """
    if edge_source == "soot_cg":
        return 0
    if edge_source == "jimple_invoke":
        return 1
    return 5


def _strict_edge_weight(edge: Dict[str, Any]) -> float:
    """
    Weight model for strict edges only (non-synthetic).

    - `soot_cg`: more precise dispatch
    - `jimple_invoke`: syntactic invoke, less precise
    """
    edge_source = str(edge.get("edge_source") or "")
    if edge_source == "soot_cg":
        return 1.0
    if edge_source == "jimple_invoke":
        return 2.0
    return 3.0


def _augmented_edge_weight(edge: Dict[str, Any]) -> float:
    """
    Weight model for augmented graph.

    Strict preferred behavior is implemented by first attempting strict reachability,
    then falling back to this augmented search when strict fails.
    """
    if not _is_synthetic_edge(edge):
        return _strict_edge_weight(edge)

    edge_source = str(edge.get("edge_source") or "")
    confidence = str(edge.get("confidence") or "").lower()

    # Prefer high-confidence synthetic edges; penalize speculative relations.
    if edge_source == "threading_synthetic":
        return {"high": 3.0, "medium": 5.0, "low": 8.0}.get(confidence, 8.0)
    if edge_source == "listener_registration_synthetic":
        return {"high": 4.0, "medium": 6.0, "low": 10.0}.get(confidence, 10.0)
    if edge_source == "flowdroid_callback":
        # FlowDroid's parent-method edges are not registration-site edges; treat as very speculative.
        return 25.0

    return 20.0


def _callsite_unit(edge: Dict[str, Any]) -> Optional[str]:
    callsite = edge.get("callsite")
    if isinstance(callsite, dict):
        unit = callsite.get("unit")
        return str(unit) if unit is not None else None
    if isinstance(callsite, str):
        return callsite
    return None


def _build_weighted_adjacency(
    edges: Iterable[Dict[str, Any]],
    *,
    include_synthetic: bool,
    weight_fn,
) -> Tuple[Dict[str, List[Tuple[str, float]]], Dict[Tuple[str, str], Dict[str, Any]]]:
    """
    Build adjacency lists and a best-edge lookup for (caller, callee).

    The lookup chooses the minimum-weight edge between the same method pair,
    with a deterministic tie-breaker favoring `soot_cg` over `jimple_invoke`.
    """
    best: Dict[Tuple[str, str], Dict[str, Any]] = {}
    best_weight: Dict[Tuple[str, str], float] = {}
    for edge in edges:
        if not include_synthetic and _is_synthetic_edge(edge):
            continue
        if include_synthetic and str(edge.get("edge_source") or "") == "flowdroid_callback":
            callee_sig = normalize_signature(edge.get("callee", ""))
            if callee_sig and _is_component_lifecycle_signature(callee_sig):
                continue
        caller = normalize_signature(edge.get("caller", ""))
        callee = normalize_signature(edge.get("callee", ""))
        if not caller or not callee:
            continue
        w = float(weight_fn(edge))
        key = (caller, callee)
        if key not in best_weight:
            best_weight[key] = w
            best[key] = {
                "caller": caller,
                "callee": callee,
                "edge_source": edge.get("edge_source"),
                "edge_layer": edge.get("edge_layer"),
                "pattern": edge.get("pattern"),
                "confidence": edge.get("confidence"),
                "callsite_unit": _callsite_unit(edge),
                "weight": w,
            }
            continue

        current_weight = best_weight[key]
        if w < current_weight:
            best_weight[key] = w
            best[key] = {
                "caller": caller,
                "callee": callee,
                "edge_source": edge.get("edge_source"),
                "edge_layer": edge.get("edge_layer"),
                "pattern": edge.get("pattern"),
                "confidence": edge.get("confidence"),
                "callsite_unit": _callsite_unit(edge),
                "weight": w,
            }
            continue
        if w == current_weight:
            new_source = str(edge.get("edge_source") or "")
            old_source = str(best[key].get("edge_source") or "")
            if _edge_source_tiebreak(new_source) < _edge_source_tiebreak(old_source):
                best[key] = {
                    "caller": caller,
                    "callee": callee,
                    "edge_source": edge.get("edge_source"),
                    "edge_layer": edge.get("edge_layer"),
                    "pattern": edge.get("pattern"),
                    "confidence": edge.get("confidence"),
                    "callsite_unit": _callsite_unit(edge),
                    "weight": w,
                }

    adjacency: Dict[str, List[Tuple[str, float]]] = {}
    for (caller, callee), info in best.items():
        adjacency.setdefault(caller, []).append((callee, float(info["weight"])))
    return adjacency, best


def _dijkstra_from_entrypoints(
    adjacency: Dict[str, List[Tuple[str, float]]],
    entrypoints: List[str],
) -> Tuple[Dict[str, float], Dict[str, Optional[str]], Dict[str, Optional[Dict[str, Any]]]]:
    distances: Dict[str, float] = {}
    predecessors: Dict[str, Optional[str]] = {}
    pred_edges: Dict[str, Optional[Dict[str, Any]]] = {}

    heap: List[Tuple[float, str]] = []
    for entry in entrypoints:
        distances[entry] = 0.0
        predecessors[entry] = None
        pred_edges[entry] = None
        heap.append((0.0, entry))
    heapq.heapify(heap)

    while heap:
        dist_u, u = heapq.heappop(heap)
        if dist_u != distances.get(u):
            continue
        for v, w in adjacency.get(u, []):
            nd = dist_u + w
            if nd < distances.get(v, float("inf")):
                distances[v] = nd
                predecessors[v] = u
                # Edge metadata is resolved lazily from the edge lookup at reconstruction time.
                pred_edges[v] = None
                heapq.heappush(heap, (nd, v))
    return distances, predecessors, pred_edges


def _reconstruct_method_path(
    target: str,
    predecessors: Dict[str, Optional[str]],
    max_example_path: int,
) -> List[str]:
    path: List[str] = []
    cursor: Optional[str] = target
    while cursor is not None:
        path.append(cursor)
        cursor = predecessors.get(cursor)
    path.reverse()
    if max_example_path and len(path) > max_example_path:
        return path[:max_example_path]
    return path


def _compute_reachability_for_graph(
    *,
    caller_sig: str,
    callee_sig: str,
    distances: Dict[str, float],
    predecessors: Dict[str, Optional[str]],
    edge_info: Dict[Tuple[str, str], Dict[str, Any]],
    max_example_path: int,
) -> Dict[str, Any]:
    if caller_sig not in distances:
        return {
            "reachable_from_entrypoint": False,
            "shortest_path_len": None,
            "path_cost": None,
            "example_path": [],
            "example_edges": [],
        }

    method_path = _reconstruct_method_path(caller_sig, predecessors, max_example_path)
    if not method_path:
        return {
            "reachable_from_entrypoint": True,
            "shortest_path_len": 1,
            "path_cost": 0.0,
            "example_path": [callee_sig],
            "example_edges": [],
        }

    example_path = list(method_path)
    example_edges: List[Dict[str, Any]] = []
    total_cost = float(distances.get(caller_sig, 0.0))

    # Edges along entrypoint->...->caller
    for idx in range(len(method_path) - 1):
        caller = method_path[idx]
        callee = method_path[idx + 1]
        info = edge_info.get((caller, callee))
        if info:
            example_edges.append(info)

    # Append sink edge (caller -> sensitive API)
    if example_path[-1] != callee_sig:
        example_path.append(callee_sig)
        sink_info = edge_info.get((caller_sig, callee_sig))
        if sink_info:
            example_edges.append(sink_info)
            total_cost += float(sink_info.get("weight") or 0.0)

    if max_example_path and len(example_path) > max_example_path:
        example_path = example_path[:max_example_path]
        example_edges = example_edges[: max(0, len(example_path) - 1)]

    return {
        "reachable_from_entrypoint": True,
        "shortest_path_len": len(example_path) - 1,
        "path_cost": total_cost,
        "example_path": example_path,
        "example_edges": example_edges,
    }


def _compute_strict_preferred_reachability(
    *,
    caller_sig: str,
    callee_sig: str,
    strict_distances: Dict[str, float],
    strict_predecessors: Dict[str, Optional[str]],
    strict_pred_edges: Dict[str, Optional[Dict[str, Any]]],
    strict_edge_info: Dict[Tuple[str, str], Dict[str, Any]],
    augmented_distances: Dict[str, float],
    augmented_predecessors: Dict[str, Optional[str]],
    augmented_pred_edges: Dict[str, Optional[Dict[str, Any]]],
    augmented_edge_info: Dict[Tuple[str, str], Dict[str, Any]],
    max_example_path: int,
) -> Dict[str, Any]:
    strict = _compute_reachability_for_graph(
        caller_sig=caller_sig,
        callee_sig=callee_sig,
        distances=strict_distances,
        predecessors=strict_predecessors,
        edge_info=strict_edge_info,
        max_example_path=max_example_path,
    )
    if strict["reachable_from_entrypoint"]:
        strict["path_layer"] = "strict"
        return strict

    augmented = _compute_reachability_for_graph(
        caller_sig=caller_sig,
        callee_sig=callee_sig,
        distances=augmented_distances,
        predecessors=augmented_predecessors,
        edge_info=augmented_edge_info,
        max_example_path=max_example_path,
    )
    augmented["path_layer"] = "augmented" if augmented["reachable_from_entrypoint"] else None
    return augmented


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
    caller_sig: str,
    component_map: Dict[str, Dict[str, str]],
    entrypoints: List[str],
    predecessors: Dict[str, Optional[str]],
) -> Dict[str, Any]:
    """
    Resolve component context for a caller method.

    Enhanced to walk backwards through the call path to find component ancestor
    when the direct caller class is not a manifest component.

    Args:
        caller_class: The class name of the caller.
        caller_sig: The full method signature of the caller.
        component_map: Map of class names to component info from manifest.
        entrypoints: List of entrypoint method signatures.
        predecessors: BFS predecessor map for walking call paths.

    Returns:
        Component context dict with type, name, entrypoint, and resolution method.
    """
    # First, try direct match (caller class is a component)
    component = component_map.get(caller_class)
    if component:
        entrypoint_method = None
        for entry in entrypoints:
            if _class_name_from_signature(entry) == caller_class:
                entrypoint_method = entry
                break
        return {
            "component_type": component.get("component_type", "Unknown"),
            "component_name": component.get("component_name", caller_class),
            "entrypoint_method": entrypoint_method,
            "resolution_method": "direct",
        }

    # Walk backwards through call path to find component ancestor
    cursor = predecessors.get(caller_sig)
    depth = 0
    while cursor and depth < 15:
        cursor_class = _class_name_from_signature(cursor)
        if cursor_class in component_map:
            comp = component_map[cursor_class]
            return {
                "component_type": comp.get("component_type", "Unknown"),
                "component_name": comp.get("component_name", cursor_class),
                "entrypoint_method": cursor,
                "resolution_method": "ancestor",
                "resolution_depth": depth + 1,
            }
        cursor = predecessors.get(cursor)
        depth += 1

    # Fallback: try heuristic inference from class name
    return _infer_component_from_class_name(caller_class)


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

    # Also derive prefixes from manifest component classes. Some apps (especially test fixtures)
    # use an applicationId / APK package_name that does not match the Java package of the
    # implementation classes. Relying solely on manifest.package_name causes app code to be
    # treated as "third-party" and can reduce investigability or filtering accuracy.
    component_classes: List[str] = []
    for class_name in component_map.keys():
        if not class_name:
            continue
        if class_name.startswith(_LIBRARY_PREFIXES) or class_name.startswith(_COMMON_LIBRARY_PREFIXES):
            continue
        component_classes.append(class_name)

    # Pick dominant component package prefix(es) to avoid whitelisting one-off SDK components as app code.
    # This is used primarily when allow_third_party_callers=False.
    package_prefix_counts: Dict[str, int] = {}
    for class_name in component_classes:
        if "." not in class_name:
            continue
        package_prefix = class_name.rsplit(".", 1)[0] + "."
        package_prefix_counts[package_prefix] = package_prefix_counts.get(package_prefix, 0) + 1

    if package_prefix_counts:
        max_count = max(package_prefix_counts.values())
        for prefix, count in package_prefix_counts.items():
            if count == max_count:
                prefixes.append(prefix)

    # Always include component class names themselves so callers inside the same component
    # (including inner classes) are treated as app code.
    prefixes.extend(component_classes)

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


def _hit_sort_key(hit: Dict[str, Any]) -> Tuple[int, float, float]:
    """
    Generate sort key for hit prioritization.

    Sorting order (primary to tertiary):
    1. Priority rank: CRITICAL(1) > HIGH(2) > MEDIUM(3) > LOW(4)
    2. Investigability score: Higher scores first (easier to analyze)
    3. Catalog weight: Higher weights first

    This ensures that within the same priority level, easier-to-analyze
    hits are processed before harder ones.
    """
    priority = hit.get("priority", "LOW")
    rank = PRIORITY_RANK.get(priority, 99)
    investigability = float(hit.get("investigability_score") or 0.0)
    weight = float(hit.get("weight") or 0.0)
    # Negate investigability and weight so higher values sort first
    return (rank, -investigability, -weight)

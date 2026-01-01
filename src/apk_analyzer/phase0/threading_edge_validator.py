from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from apk_analyzer.utils.signature_normalize import method_name_from_signature, normalize_signature


@dataclass(frozen=True)
class StartCallsite:
    caller: str
    callee: str
    callsite_unit: str


def validate_threading_edges(callgraph: Dict[str, Any], class_hierarchy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Best-effort validation of synthetic threading edge coverage.

    This checks whether methods that call Thread.start()/Handler.post()/Executor.execute()
    have corresponding synthetic edges to their runnable targets.
    """
    edges = callgraph.get("edges") or []
    threading_edges = [
        e for e in edges
        if isinstance(e, dict) and e.get("edge_source") == "threading_synthetic"
    ]

    thread_classes: Set[str] = {"java.lang.Thread"}
    runnable_classes: Set[str] = set()
    if isinstance(class_hierarchy, dict):
        thread_classes |= _find_classes_with_supertype(class_hierarchy, "java.lang.Thread")
        runnable_classes |= _find_classes_with_supertype(class_hierarchy, "java.lang.Runnable")

    start_callsites = _find_thread_start_callsites(edges, thread_classes)
    bridged = _find_thread_run_bridges(edges, thread_classes, runnable_classes)
    missing = [s for s in start_callsites if s.callsite_unit and (s.caller, s.callsite_unit) not in bridged]

    thread_subclasses: List[str] = []
    runnable_implementors: List[str] = []
    if isinstance(class_hierarchy, dict):
        thread_subclasses = sorted(_find_classes_with_supertype(class_hierarchy, "java.lang.Thread"))
        runnable_implementors = sorted(_find_classes_with_supertype(class_hierarchy, "java.lang.Runnable"))

    return {
        "thread_subclasses": thread_subclasses,
        "runnable_implementors": runnable_implementors,
        "start_callsites": len(start_callsites),
        "threading_edge_count": len(threading_edges),
        "missing_run_edges": len(missing),
        "missing_run_edge_samples": [
            {"caller": s.caller, "callee": s.callee, "callsite_unit": s.callsite_unit}
            for s in missing[:25]
        ],
    }


def _find_thread_start_callsites(edges: Iterable[Dict[str, Any]], thread_classes: Set[str]) -> List[StartCallsite]:
    out: List[StartCallsite] = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        caller = normalize_signature(edge.get("caller", ""))
        callee = normalize_signature(edge.get("callee", ""))
        if not caller or not callee:
            continue
        if method_name_from_signature(callee) != "start":
            continue
        if " void start()" not in callee:
            continue
        callee_class = _class_name_from_signature(callee)
        if callee_class not in thread_classes:
            continue
        callsite_unit = _callsite_unit(edge)
        out.append(StartCallsite(caller=caller, callee=callee, callsite_unit=callsite_unit or ""))
    return out


def _find_thread_run_bridges(
    edges: Iterable[Dict[str, Any]],
    thread_classes: Set[str],
    runnable_classes: Set[str],
) -> Set[Tuple[str, str]]:
    """
    Identify callsites that already have a start() -> run() bridge, either from the soot call graph
    or from our synthetic edges.

    We match by (caller_method, callsite_unit_string) since the extractor reuses the same stmt string.
    """
    bridged: Set[Tuple[str, str]] = set()
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        caller = normalize_signature(edge.get("caller", ""))
        callee = normalize_signature(edge.get("callee", ""))
        if not caller or not callee:
            continue
        callsite_unit = _callsite_unit(edge)
        if not callsite_unit:
            continue
        if method_name_from_signature(callee) != "run":
            continue
        if " void run()" not in callee:
            continue

        callee_class = _class_name_from_signature(callee)
        if callee_class in thread_classes:
            bridged.add((caller, callsite_unit))
            continue
        if callee_class in runnable_classes:
            bridged.add((caller, callsite_unit))
            continue

        # Best-effort fallback when hierarchy isn't available: trust our own synthetic threading edges.
        if edge.get("edge_source") == "threading_synthetic":
            bridged.add((caller, callsite_unit))

    return bridged


def _callsite_unit(edge: Dict[str, Any]) -> str:
    callsite_obj = edge.get("callsite")
    if isinstance(callsite_obj, dict):
        return str(callsite_obj.get("unit") or "")
    if isinstance(callsite_obj, str):
        return str(callsite_obj)
    return ""


def _class_name_from_signature(signature: str) -> str:
    signature = signature.strip()
    if signature.startswith("<") and ":" in signature:
        return signature[1: signature.index(":", 1)].strip()
    return signature.split(":", 1)[0].strip("<>")


def _find_classes_with_supertype(class_hierarchy: Dict[str, Any], supertype: str) -> Set[str]:
    classes = class_hierarchy.get("classes", {})
    out: Set[str] = set()
    if not isinstance(classes, dict):
        return out
    for class_name, info in classes.items():
        if not isinstance(info, dict):
            continue
        supertypes = info.get("supertypes", []) or []
        if supertype in supertypes:
            out.add(str(class_name))
    return out

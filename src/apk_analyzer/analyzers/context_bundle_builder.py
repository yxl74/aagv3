from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from apk_analyzer.analyzers.dex_invocation_indexer import SuspiciousApiIndex
from apk_analyzer.utils.signature_normalize import method_name_from_signature, normalize_signature
from apk_analyzer.utils.artifact_store import ArtifactStore
from apk_analyzer.utils.json_schema import validate_json


BOOT_TRIGGERS = {
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.QUICKBOOT_POWERON",
    "android.intent.action.MY_PACKAGE_REPLACED",
}


def _hash_method_sig(signature: str) -> str:
    return hashlib.sha1(signature.encode("utf-8")).hexdigest()


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _build_slice_from_cfg(cfg: Dict[str, Any], seed_match: str) -> Dict[str, Any]:
    units = cfg.get("units", [])
    unit_map = {u["id"]: u for u in units}
    preds: Dict[str, List[str]] = {u["id"]: [] for u in units}
    for u in units:
        for succ in u.get("succs", []) or []:
            if succ in preds:
                preds[succ].append(u["id"])
    seed_units = [u["id"] for u in units if seed_match in u.get("stmt", "")]
    if not seed_units and units:
        seed_units = [units[-1]["id"]]
    visited = set(seed_units)
    stack = list(seed_units)
    while stack:
        current = stack.pop()
        for pred in preds.get(current, []):
            if pred not in visited:
                visited.add(pred)
                stack.append(pred)
    slice_units = []
    for u in units:
        if u["id"] in visited:
            tags = []
            if u["id"] in seed_units:
                tags.append("SEED")
            slice_units.append({"unit_id": u["id"], "stmt": u.get("stmt", ""), "tags": tags})
    edges = []
    for child in visited:
        for pred in preds.get(child, []):
            if pred in visited:
                edges.append({"from": pred, "to": child, "type": "control_dep"})
    return {"units": slice_units, "edges": edges}


def _build_callsite_map(callgraph: Dict[str, Any]) -> Dict[tuple[str, str], Optional[str]]:
    mapping: Dict[tuple[str, str], Optional[str]] = {}
    for edge in callgraph.get("edges", []) or []:
        caller = normalize_signature(edge.get("caller", ""))
        callee = normalize_signature(edge.get("callee", ""))
        if not caller or not callee:
            continue
        if (caller, callee) in mapping:
            continue
        callsite = None
        callsite_obj = edge.get("callsite")
        if isinstance(callsite_obj, dict):
            callsite = callsite_obj.get("unit")
        elif isinstance(callsite_obj, str):
            callsite = callsite_obj
        mapping[(caller, callee)] = callsite
    return mapping


def _build_control_flow_path(
    callsite,
    callsite_map: Dict[tuple[str, str], Optional[str]],
    branch_conditions: List[Dict[str, Any]],
) -> Dict[str, Any]:
    descriptor = callsite.callsite_descriptor if isinstance(callsite.callsite_descriptor, dict) else {}
    component_context = descriptor.get("component_context") or {}
    reachability = descriptor.get("reachability") or {}
    example_path = reachability.get("example_path")

    path_methods: List[str] = []
    if isinstance(example_path, list) and example_path:
        for method in example_path:
            method = normalize_signature(str(method))
            if method:
                path_methods.append(method)
    else:
        caller = normalize_signature(callsite.caller_method)
        if caller:
            path_methods.append(caller)
        callee = normalize_signature(callsite.signature)
        if callee and (not path_methods or callee != path_methods[-1]):
            path_methods.append(callee)

    edges: List[Dict[str, Any]] = []
    for idx in range(len(path_methods) - 1):
        caller = path_methods[idx]
        callee = path_methods[idx + 1]
        edges.append({
            "caller": caller,
            "callee": callee,
            "callsite": callsite_map.get((caller, callee)),
        })

    status = "full" if isinstance(example_path, list) and example_path else "partial"
    return {
        "seed_id": callsite.seed_id,
        "category_id": callsite.category,
        "hit_id": descriptor.get("hit_id"),
        "priority": descriptor.get("priority"),
        "component_context": component_context,
        "reachability": reachability,
        "path_methods": path_methods,
        "edges": edges,
        "sink": {
            "caller_method": callsite.caller_method,
            "callee_signature": callsite.signature,
        },
        "branch_conditions": branch_conditions,
        "status": status,
    }


def _looks_like_branch(stmt: str) -> bool:
    stmt = stmt.strip()
    if stmt.startswith("if "):
        return True
    if stmt.startswith("switch "):
        return True
    return " goto " in stmt or " == " in stmt or " != " in stmt or " < " in stmt or " > " in stmt


def _fcg_neighborhood(callgraph: Dict[str, Any], method_sig: str, k: int) -> Dict[str, Any]:
    edges = callgraph.get("edges", [])
    callers_map: Dict[str, List[str]] = {}
    callees_map: Dict[str, List[str]] = {}
    for edge in edges:
        caller = edge.get("caller")
        callee = edge.get("callee")
        callers_map.setdefault(callee, []).append(caller)
        callees_map.setdefault(caller, []).append(callee)

    callers = set()
    callees = set()
    frontier = {method_sig}
    for _ in range(k):
        next_frontier = set()
        for node in frontier:
            for c in callers_map.get(node, []):
                if c not in callers:
                    callers.add(c)
                    next_frontier.add(c)
            for c in callees_map.get(node, []):
                if c not in callees:
                    callees.add(c)
                    next_frontier.add(c)
        frontier = next_frontier
    return {
        "k": k,
        "callers": sorted(callers),
        "callees": sorted(callees),
        "paths": [],
    }


class ContextBundleBuilder:
    def __init__(self, artifact_store: ArtifactStore) -> None:
        self.artifact_store = artifact_store

    def build_for_index(
        self,
        index: SuspiciousApiIndex,
        static_context: Dict[str, Any],
        callgraph_path: Optional[Path],
        k_hop: int = 2,
    ) -> List[Dict[str, Any]]:
        callgraph = {}
        if callgraph_path and callgraph_path.exists():
            callgraph = _load_json(callgraph_path)
        callsite_map = _build_callsite_map(callgraph) if callgraph else {}
        bundles = []
        method_index_path = self.artifact_store.path("graphs/method_index.json")
        method_index = {}
        if method_index_path.exists():
            method_index = _load_json(method_index_path)
        for callsite in index.callsites:
            cfg_ref = None
            cfg = None
            method_hash = _hash_method_sig(callsite.caller_method)
            cfg_path = self.artifact_store.path(f"graphs/cfg/{method_hash}.json")
            if cfg_path.exists():
                cfg = _load_json(cfg_path)
                cfg_ref = f"cfg/{method_hash}.json"
            elif method_index:
                cfg_key = method_index.get(callsite.caller_method)
                if cfg_key:
                    cfg_path = self.artifact_store.path(f"graphs/cfg/{cfg_key}.json")
                    if cfg_path.exists():
                        cfg = _load_json(cfg_path)
                        cfg_ref = f"cfg/{cfg_key}.json"
            if cfg:
                seed_match = method_name_from_signature(callsite.signature)
                sliced_cfg = _build_slice_from_cfg(cfg, seed_match)
            else:
                sliced_cfg = {
                    "units": [
                        {
                            "unit_id": "seed",
                            "stmt": f"invoke {callsite.signature}",
                            "tags": ["SEED"],
                        }
                    ],
                    "edges": [],
                }
                cfg_ref = cfg_ref or "cfg/unknown.json"
            slice_payload = {
                "seed_id": callsite.seed_id,
                "api_signature": callsite.signature,
                "caller_method": callsite.caller_method,
                "slice": sliced_cfg,
                "cfg_ref": cfg_ref,
                "notes": {"slice_algo": "cfg_backtrace_v0"},
            }
            self.artifact_store.write_json(f"graphs/slices/{callsite.seed_id}.json", slice_payload)
            validate_json(slice_payload, "config/schemas/BackwardSlice.schema.json")
            branch_conditions = [
                {"unit_id": u.get("unit_id"), "stmt": u.get("stmt", "")}
                for u in sliced_cfg.get("units", [])
                if _looks_like_branch(u.get("stmt", ""))
            ]
            control_flow_path = _build_control_flow_path(callsite, callsite_map, branch_conditions)
            path_ref = None
            if control_flow_path.get("path_methods"):
                path_ref = f"graphs/entrypoint_paths/{callsite.seed_id}.json"
                self.artifact_store.write_json(path_ref, control_flow_path)
            bundle = {
                "seed_id": callsite.seed_id,
                "api_category": callsite.category,
                "api_signature": callsite.signature,
                "caller_method": callsite.caller_method,
                "caller_class": callsite.caller_class,
                "sliced_cfg": sliced_cfg,
                "fcg_neighborhood": _fcg_neighborhood(callgraph, callsite.caller_method, k_hop),
                "static_context": static_context,
                "callsite_descriptor": callsite.callsite_descriptor,
                "branch_conditions": branch_conditions,
                "control_flow_path": control_flow_path,
                "control_flow_path_ref": path_ref,
            }
            if isinstance(callsite.callsite_descriptor, dict):
                case_context = {
                    "case_id": callsite.callsite_descriptor.get("case_id"),
                    "priority": callsite.callsite_descriptor.get("priority"),
                    "component_context": callsite.callsite_descriptor.get("component_context"),
                    "reachability": callsite.callsite_descriptor.get("reachability"),
                }
                if any(value is not None for value in case_context.values()):
                    bundle["case_context"] = case_context
            self.artifact_store.write_json(f"graphs/context_bundles/{callsite.seed_id}.json", bundle)
            validate_json(bundle, "config/schemas/ContextBundle.schema.json")
            bundles.append(bundle)
        return bundles


def build_static_context(manifest: Dict[str, Any], strings: Dict[str, Any]) -> Dict[str, Any]:
    permissions = manifest.get("permissions") or manifest.get("all_permissions") or []
    triggers = []
    for receiver in manifest.get("receivers", []):
        if isinstance(receiver, dict):
            actions = receiver.get("intent_actions", [])
        else:
            actions = []
        if any(action in BOOT_TRIGGERS for action in actions):
            triggers.extend(actions)
    strings_nearby = []
    for key in ("urls", "domains", "ips", "suspicious_keywords"):
        strings_nearby.extend(strings.get(key, []))
    return {
        "permissions": sorted(set(permissions)),
        "component_triggers": sorted(set(triggers)),
        "strings_nearby": strings_nearby[:200],
    }

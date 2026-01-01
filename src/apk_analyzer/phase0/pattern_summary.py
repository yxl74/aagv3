from __future__ import annotations

from collections import Counter, defaultdict, deque
from typing import Any, Dict, List, Optional, Set, Tuple

from apk_analyzer.analyzers.package_inventory import package_name_from_class
from apk_analyzer.phase0.cooccurrence_scorer import (
    COOCCURRENCE_PATTERNS,
    CooccurrencePattern,
    pattern_matches,
)
from apk_analyzer.phase0.sensitive_api_matcher import ENTRYPOINT_METHODS
from apk_analyzer.utils.signature_normalize import method_name_from_signature, normalize_signature


def _class_from_signature(signature: str) -> str:
    if signature.startswith("<") and ":" in signature:
        return signature[1: signature.index(":", 1)].strip()
    return signature.split(":", 1)[0].strip("<>")


def _normalize_component_name(name: str, package_name: str) -> str:
    if name.startswith(".") and package_name:
        return f"{package_name}{name}"
    if "." not in name and package_name:
        return f"{package_name}.{name}"
    return name


def _extract_component_map(manifest: Dict[str, Any]) -> Dict[str, str]:
    package_name = manifest.get("package_name") or manifest.get("package") or ""
    components: Dict[str, str] = {}
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
            normalized = _normalize_component_name(str(name), package_name)
            if normalized:
                components[normalized] = component_type
    return components


def _component_entrypoints_from_callgraph(
    callgraph: Dict[str, Any],
    manifest: Dict[str, Any],
) -> List[str]:
    component_map = _extract_component_map(manifest)
    if not component_map:
        return []
    entrypoints: List[str] = []
    nodes = callgraph.get("nodes", []) or []
    for node in nodes:
        method_sig = normalize_signature(node.get("method", ""))
        if not method_sig:
            continue
        class_name = node.get("class") or _class_from_signature(method_sig)
        component_type = component_map.get(class_name)
        if not component_type:
            continue
        method_name = method_name_from_signature(method_sig)
        allowed = ENTRYPOINT_METHODS.get(component_type, set())
        if method_name in allowed:
            entrypoints.append(method_sig)
    return sorted(set(entrypoints))


def _build_adjacency(edges: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    adjacency: Dict[str, List[str]] = {}
    for edge in edges:
        caller = normalize_signature(edge.get("caller", ""))
        callee = normalize_signature(edge.get("callee", ""))
        if not caller or not callee:
            continue
        adjacency.setdefault(caller, []).append(callee)
    return adjacency


def _bfs_entrypoint_index(
    adjacency: Dict[str, List[str]],
    entrypoints: List[str],
) -> Tuple[Dict[str, int], Dict[str, Optional[str]], Dict[str, str]]:
    distances: Dict[str, int] = {}
    predecessors: Dict[str, Optional[str]] = {}
    root_by_method: Dict[str, str] = {}
    queue: deque[str] = deque()
    for entry in sorted(entrypoints):
        distances[entry] = 0
        predecessors[entry] = None
        root_by_method[entry] = entry
        queue.append(entry)
    while queue:
        current = queue.popleft()
        for callee in adjacency.get(current, []):
            if callee in distances:
                continue
            distances[callee] = distances[current] + 1
            predecessors[callee] = current
            root_by_method[callee] = root_by_method[current]
            queue.append(callee)
    return distances, predecessors, root_by_method


def _component_entrypoint_index(
    callgraph: Dict[str, Any],
    manifest: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    entrypoints = _component_entrypoints_from_callgraph(callgraph, manifest)
    if not entrypoints:
        return None
    adjacency = _build_adjacency(callgraph.get("edges", []) or [])
    distances, predecessors, root_by_method = _bfs_entrypoint_index(adjacency, entrypoints)
    return {
        "entrypoints": entrypoints,
        "distances": distances,
        "predecessors": predecessors,
        "root_by_method": root_by_method,
    }


def _reconstruct_path(
    target: str,
    predecessors: Dict[str, Optional[str]],
    *,
    max_len: int = 25,
) -> List[str]:
    path: List[str] = []
    cursor: Optional[str] = target
    while cursor is not None:
        path.append(cursor)
        cursor = predecessors.get(cursor)
        if len(path) >= max_len:
            break
    return list(reversed(path))


def _categories_from_evidence(
    evidence: Dict[str, Any],
    *,
    include_string_categories: bool = True,
) -> Set[str]:
    categories: Set[str] = set()
    for cat in evidence.get("categories", []) or []:
        if cat:
            categories.add(str(cat))
    if include_string_categories:
        for cat in evidence.get("string_categories", []) or []:
            if cat:
                categories.add(str(cat))
    return categories


def _is_reachable_group(group: Dict[str, Any]) -> bool:
    reach = group.get("reachability") or {}
    return bool(reach.get("reachable_from_entrypoint", False))


def _pattern_ids_for_categories(
    categories: Set[str],
    patterns: List[CooccurrencePattern],
) -> List[str]:
    return [p.pattern_id for p in patterns if pattern_matches(p, categories)]


def _pattern_evidence(
    pattern: CooccurrencePattern,
    categories: Set[str],
    category_examples: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Construct lightweight, deterministic evidence for why a pattern matched.

    This is intended for debugging/traceability, not as a hard guarantee of
    execution semantics.
    """
    evidence: Dict[str, Any] = {}

    if pattern.all_of:
        evidence["all_of"] = {
            cat: category_examples.get(cat) for cat in sorted(pattern.all_of)
        }

    if pattern.any_of:
        matched = sorted(pattern.any_of & categories)
        selected = matched[0] if matched else ""
        evidence["any_of_selected"] = selected
        if selected:
            evidence["any_of_example"] = category_examples.get(selected)

    if pattern.any_of_2:
        matched = sorted(pattern.any_of_2 & categories)
        selected = matched[0] if matched else ""
        evidence["any_of_2_selected"] = selected
        if selected:
            evidence["any_of_2_example"] = category_examples.get(selected)

    if pattern.min_count > 0 and pattern.from_set:
        matched = sorted(pattern.from_set & categories)
        selected = matched[: pattern.min_count]
        evidence["from_set_selected"] = selected
        evidence["from_set_examples"] = {
            cat: category_examples.get(cat) for cat in selected
        }

    return evidence


def _entrypoint_signature(group: Dict[str, Any]) -> str:
    reachability = group.get("reachability") or {}
    if not reachability.get("reachable_from_entrypoint", False):
        return ""
    path = reachability.get("example_path") or []
    if not path:
        return ""
    return str(path[0])


def build_cooccurrence_pattern_summary(
    hit_groups: List[Dict[str, Any]],
    code_blocks: Optional[List[Dict[str, Any]]] = None,
    *,
    callgraph: Optional[Dict[str, Any]] = None,
    manifest: Optional[Dict[str, Any]] = None,
    patterns: Optional[List[CooccurrencePattern]] = None,
    include_string_categories: bool = True,
    max_packages: int = 50,
    max_entrypoints: int = 50,
) -> Dict[str, Any]:
    """
    Build a multi-scope summary of co-occurrence patterns.

    Why this exists:
      - Groups and class-level blocks often *split* an attack chain across multiple
        classes (e.g., Accessibility in one class, C2 in another), which means
        per-group/per-class pattern matches can look artificially low.
      - This summary computes pattern matches at broader scopes (app/package union)
        to aid debugging and library/package pruning decisions.
    """
    patterns = patterns or COOCCURRENCE_PATTERNS
    code_blocks = code_blocks or []

    pattern_ids = [p.pattern_id for p in patterns]

    def summarize_groups(groups: List[Dict[str, Any]]) -> Dict[str, Any]:
        counts: Counter[str] = Counter()
        matched_group_count = 0
        for group in groups:
            cats = _categories_from_evidence(group, include_string_categories=include_string_categories)
            matched = _pattern_ids_for_categories(cats, patterns)
            if matched:
                matched_group_count += 1
                counts.update(matched)
        return {
            "group_count": len(groups),
            "groups_with_patterns": matched_group_count,
            "pattern_counts": {pid: int(counts.get(pid, 0)) for pid in pattern_ids if counts.get(pid, 0)},
            "unique_patterns_matched": [pid for pid in pattern_ids if counts.get(pid, 0)],
        }

    def summarize_blocks(blocks: List[Dict[str, Any]]) -> Dict[str, Any]:
        counts: Counter[str] = Counter()
        matched_block_count = 0
        for block in blocks:
            cats = _categories_from_evidence(block, include_string_categories=include_string_categories)
            matched = _pattern_ids_for_categories(cats, patterns)
            if matched:
                matched_block_count += 1
                counts.update(matched)
        return {
            "block_count": len(blocks),
            "blocks_with_patterns": matched_block_count,
            "pattern_counts": {pid: int(counts.get(pid, 0)) for pid in pattern_ids if counts.get(pid, 0)},
            "unique_patterns_matched": [pid for pid in pattern_ids if counts.get(pid, 0)],
        }

    def union_summary_from_groups(groups: List[Dict[str, Any]]) -> Dict[str, Any]:
        categories: Set[str] = set()
        category_examples: Dict[str, Dict[str, Any]] = {}
        for group in groups:
            cats = _categories_from_evidence(group, include_string_categories=include_string_categories)
            categories |= cats
            for cat in cats:
                if cat in category_examples:
                    continue
                category_examples[cat] = {
                    "group_id": group.get("group_id"),
                    "caller_class": group.get("caller_class"),
                    "caller_method": group.get("caller_method"),
                }

        matched_patterns: List[CooccurrencePattern] = [
            p for p in patterns if pattern_matches(p, categories)
        ]
        return {
            "group_count": len(groups),
            "category_union": sorted(categories),
            "category_count": len(categories),
            "pattern_count": len(matched_patterns),
            "patterns_matched": [p.pattern_id for p in matched_patterns],
            "pattern_details": [
                {
                    "pattern_id": p.pattern_id,
                    "description": p.description,
                    "priority_override": p.priority_override,
                    "evidence": _pattern_evidence(p, categories, category_examples),
                }
                for p in matched_patterns
            ],
        }

    def package_summary_from_groups(groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        cats_by_pkg: Dict[str, Set[str]] = defaultdict(set)
        group_count_by_pkg: Dict[str, int] = defaultdict(int)
        example_classes_by_pkg: Dict[str, List[str]] = defaultdict(list)
        for group in groups:
            cls = str(group.get("caller_class") or "")
            pkg = package_name_from_class(cls)
            if not pkg:
                continue
            group_count_by_pkg[pkg] += 1
            cats_by_pkg[pkg] |= _categories_from_evidence(group, include_string_categories=include_string_categories)
            if cls and cls not in example_classes_by_pkg[pkg] and len(example_classes_by_pkg[pkg]) < 3:
                example_classes_by_pkg[pkg].append(cls)

        packages: List[Dict[str, Any]] = []
        for pkg, cats in cats_by_pkg.items():
            matched = [p.pattern_id for p in patterns if pattern_matches(p, cats)]
            if not matched:
                continue
            packages.append({
                "package": pkg,
                "group_count": int(group_count_by_pkg.get(pkg, 0)),
                "category_union": sorted(cats),
                "category_count": len(cats),
                "pattern_count": len(matched),
                "patterns_matched": matched,
                "example_classes": example_classes_by_pkg.get(pkg, [])[:3],
            })

        packages.sort(key=lambda p: (-int(p.get("pattern_count") or 0), -int(p.get("group_count") or 0), p.get("package") or ""))
        return packages[:max_packages]

    def entrypoint_summary_from_groups(
        groups: List[Dict[str, Any]],
        entrypoint_index: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        cats_by_entry: Dict[str, Set[str]] = defaultdict(set)
        group_count_by_entry: Dict[str, int] = defaultdict(int)
        example_path_by_entry: Dict[str, List[str]] = {}
        min_path_len_by_entry: Dict[str, int] = {}

        for group in groups:
            example_path = (group.get("reachability") or {}).get("example_path", []) or []
            path_len = (group.get("reachability") or {}).get("shortest_path_len")
            entry = ""
            if entrypoint_index:
                caller_method = normalize_signature(str(group.get("caller_method") or ""))
                if caller_method:
                    root = entrypoint_index.get("root_by_method", {}).get(caller_method)
                    if root:
                        entry = root
                        example_path = _reconstruct_path(
                            caller_method,
                            entrypoint_index.get("predecessors", {}),
                        )
                        path_len = entrypoint_index.get("distances", {}).get(caller_method)
                        entry = root
            if not entry:
                entry = _entrypoint_signature(group)
                if not entry:
                    continue
            group_count_by_entry[entry] += 1
            cats_by_entry[entry] |= _categories_from_evidence(
                group, include_string_categories=include_string_categories
            )
            if entry not in example_path_by_entry:
                example_path_by_entry[entry] = example_path
            if path_len is not None:
                current = min_path_len_by_entry.get(entry)
                if current is None or path_len < current:
                    min_path_len_by_entry[entry] = int(path_len)
                    example_path_by_entry[entry] = example_path

        entries: List[Dict[str, Any]] = []
        for entry, cats in cats_by_entry.items():
            matched = [p.pattern_id for p in patterns if pattern_matches(p, cats)]
            entries.append({
                "entrypoint": entry,
                "group_count": int(group_count_by_entry.get(entry, 0)),
                "category_union": sorted(cats),
                "category_count": len(cats),
                "pattern_count": len(matched),
                "patterns_matched": matched,
                "example_path": example_path_by_entry.get(entry, [])[:25],
                "shortest_path_len": min_path_len_by_entry.get(entry),
            })

        entries.sort(key=lambda e: (-int(e.get("pattern_count") or 0), -int(e.get("group_count") or 0), e.get("entrypoint") or ""))
        entries_with_patterns = [e for e in entries if e.get("pattern_count", 0) > 0]
        return {
            "entrypoint_count": len(entries),
            "entrypoints_with_patterns": len(entries_with_patterns),
            "entrypoints": entries_with_patterns[:max_entrypoints],
        }

    groups_all = hit_groups or []
    groups_reachable = [g for g in groups_all if _is_reachable_group(g)]
    entrypoint_index = None
    if callgraph and manifest:
        entrypoint_index = _component_entrypoint_index(callgraph, manifest)

    return {
        "pattern_definitions": {
            "count": len(patterns),
            "pattern_ids": pattern_ids,
        },
        "group_level": {
            "all_groups": summarize_groups(groups_all),
            "reachable_groups": summarize_groups(groups_reachable),
        },
        "block_level": {
            "final_blocks": summarize_blocks(code_blocks),
        },
        "entrypoint_level": {
            "from_reachable_groups": entrypoint_summary_from_groups(
                groups_reachable,
                entrypoint_index=entrypoint_index,
            ),
        },
        "app_level": {
            "from_all_groups": union_summary_from_groups(groups_all),
            "from_reachable_groups": union_summary_from_groups(groups_reachable),
        },
        "package_level": {
            "from_all_groups": package_summary_from_groups(groups_all),
            "from_reachable_groups": package_summary_from_groups(groups_reachable),
        },
    }

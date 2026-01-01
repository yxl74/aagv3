from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Set


def class_name_from_method_signature(signature: str) -> str:
    """
    Extract a Java class name from a Soot-style method signature.

    Examples:
        "<com.example.Foo: void bar()>" -> "com.example.Foo"
        "com.example.Foo: void bar()" -> "com.example.Foo"
        "com.example.Foo" -> "com.example.Foo"
    """
    if not signature:
        return ""
    value = str(signature).strip()
    if not value:
        return ""

    if value.startswith("<") and ":" in value:
        try:
            return value[1:value.index(":", 1)].strip()
        except ValueError:
            return value.strip("<> ").split(":", 1)[0].strip()

    if ":" in value:
        return value.split(":", 1)[0].strip("<> ").strip()

    return value.strip("<> ").strip()


def outer_class_name(class_name: str) -> str:
    if not class_name:
        return ""
    return class_name.split("$", 1)[0]


def package_name_from_class(class_name: str) -> str:
    cls = outer_class_name(class_name)
    if "." not in cls:
        return ""
    return cls.rsplit(".", 1)[0]


def _dominant_package_prefix(class_names: Iterable[str]) -> List[str]:
    """
    Return the most common package prefix(es) among the given fully-qualified class names.

    Output prefixes are normalized with a trailing dot, e.g. "com.example.app.".
    """
    counts: Dict[str, int] = {}
    for class_name in class_names:
        pkg = package_name_from_class(class_name)
        if not pkg:
            continue
        prefix = f"{pkg}."
        counts[prefix] = counts.get(prefix, 0) + 1
    if not counts:
        return []
    max_count = max(counts.values())
    return sorted([prefix for prefix, count in counts.items() if count == max_count])


def build_package_inventory(
    callgraph: Optional[Dict[str, Any]],
    sensitive_hits: Optional[List[Dict[str, Any]]] = None,
    hit_groups: Optional[List[Dict[str, Any]]] = None,
    manifest: Optional[Dict[str, Any]] = None,
    *,
    max_examples_per_package: int = 3,
) -> Dict[str, Any]:
    """
    Build a package inventory from callgraph + hit evidence.

    This is used for:
      - debugging app/library classification issues
      - optional LLM package-scope selection
    """
    sensitive_hits = sensitive_hits or []
    hit_groups = hit_groups or []
    manifest = manifest or {}

    manifest_package = manifest.get("package_name") or manifest.get("package") or ""

    component_classes: Set[str] = set()
    for key in ("activities", "services", "receivers", "providers"):
        for comp in manifest.get(key, []) or []:
            name = comp.get("name", "") if isinstance(comp, dict) else str(comp or "")
            if not name:
                continue
            component_classes.add(name)

    component_packages: Set[str] = {package_name_from_class(c) for c in component_classes if package_name_from_class(c)}
    dominant_component_prefixes = _dominant_package_prefix(component_classes)

    # Accumulators
    method_count: Dict[str, int] = defaultdict(int)
    caller_edge_count: Dict[str, int] = defaultdict(int)
    classes_by_package: Dict[str, Set[str]] = defaultdict(set)
    hit_count: Dict[str, int] = defaultdict(int)
    group_count: Dict[str, int] = defaultdict(int)
    categories_by_package: Dict[str, Set[str]] = defaultdict(set)
    examples_by_package: Dict[str, List[str]] = defaultdict(list)

    # Callgraph nodes
    if callgraph:
        for node in callgraph.get("nodes", []) or []:
            cls = class_name_from_method_signature(node.get("method", ""))
            pkg = package_name_from_class(cls)
            if not pkg:
                continue
            method_count[pkg] += 1
            classes_by_package[pkg].add(outer_class_name(cls))
            if len(examples_by_package[pkg]) < max_examples_per_package:
                if cls and cls not in examples_by_package[pkg]:
                    examples_by_package[pkg].append(cls)

        for edge in callgraph.get("edges", []) or []:
            caller_cls = class_name_from_method_signature(edge.get("caller", ""))
            caller_pkg = package_name_from_class(caller_cls)
            if not caller_pkg:
                continue
            caller_edge_count[caller_pkg] += 1

    # Hits
    for hit in sensitive_hits:
        caller = hit.get("caller", {}) or {}
        caller_cls = caller.get("class") or class_name_from_method_signature(caller.get("method", ""))
        pkg = package_name_from_class(caller_cls)
        if not pkg:
            continue
        hit_count[pkg] += 1
        cat = hit.get("category_id")
        if cat:
            categories_by_package[pkg].add(cat)

    # Groups
    for group in hit_groups:
        caller_cls = group.get("caller_class") or class_name_from_method_signature(group.get("caller_method", ""))
        pkg = package_name_from_class(caller_cls)
        if not pkg:
            continue
        group_count[pkg] += 1
        for cat in group.get("categories", []) or []:
            if cat:
                categories_by_package[pkg].add(cat)
        for cat in group.get("string_categories", []) or []:
            if cat:
                categories_by_package[pkg].add(cat)

    # Merge all packages observed from any source
    all_packages: Set[str] = set()
    all_packages.update(method_count.keys())
    all_packages.update(hit_count.keys())
    all_packages.update(group_count.keys())
    all_packages.update(component_packages)
    if manifest_package:
        all_packages.add(manifest_package)

    packages: List[Dict[str, Any]] = []
    for pkg in sorted(all_packages):
        pkg_classes = classes_by_package.get(pkg, set())
        # If a component package is com.foo.bar, treat com.foo.bar.baz as component-related.
        is_component_related = any(pkg == c or pkg.startswith(f"{c}.") for c in component_packages)
        packages.append({
            "package": pkg,
            "class_count": len(pkg_classes),
            "method_count": int(method_count.get(pkg, 0)),
            "caller_edge_count": int(caller_edge_count.get(pkg, 0)),
            "hit_count": int(hit_count.get(pkg, 0)),
            "group_count": int(group_count.get(pkg, 0)),
            "categories": sorted(categories_by_package.get(pkg, set())),
            "example_classes": examples_by_package.get(pkg, [])[:max_examples_per_package],
            "is_manifest_package": bool(
                manifest_package
                and (pkg == manifest_package or pkg.startswith(f"{manifest_package}."))
            ),
            "is_component_package": is_component_related,
        })

    packages.sort(key=lambda p: (-(p.get("hit_count") or 0), -(p.get("method_count") or 0), p.get("package") or ""))

    return {
        "manifest_package": manifest_package,
        "component_class_count": len(component_classes),
        "component_packages": sorted(component_packages),
        "dominant_component_prefixes": dominant_component_prefixes,
        "package_count": len(packages),
        "packages": packages,
    }


def package_inventory_preview(
    inventory: Dict[str, Any],
    *,
    max_packages: int = 80,
    min_hit_count: int = 1,
) -> List[Dict[str, Any]]:
    """
    Produce a compact, LLM-friendly preview of the package inventory.
    """
    packages = inventory.get("packages", []) or []
    if not isinstance(packages, list):
        return []

    selected: List[Dict[str, Any]] = []
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        if (entry.get("hit_count") or 0) < min_hit_count:
            continue
        selected.append({
            "package": entry.get("package"),
            "hit_count": entry.get("hit_count"),
            "group_count": entry.get("group_count"),
            "method_count": entry.get("method_count"),
            "class_count": entry.get("class_count"),
            "categories": entry.get("categories"),
            "is_manifest_package": entry.get("is_manifest_package"),
            "is_component_package": entry.get("is_component_package"),
            "example_classes": entry.get("example_classes"),
        })
        if len(selected) >= max_packages:
            break
    return selected

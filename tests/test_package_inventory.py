from __future__ import annotations

from apk_analyzer.analyzers.package_inventory import (
    build_package_inventory,
    class_name_from_method_signature,
    package_inventory_preview,
)


def test_class_name_from_method_signature():
    assert class_name_from_method_signature("<com.example.Foo: void bar()>") == "com.example.Foo"
    assert class_name_from_method_signature("com.example.Foo: void bar()") == "com.example.Foo"
    assert class_name_from_method_signature("com.example.Foo") == "com.example.Foo"
    assert class_name_from_method_signature("") == ""


def test_build_package_inventory_counts():
    callgraph = {
        "nodes": [
            {"method": "<com.app.A: void a()>"},
            {"method": "<com.app.A$Inner: void x()>"},
            {"method": "<com.sdk.S: void s()>"},
        ],
        "edges": [
            {"caller": "<com.app.A: void a()>", "callee": "<com.sdk.S: void s()>"},
            {"caller": "<com.app.A$Inner: void x()>", "callee": "<com.sdk.S: void s()>"},
        ],
    }
    hits = [
        {"caller": {"class": "com.app.A", "method": "<com.app.A: void a()>"}, "category_id": "C2_NETWORKING"},
        {"caller": {"class": "com.sdk.S", "method": "<com.sdk.S: void s()>"}, "category_id": "C2_NETWORKING"},
    ]
    groups = [
        {"caller_class": "com.app.A", "categories": ["C2_NETWORKING"], "string_categories": []},
        {"caller_class": "com.sdk.S", "categories": ["C2_NETWORKING"], "string_categories": ["SOCIAL_ENGINEERING_PERMISSION_LURE_SETTINGS"]},
    ]
    manifest = {"package_name": "com.appid", "activities": ["com.app.A"]}

    inventory = build_package_inventory(callgraph, hits, groups, manifest)
    assert inventory["manifest_package"] == "com.appid"
    assert "packages" in inventory

    by_pkg = {p["package"]: p for p in inventory["packages"]}
    assert by_pkg["com.app"]["method_count"] == 2
    assert by_pkg["com.app"]["caller_edge_count"] == 2
    assert by_pkg["com.app"]["hit_count"] == 1
    assert by_pkg["com.app"]["group_count"] == 1
    assert "C2_NETWORKING" in by_pkg["com.app"]["categories"]

    assert by_pkg["com.sdk"]["method_count"] == 1
    assert by_pkg["com.sdk"]["caller_edge_count"] == 0
    assert by_pkg["com.sdk"]["hit_count"] == 1
    assert by_pkg["com.sdk"]["group_count"] == 1
    assert "SOCIAL_ENGINEERING_PERMISSION_LURE_SETTINGS" in by_pkg["com.sdk"]["categories"]


def test_package_inventory_preview_filters_by_hit_count():
    inventory = {
        "packages": [
            {"package": "com.a", "hit_count": 2, "group_count": 1, "method_count": 10, "class_count": 3, "categories": ["X"], "is_manifest_package": False, "is_component_package": False, "example_classes": []},
            {"package": "com.b", "hit_count": 0, "group_count": 0, "method_count": 5, "class_count": 2, "categories": [], "is_manifest_package": False, "is_component_package": False, "example_classes": []},
        ]
    }
    preview = package_inventory_preview(inventory, max_packages=10, min_hit_count=1)
    assert len(preview) == 1
    assert preview[0]["package"] == "com.a"

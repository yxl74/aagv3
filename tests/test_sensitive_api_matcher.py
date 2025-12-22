from __future__ import annotations

import json

from apk_analyzer.knowledge.api_catalog import ApiCatalog
from apk_analyzer.phase0.sensitive_api_matcher import build_sensitive_api_hits


def test_sensitive_api_hits_with_reachability(tmp_path):
    catalog_payload = {
        "version": "test",
        "categories": {
            "COLLECTION_SMS_MESSAGES": {
                "priority": "CRITICAL",
                "description": "SMS collection",
                "weight": 1.0,
                "mitre": {"primary": "T1234", "aliases": []},
                "requires_slice": True,
                "pha_tags": ["SPYWARE"],
                "permission_hints": ["READ_SMS"],
                "signatures": {
                    "methods": [
                        "<android.content.ContentResolver: android.database.Cursor query(...)>"
                    ],
                    "fields": [],
                    "strings": [],
                },
            }
        },
    }
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_text(json.dumps(catalog_payload), encoding="utf-8")
    catalog = ApiCatalog.load(catalog_path)

    callgraph = {
        "nodes": [
            {
                "method": "<com.example.MainActivity: void onCreate()>",
                "class": "com.example.MainActivity",
            },
            {
                "method": "<com.example.MainActivity: void doSms()>",
                "class": "com.example.MainActivity",
            },
            {
                "method": "<android.content.ContentResolver: android.database.Cursor query(...)>",
                "class": "android.content.ContentResolver",
            },
        ],
        "edges": [
            {
                "caller": "<com.example.MainActivity: void onCreate()>",
                "callee": "<com.example.MainActivity: void doSms()>",
            },
            {
                "caller": "<com.example.MainActivity: void doSms()>",
                "callee": "<android.content.ContentResolver: android.database.Cursor query(...)>",
            },
        ],
        "metadata": {},
    }
    manifest = {
        "package_name": "com.example",
        "activities": ["com.example.MainActivity"],
        "min_sdk_version": 21,
        "target_sdk_version": 34,
    }

    hits = build_sensitive_api_hits(callgraph, catalog, manifest)

    assert hits["summary"]["total_hits"] == 1
    hit = hits["hits"][0]
    assert hit["category_id"] == "COLLECTION_SMS_MESSAGES"
    assert hit["reachability"]["reachable_from_entrypoint"] is True
    assert hit["reachability"]["shortest_path_len"] == 2
    assert hit["component_context"]["component_type"] == "Activity"
    assert hit["component_context"]["entrypoint_method"] == "<com.example.MainActivity: void onCreate()>"

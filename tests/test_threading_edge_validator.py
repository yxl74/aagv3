from __future__ import annotations

from apk_analyzer.phase0.sensitive_api_matcher import _filter_valid_entrypoints
from apk_analyzer.phase0.threading_edge_validator import validate_threading_edges


def test_filter_valid_entrypoints_excludes_callbacks() -> None:
    component_map = {
        "com.example.MainActivity": {
            "component_type": "Activity",
            "component_name": "com.example.MainActivity",
        }
    }
    entrypoints = [
        "<com.example.MainActivity: void onCreate(android.os.Bundle)>",
        # Callback/thread methods should never be treated as roots, even if present in an override list.
        "<com.example.MainActivity: void onClick(android.view.View)>",
        "<com.example.Worker: void run()>",
    ]
    assert _filter_valid_entrypoints(entrypoints, component_map) == [
        "<com.example.MainActivity: void onCreate(android.os.Bundle)>"
    ]


def test_threading_edge_validator_detects_missing_start_bridges() -> None:
    callgraph = {
        "nodes": [],
        "edges": [
            {
                "caller": "<com.example.A: void foo()>",
                "callee": "<java.lang.Thread: void start()>",
                "callsite": {"unit": "virtualinvoke $r0.<java.lang.Thread: void start()>()"},
                "edge_source": "jimple_invoke",
            }
        ],
        "metadata": {},
    }
    result = validate_threading_edges(callgraph)
    assert result["start_callsites"] == 1
    assert result["threading_edge_count"] == 0
    assert result["missing_run_edges"] == 1


def test_threading_edge_validator_accepts_synthetic_bridge() -> None:
    callsite = "virtualinvoke $r0.<java.lang.Thread: void start()>()"
    callgraph = {
        "nodes": [],
        "edges": [
            {
                "caller": "<com.example.A: void foo()>",
                "callee": "<java.lang.Thread: void start()>",
                "callsite": {"unit": callsite},
                "edge_source": "jimple_invoke",
            },
            {
                "caller": "<com.example.A: void foo()>",
                "callee": "<com.example.B: void run()>",
                "callsite": {"unit": callsite},
                "edge_source": "threading_synthetic",
                "pattern": "thread_start",
                "confidence": "high",
            },
        ],
        "metadata": {},
    }
    result = validate_threading_edges(callgraph)
    assert result["start_callsites"] == 1
    assert result["threading_edge_count"] == 1
    assert result["missing_run_edges"] == 0


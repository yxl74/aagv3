from __future__ import annotations

from apk_analyzer.phase0.sensitive_api_matcher import (
    _augmented_edge_weight,
    _build_weighted_adjacency,
    _compute_strict_preferred_reachability,
    _dijkstra_from_entrypoints,
    _strict_edge_weight,
)


def test_strict_preferred_when_strict_path_exists() -> None:
    entry = "<com.example.Entry: void onCreate(android.os.Bundle)>"
    a = "<com.example.A: void a()>"
    b = "<com.example.B: void b()>"
    sink = "<com.example.Sink: void sink()>"

    edges = [
        {"caller": entry, "callee": a, "edge_source": "soot_cg", "callsite": {"unit": "invoke a"}},
        {"caller": a, "callee": b, "edge_source": "jimple_invoke", "callsite": {"unit": "invoke b"}},
        {"caller": b, "callee": sink, "edge_source": "soot_cg", "callsite": {"unit": "invoke sink"}},
        # Synthetic shortcut exists, but strict path is reachable and should be preferred.
        {
            "caller": entry,
            "callee": b,
            "edge_source": "threading_synthetic",
            "edge_layer": "synthetic",
            "pattern": "thread_start",
            "confidence": "high",
            "callsite": {"unit": "synthetic bridge"},
        },
    ]

    strict_adj, strict_info = _build_weighted_adjacency(
        edges,
        include_synthetic=False,
        weight_fn=_strict_edge_weight,
    )
    strict_dist, strict_pred, strict_pred_edges = _dijkstra_from_entrypoints(strict_adj, [entry])

    aug_adj, aug_info = _build_weighted_adjacency(
        edges,
        include_synthetic=True,
        weight_fn=_augmented_edge_weight,
    )
    aug_dist, aug_pred, aug_pred_edges = _dijkstra_from_entrypoints(aug_adj, [entry])

    reach = _compute_strict_preferred_reachability(
        caller_sig=b,
        callee_sig=sink,
        strict_distances=strict_dist,
        strict_predecessors=strict_pred,
        strict_pred_edges=strict_pred_edges,
        strict_edge_info=strict_info,
        augmented_distances=aug_dist,
        augmented_predecessors=aug_pred,
        augmented_pred_edges=aug_pred_edges,
        augmented_edge_info=aug_info,
        max_example_path=20,
    )

    assert reach["reachable_from_entrypoint"] is True
    assert reach["path_layer"] == "strict"
    assert reach["example_path"] == [entry, a, b, sink]
    assert [e.get("edge_source") for e in reach.get("example_edges", [])] == [
        "soot_cg",
        "jimple_invoke",
        "soot_cg",
    ]


def test_augmented_fallback_when_strict_unreachable() -> None:
    entry = "<com.example.Entry: void onCreate(android.os.Bundle)>"
    a = "<com.example.A: void a()>"
    b = "<com.example.B: void b()>"
    sink = "<com.example.Sink: void sink()>"

    edges = [
        {"caller": entry, "callee": a, "edge_source": "soot_cg", "callsite": {"unit": "invoke a"}},
        # Missing strict edge a -> b; only available as synthetic bridge.
        {
            "caller": a,
            "callee": b,
            "edge_source": "listener_registration_synthetic",
            "edge_layer": "synthetic",
            "pattern": "setOnClickListener",
            "confidence": "high",
            "callsite": {"unit": "synthetic reg"},
        },
        {"caller": b, "callee": sink, "edge_source": "soot_cg", "callsite": {"unit": "invoke sink"}},
    ]

    strict_adj, strict_info = _build_weighted_adjacency(
        edges,
        include_synthetic=False,
        weight_fn=_strict_edge_weight,
    )
    strict_dist, strict_pred, strict_pred_edges = _dijkstra_from_entrypoints(strict_adj, [entry])

    aug_adj, aug_info = _build_weighted_adjacency(
        edges,
        include_synthetic=True,
        weight_fn=_augmented_edge_weight,
    )
    aug_dist, aug_pred, aug_pred_edges = _dijkstra_from_entrypoints(aug_adj, [entry])

    reach = _compute_strict_preferred_reachability(
        caller_sig=b,
        callee_sig=sink,
        strict_distances=strict_dist,
        strict_predecessors=strict_pred,
        strict_pred_edges=strict_pred_edges,
        strict_edge_info=strict_info,
        augmented_distances=aug_dist,
        augmented_predecessors=aug_pred,
        augmented_pred_edges=aug_pred_edges,
        augmented_edge_info=aug_info,
        max_example_path=20,
    )

    assert reach["reachable_from_entrypoint"] is True
    assert reach["path_layer"] == "augmented"
    assert reach["example_path"] == [entry, a, b, sink]
    assert [e.get("edge_source") for e in reach.get("example_edges", [])] == [
        "soot_cg",
        "listener_registration_synthetic",
        "soot_cg",
    ]

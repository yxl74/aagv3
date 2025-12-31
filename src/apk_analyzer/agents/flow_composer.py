"""Static flow composition module.

This module implements static (non-LLM) composition of flow-level analyses
from pre-computed method analyses.

Key classes:
- ComposedFlowAnalysis: Statically composed analysis for a flow
- FlowComposer: Composes method analyses into flow-level context
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from apk_analyzer.agents.method_tier1 import MethodAnalysis


@dataclass
class ComposedFlowAnalysis:
    """Statically composed analysis for a flow.

    Aggregates method analyses along the execution path into
    a unified flow-level analysis for tier2 consumption.
    """

    flow_id: str
    api_category: str
    sink_api: str

    # Ordered method analyses along the path
    path_analyses: List[MethodAnalysis] = field(default_factory=list)

    # Aggregated from all methods
    all_constraints: List[Dict[str, Any]] = field(default_factory=list)
    all_required_inputs: List[Dict[str, Any]] = field(default_factory=list)

    # From control_flow_path
    component_context: Dict[str, Any] = field(default_factory=dict)
    reachability: Dict[str, Any] = field(default_factory=dict)

    # Statistics
    methods_analyzed: int = 0
    methods_with_jadx: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict."""
        result = asdict(self)
        # Convert MethodAnalysis objects to dicts
        result["path_analyses"] = [
            ma.to_dict() if isinstance(ma, MethodAnalysis) else ma
            for ma in self.path_analyses
        ]
        return result


# Backwards compatibility alias
ComposedSeedAnalysis = ComposedFlowAnalysis


def deduplicate_inputs(inputs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate required inputs by type+name.

    Keeps the first occurrence of each unique (type, name) pair.
    """
    seen: set = set()
    result: List[Dict[str, Any]] = []

    for inp in inputs:
        key = (inp.get("type", ""), inp.get("name", ""))
        if key not in seen:
            seen.add(key)
            result.append(inp)

    return result


def compose_flow_analysis(
    flow: Dict[str, Any],
    method_cache: Dict[str, MethodAnalysis],
) -> ComposedFlowAnalysis:
    """Statically compose method analyses into flow-level analysis.

    Args:
        flow: Flow dict with control_flow_path, api_category, etc.
        method_cache: Dict of method_sig -> MethodAnalysis

    Returns:
        ComposedFlowAnalysis with aggregated path analyses
    """
    control_flow_path = flow.get("control_flow_path", {})
    path_methods = control_flow_path.get("path_methods", [])

    # Collect analyses for each method in path
    path_analyses: List[MethodAnalysis] = []
    all_constraints: List[Dict[str, Any]] = []
    all_required_inputs: List[Dict[str, Any]] = []
    methods_with_jadx = 0

    # Framework prefixes to identify sink API (last in path)
    framework_prefixes = ("<android.", "<java.", "<javax.", "<dalvik.")

    for method in path_methods:
        # Skip framework sink APIs (they're the sink, not analyzed)
        if any(method.startswith(prefix) for prefix in framework_prefixes):
            continue

        if method in method_cache:
            analysis = method_cache[method]
            path_analyses.append(analysis)
            all_constraints.extend(analysis.path_constraints)
            all_required_inputs.extend(analysis.required_inputs)
            if analysis.jadx_available:
                methods_with_jadx += 1
        else:
            # Method not in cache - create placeholder
            placeholder = MethodAnalysis.placeholder(method)
            path_analyses.append(placeholder)

    # Determine sink API (typically last method in path)
    sink_api = ""
    for method in reversed(path_methods):
        if any(method.startswith(prefix) for prefix in framework_prefixes):
            sink_api = method
            break

    return ComposedFlowAnalysis(
        flow_id=flow.get("flow_id") or flow.get("seed_id", ""),
        api_category=flow.get("api_category", ""),
        sink_api=sink_api,
        path_analyses=path_analyses,
        all_constraints=all_constraints,
        all_required_inputs=deduplicate_inputs(all_required_inputs),
        component_context=control_flow_path.get("component_context", {}),
        reachability=control_flow_path.get("reachability", {}),
        methods_analyzed=len(path_analyses),
        methods_with_jadx=methods_with_jadx,
    )


# Backwards compatibility alias
compose_seed_analysis = compose_flow_analysis


def prepare_tier2_input(
    composed: ComposedFlowAnalysis,
    include_full_analyses: bool = False,
) -> Dict[str, Any]:
    """Prepare tier2 input from composed flow analysis.

    Args:
        composed: ComposedFlowAnalysis to convert
        include_full_analyses: If True, include full MethodAnalysis objects.
                              If False, include only summaries (lighter).

    Returns:
        Dict suitable for tier2 prompt consumption
    """
    # Build execution path summary
    if include_full_analyses:
        execution_path = [
            {
                "method": a.method_sig,
                "jadx_available": a.jadx_available,
                "summary": a.function_summary,
                "constraints": a.path_constraints,
                "required_inputs": a.required_inputs,
                "data_flow": a.data_flow,
                "trigger_info": a.trigger_info,
                "facts": a.facts,
                "uncertainties": a.uncertainties,
                "confidence": a.confidence,
            }
            for a in composed.path_analyses
        ]
    else:
        # Lighter summary for tier2
        execution_path = [
            {
                "method": a.method_sig,
                "jadx_available": a.jadx_available,
                "summary": a.function_summary,
                "constraints": a.path_constraints,
                "data_flow": a.data_flow,
                "trigger_info": a.trigger_info,
            }
            for a in composed.path_analyses
        ]

    # Extract permissions from required inputs
    required_permissions = [
        inp for inp in composed.all_required_inputs
        if inp.get("type") == "permission"
    ]

    return {
        "flow_id": composed.flow_id,
        "api_category": composed.api_category,
        "sink_api": composed.sink_api,

        # Full method-by-method breakdown
        "execution_path": execution_path,

        # Aggregated for quick reference
        "all_constraints": composed.all_constraints,
        "required_permissions": required_permissions,
        "all_required_inputs": composed.all_required_inputs,

        # Entrypoint info
        "component_context": composed.component_context,
        "reachability": composed.reachability,

        # Statistics
        "methods_analyzed": composed.methods_analyzed,
        "methods_with_jadx": composed.methods_with_jadx,
    }


def compose_all_flows(
    flows: List[Dict[str, Any]],
    method_cache: Dict[str, MethodAnalysis],
) -> List[ComposedFlowAnalysis]:
    """Compose analyses for all flows.

    Args:
        flows: List of flow dicts
        method_cache: Dict of method_sig -> MethodAnalysis

    Returns:
        List of ComposedFlowAnalysis, one per flow
    """
    return [compose_flow_analysis(flow, method_cache) for flow in flows]


# Backwards compatibility alias
compose_all_seeds = compose_all_flows


def prepare_all_tier2_inputs(
    composed_flows: List[ComposedFlowAnalysis],
    include_full_analyses: bool = False,
) -> List[Dict[str, Any]]:
    """Prepare tier2 inputs for all flows.

    Args:
        composed_flows: List of ComposedFlowAnalysis
        include_full_analyses: Whether to include full method analysis details

    Returns:
        List of tier2 input dicts
    """
    return [
        prepare_tier2_input(composed, include_full_analyses)
        for composed in composed_flows
    ]

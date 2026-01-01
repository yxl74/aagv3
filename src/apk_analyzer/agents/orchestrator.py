from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from functools import lru_cache
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional

import re

from apk_analyzer.agents.recon import ReconAgent
from apk_analyzer.agents.recon_tools import ReconToolRunner
from apk_analyzer.agents.package_scope import PackageScopeAgent
from apk_analyzer.agents.report import ReportAgent
from apk_analyzer.agents.tier2_intent import Tier2IntentAgent
from apk_analyzer.agents.tier2a_reasoning import Tier2AReasoningAgent
from apk_analyzer.agents.tier2b_commands import Tier2BCommandsAgent
from apk_analyzer.agents.verifier import VerifierAgent
from apk_analyzer.agents.method_tier1 import (
    MethodAnalysis,
    MethodAnalysisCache,
    MethodTier1Agent,
    analyze_methods_with_sources,
    batch_extract_sources,
    collect_unique_methods,
)
from apk_analyzer.agents.flow_composer import (
    ComposedFlowAnalysis,
    compose_flow_analysis,
    prepare_tier2_input,
)
from apk_analyzer.analyzers.context_bundle_builder import ContextBundleBuilder, build_static_context
from apk_analyzer.analyzers.dex_invocation_indexer import ApiCallSite, DexInvocationIndexer, SuspiciousApiIndex
from apk_analyzer.analyzers.jadx_extractors import extract_method_source, run_jadx
from apk_analyzer.analyzers.intent_contracts import extract_intent_contracts
from apk_analyzer.analyzers.code_artifacts import extract_file_artifacts, extract_log_hints
from apk_analyzer.analyzers.execution_guidance_validator import validate_execution_guidance
from apk_analyzer.analyzers.semantic_annotator import annotate_sliced_cfg
from apk_analyzer.analyzers.tier2_prevalidator import prevalidate_for_tier2, format_validation_summary
from apk_analyzer.analyzers.value_hints_builder import build_value_hints_for_seed
from apk_analyzer.analyzers.package_inventory import build_package_inventory, package_inventory_preview
from apk_analyzer.models.tier2_phases import merge_phase_outputs, ExecutionStep, Phase2AOutput, Phase2BOutput
from apk_analyzer.analyzers.local_query import search_source_code
from apk_analyzer.analyzers.mitre_mapper import load_rules, load_technique_index, map_evidence
from apk_analyzer.analyzers.sources_sinks_subset import generate_subset
from apk_analyzer.clients.knox_client import KnoxClient
from apk_analyzer.knowledge.api_catalog import ApiCatalog
from apk_analyzer.observability.logger import EventLogger
from apk_analyzer.phase0.sensitive_api_matcher import (
    _COMMON_LIBRARY_PREFIXES,
    _LIBRARY_PREFIXES,
    build_sensitive_api_hits,
    load_callgraph,
)
from apk_analyzer.phase0.threading_edge_validator import validate_threading_edges
from apk_analyzer.phase0.cooccurrence_scorer import compute_threat_score, COOCCURRENCE_PATTERNS
from apk_analyzer.phase0.pattern_summary import build_cooccurrence_pattern_summary
from apk_analyzer.telemetry import llm_context, set_run_context, span
from apk_analyzer.telemetry.llm_instrumentation import InstrumentedLLMClient
from apk_analyzer.tools.flowdroid_tools import run_targeted_taint_analysis
from apk_analyzer.tools.soot_tools import run_soot_extractor
from apk_analyzer.tools.static_tools import run_static_extractors
from apk_analyzer.utils.artifact_store import ArtifactStore
from apk_analyzer.utils.json_schema import validate_json
from apk_analyzer.utils.signature_normalize import normalize_signature


def _safe_load_sensitive_catalog(
    path: str | Path,
    event_logger: Optional[EventLogger] = None,
) -> ApiCatalog:
    try:
        return ApiCatalog.load(path)
    except Exception as exc:
        if event_logger:
            event_logger.log(
                "catalog.load_failed",
                catalog_path=str(path),
                error=str(exc),
            )
        return ApiCatalog.empty()


class Orchestrator:
    def __init__(self, settings: Dict[str, Any], llm_client: Optional[Any] = None) -> None:
        self.settings = settings
        self.llm_client = llm_client
        self.prompt_dir = Path("src/apk_analyzer/prompts")

    def run(self, apk_path: str | None, knox_apk_id: str | None, mode: str = "combined") -> Dict[str, Any]:
        if mode == "combined":
            if not apk_path or not knox_apk_id:
                raise ValueError("Both apk_path and knox_apk_id are required for analysis.")
        elif mode == "apk-only":
            if not apk_path:
                raise ValueError("apk_path is required for apk-only analysis.")
        else:
            raise ValueError(f"Unknown analysis mode: {mode}")
        analysis_id = ArtifactStore.compute_analysis_id(apk_path, knox_apk_id)
        run_id = set_run_context(analysis_id, mode=mode)
        artifact_store = ArtifactStore(
            self.settings["analysis"]["artifacts_dir"],
            analysis_id,
            run_id=run_id,
        )
        artifact_store.ensure_dir("input")
        artifact_store.ensure_dir("static")
        artifact_store.ensure_dir("seeds")
        artifact_store.ensure_dir("graphs")
        artifact_store.ensure_dir("llm")
        artifact_store.ensure_dir("llm/tier1a")
        artifact_store.ensure_dir("llm/tier1b")
        artifact_store.ensure_dir("llm_inputs")
        artifact_store.ensure_dir("llm_outputs")
        artifact_store.ensure_dir("taint")
        artifact_store.ensure_dir("report")
        obs_conf = self.settings.get("observability", {}) if isinstance(self.settings, dict) else {}
        event_logger = EventLogger(
            artifact_store,
            run_id=run_id,
            enabled=obs_conf.get("enabled", True),
        )
        event_logger.log("run.start", mode=mode, apk_path=str(apk_path) if apk_path else None, knox_apk_id=knox_apk_id)
        sensitive_catalog = _safe_load_sensitive_catalog(
            "config/android_sensitive_api_catalog.json",
            event_logger=event_logger,
        )

        knox_client = None
        full_knox = None
        jadx_root = None
        local_search_fn = None

        if mode == "combined" and knox_apk_id:
            knox_conf = self.settings.get("knox", {})
            knox_client = KnoxClient(
                base_url=knox_conf.get("base_url", ""),
                headers=knox_conf.get("headers", {}),
                artifact_store=artifact_store,
                event_logger=event_logger,
            )
            full_knox = knox_client.get_full_analysis(knox_apk_id)

        jadx_enabled = bool(self.settings.get("analysis", {}).get("jadx_enabled", True))
        use_jadx = bool(apk_path) and jadx_enabled
        temp_ctx = TemporaryDirectory(prefix="jadx-") if use_jadx else _noop_context()
        success = False
        try:
            with temp_ctx as tmpdir:
                static_outputs: Dict[str, Any] = {}
                manifest = {}
                event_logger.stage_start("static_preprocess")
                with span("stage.static_preprocess", stage="static_preprocess"):
                    if apk_path:
                        static_outputs = run_static_extractors(apk_path, artifact_store)
                        manifest = static_outputs.get("manifest", {})
                event_logger.stage_end(
                    "static_preprocess",
                    manifest_permission_count=len(manifest.get("permissions") or []),
                    string_count=static_outputs.get("strings", {}).get("string_count", 0),
                    cert_count=len(static_outputs.get("cert", {}).get("cert_files", []) or []),
                )

                if use_jadx:
                    event_logger.stage_start("jadx")
                    with span("tool.jadx", tool_name="jadx"):
                        jadx_path = self.settings.get("analysis", {}).get("jadx_path", "jadx")
                        jadx_timeout = self.settings.get("analysis", {}).get("jadx_timeout_sec", 600)
                        if tmpdir:
                            jadx_root = run_jadx(apk_path, Path(tmpdir), jadx_path=jadx_path, timeout_sec=jadx_timeout)
                        if jadx_root:
                            local_search_fn = lambda query, limit=10: search_source_code(jadx_root, query, limit)
                    event_logger.stage_end(
                        "jadx",
                        status="ok" if jadx_root else "skipped",
                        output_dir=str(jadx_root) if jadx_root else None,
                    )
                    event_logger.log(
                        "tool.jadx",
                        tool="jadx",
                        status="ok" if jadx_root else "skipped",
                        output_dir=str(jadx_root) if jadx_root else None,
                    )

                if full_knox and full_knox.get("manifest_data"):
                    manifest = full_knox.get("manifest_data", manifest)
                    artifact_store.write_json("static/manifest.json", manifest)
                if full_knox:
                    artifact_store.write_json("static/knox_full.json", full_knox)
                    artifact_store.write_json(
                        "static/permissions.json",
                        {"permissions": knox_client.get_permissions(knox_apk_id, full_knox)},
                    )
                    artifact_store.write_json("static/components.json", knox_client.get_components(knox_apk_id, full_knox))
                    artifact_store.write_json("static/threat_indicators.json", knox_client.get_threat_indicators(knox_apk_id, full_knox))

                strings = static_outputs.get("strings", {})
                component_intents = static_outputs.get("component_intents", {})
                intent_contracts: Dict[str, Any] = {}
                file_artifacts: Dict[str, Any] = {}
                log_hints: Dict[str, Any] = {}
                if jadx_root:
                    intent_contracts = extract_intent_contracts(jadx_root, manifest)
                    artifact_store.write_json("static/intent_contracts.json", intent_contracts)
                    file_artifacts = extract_file_artifacts(jadx_root)
                    log_hints = extract_log_hints(jadx_root)
                    artifact_store.write_json("static/file_artifacts.json", file_artifacts)
                    artifact_store.write_json("static/log_hints.json", log_hints)
                static_context = build_static_context(manifest, strings)
                if intent_contracts:
                    static_context["intent_contracts"] = intent_contracts
                if file_artifacts:
                    static_context["file_artifacts"] = file_artifacts
                if log_hints:
                    static_context["log_hints"] = log_hints
                if component_intents:
                    static_context["component_intents"] = component_intents

                callgraph_path = None
                callgraph_data = None
                entrypoint_paths_ref = None
                class_hierarchy = None
                entrypoints_override = None
                android_platforms = self.settings["analysis"].get("android_platforms_dir")
                soot_jar = self.settings["analysis"].get("soot_extractor_jar_path") or "java/soot-extractor/build/libs/soot-extractor.jar"
                if apk_path and android_platforms:
                    event_logger.stage_start("graphs")
                    with span("stage.graphs", stage="graphs"):
                        out_dir = artifact_store.path("graphs")
                        target_sdk = _parse_target_sdk(manifest)
                        flowdroid_callbacks_enabled = bool(
                            self.settings["analysis"].get("flowdroid_callbacks_enabled", True)
                        )
                        flowdroid_callbacks_timeout = self.settings["analysis"].get("flowdroid_callbacks_timeout_sec")
                        flowdroid_callbacks_max = self.settings["analysis"].get(
                            "flowdroid_callbacks_max_per_component"
                        )
                        flowdroid_callbacks_mode = self.settings["analysis"].get("flowdroid_callbacks_mode")
                        run_soot_extractor(
                            apk_path,
                            android_platforms,
                            out_dir,
                            soot_jar,
                            cg_algo=self.settings["analysis"].get("callgraph_algo", "SPARK"),
                            k_hop=self.settings["analysis"].get("k_hop", 2),
                            target_sdk=target_sdk,
                            flowdroid_callbacks_enabled=flowdroid_callbacks_enabled,
                            flowdroid_callbacks_timeout_sec=flowdroid_callbacks_timeout,
                            flowdroid_callbacks_max_per_component=flowdroid_callbacks_max,
                            flowdroid_callbacks_mode=flowdroid_callbacks_mode,
                        )
                        callgraph_path = artifact_store.path("graphs/callgraph.json")
                        class_hierarchy_path = artifact_store.path("graphs/class_hierarchy.json")
                        if class_hierarchy_path.exists():
                            class_hierarchy = load_callgraph(class_hierarchy_path)
                        entrypoints_path = artifact_store.path("graphs/entrypoints.json")
                        if entrypoints_path.exists():
                            entrypoints_payload = load_callgraph(entrypoints_path)
                            if isinstance(entrypoints_payload, dict):
                                entrypoints_override = entrypoints_payload.get("entrypoints")
                        callgraph_stats: Dict[str, Any] = {}
                        if callgraph_path.exists():
                            callgraph_data = load_callgraph(callgraph_path)
                            validate_json(callgraph_data, "config/schemas/CallGraph.schema.json")
                            metadata = callgraph_data.get("metadata", {}) if isinstance(callgraph_data, dict) else {}
                            callgraph_stats = {
                                "node_count": len(callgraph_data.get("nodes", [])),
                                "edge_count": len(callgraph_data.get("edges", [])),
                                "android_jar_api": metadata.get("android_jar_api"),
                                "android_jar_reason": metadata.get("android_jar_reason"),
                            }
                            if class_hierarchy and isinstance(callgraph_data, dict):
                                try:
                                    threading_validation = validate_threading_edges(callgraph_data, class_hierarchy)
                                    artifact_store.write_json(
                                        "graphs/threading_edge_validation.json",
                                        threading_validation,
                                    )
                                    event_logger.log(
                                        "graphs.threading_edge_validation",
                                        start_callsites=threading_validation.get("start_callsites"),
                                        missing_run_edges=threading_validation.get("missing_run_edges"),
                                        threading_edge_count=threading_validation.get("threading_edge_count"),
                                        ref=artifact_store.relpath("graphs/threading_edge_validation.json"),
                                    )
                                except Exception as exc:
                                    event_logger.log(
                                        "graphs.threading_edge_validation_failed",
                                        error=str(exc),
                                    )
                    cfg_dir = artifact_store.path("graphs/cfg")
                    cfg_count = len(list(cfg_dir.glob("*.json"))) if cfg_dir.exists() else 0
                    event_logger.stage_end(
                        "graphs",
                        **callgraph_stats,
                        cfg_count=cfg_count,
                        callgraph_ref=artifact_store.relpath("graphs/callgraph.json") if callgraph_path else None,
                        class_hierarchy_ref=artifact_store.relpath("graphs/class_hierarchy.json") if class_hierarchy else None,
                        entrypoints_ref=artifact_store.relpath("graphs/entrypoints.json") if entrypoints_override else None,
                    )
                    event_logger.log(
                        "tool.soot",
                        tool="soot",
                        status="ok",
                        **callgraph_stats,
                        cfg_count=cfg_count,
                        callgraph_ref=artifact_store.relpath("graphs/callgraph.json") if callgraph_path else None,
                        class_hierarchy_ref=artifact_store.relpath("graphs/class_hierarchy.json") if class_hierarchy else None,
                        entrypoints_ref=artifact_store.relpath("graphs/entrypoints.json") if entrypoints_override else None,
                    )

                sensitive_hits = None
                if callgraph_data:
                    event_logger.stage_start("sensitive_api")
                    with span("stage.sensitive_api", stage="sensitive_api"):
                        if sensitive_catalog.categories:
                            allow_third_party = bool(self.settings["analysis"].get("allow_third_party_callers", True))
                            filter_common_libs = bool(self.settings["analysis"].get("filter_common_libraries", True))
                            sensitive_hits = build_sensitive_api_hits(
                                callgraph_data,
                                sensitive_catalog,
                                manifest,
                                apk_path=apk_path,
                                class_hierarchy=class_hierarchy,
                                entrypoints_override=entrypoints_override if isinstance(entrypoints_override, list) else None,
                                allow_third_party_callers=allow_third_party,
                                filter_common_libraries=filter_common_libs,
                            )
                            reflection_high_signal_only = bool(
                                self.settings["analysis"].get("reflection_high_signal_only", True)
                            )
                            if reflection_high_signal_only and sensitive_hits.get("hits"):
                                from apk_analyzer.phase0.reflection_analyzer import (
                                    analyze_reflection_hits,
                                    filter_reflection_hits,
                                )

                                event_logger.stage_start("reflection_analysis")
                                with span("stage.reflection_analysis", stage="reflection_analysis"):
                                    reflection_analysis = analyze_reflection_hits(
                                        sensitive_hits=sensitive_hits,
                                        catalog=sensitive_catalog,
                                        jadx_root=jadx_root if use_jadx else None,
                                    )
                                    sensitive_hits, suppressed = filter_reflection_hits(
                                        sensitive_hits=sensitive_hits,
                                        analysis=reflection_analysis,
                                        catalog=sensitive_catalog,
                                        filter_low_signal=True,
                                    )
                                    if suppressed:
                                        artifact_store.write_json("seeds/reflection_suppressed.json", {
                                            "count": len(suppressed),
                                            "hits": suppressed[:50],
                                        })
                                event_logger.stage_end(
                                    "reflection_analysis",
                                    kept=sensitive_hits.get("summary", {}).get("reflection_kept", 0),
                                    suppressed=len(suppressed) if reflection_high_signal_only else 0,
                                )
                            artifact_store.write_json("seeds/sensitive_api_hits.json", sensitive_hits)
                            artifact_store.write_json(
                                "graphs/callgraph_summary.json",
                                sensitive_hits.get("callgraph_summary", {}),
                            )
                        else:
                            event_logger.log(
                                "sensitive_api.skip",
                                reason="catalog_unavailable",
                            )
                    event_logger.stage_end(
                        "sensitive_api",
                        total_hits=sensitive_hits.get("summary", {}).get("total_hits", 0) if sensitive_hits else 0,
                        ref=artifact_store.relpath("seeds/sensitive_api_hits.json") if sensitive_hits else None,
                    )

                hit_groups_payload = None
                hit_groups_by_id: Dict[str, Dict[str, Any]] = {}
                hits_by_id: Dict[str, Dict[str, Any]] = {}
                if sensitive_hits and sensitive_hits.get("hits"):
                    hits_by_id = {
                        hit.get("hit_id"): hit
                        for hit in sensitive_hits.get("hits", [])
                        if hit.get("hit_id")
                    }
                    hit_groups_payload = _group_sensitive_hits(
                        sensitive_hits.get("hits", []),
                        artifact_store=artifact_store,
                        catalog=sensitive_catalog,
                    )
                    artifact_store.write_json("seeds/sensitive_api_groups.json", hit_groups_payload)
                    hit_groups_by_id = {
                        group.get("group_id"): group
                        for group in hit_groups_payload.get("groups", [])
                        if group.get("group_id")
                    }

                    # Build code blocks (class-level aggregation with scoring)
                    code_blocks, library_groups = build_code_blocks(
                        hit_groups_payload.get("groups", []),
                        manifest,
                        catalog=sensitive_catalog,
                    )
                    artifact_store.write_json(
                        "seeds/code_blocks.json",
                        {"block_count": len(code_blocks), "blocks": code_blocks},
                    )
                    artifact_store.write_json(
                        "seeds/library_groups.json",
                        {"group_count": len(library_groups), "groups": library_groups},
                    )
                else:
                    code_blocks = []
                    library_groups = []

                # Package inventory (debug + optional LLM package scope selection)
                package_inventory = build_package_inventory(
                    callgraph_data if isinstance(callgraph_data, dict) else None,
                    sensitive_hits.get("hits", []) if isinstance(sensitive_hits, dict) else [],
                    hit_groups_payload.get("groups", []) if isinstance(hit_groups_payload, dict) else [],
                    manifest,
                )
                artifact_store.write_json("graphs/package_inventory.json", package_inventory)

                llm_conf = self.settings.get("llm", {}) or {}
                analysis_conf = self.settings.get("analysis", {}) or {}
                llm_client = self.llm_client
                if llm_client:
                    llm_client = InstrumentedLLMClient(llm_client, artifact_store, event_logger=event_logger)

                    # Optional: ask a high-capacity LLM to choose in-scope package prefixes.
                    if llm_client and analysis_conf.get("package_scope_llm_enabled") and package_inventory:
                        preview_max = int(analysis_conf.get("package_scope_llm_max_packages", 80) or 80)
                        preview_min_hits = int(analysis_conf.get("package_scope_llm_min_hit_count", 1) or 1)
                        inventory_preview = package_inventory_preview(
                            package_inventory,
                            max_packages=preview_max,
                            min_hit_count=preview_min_hits,
                        )
                        scope_payload = {
                            "manifest_package": package_inventory.get("manifest_package", ""),
                            "component_packages": package_inventory.get("component_packages", []),
                            "dominant_component_prefixes": package_inventory.get("dominant_component_prefixes", []),
                            "inventory_preview": inventory_preview,
                        }
                        scope_agent = PackageScopeAgent(
                            self.prompt_dir / "package_scope.md",
                            llm_client,
                            model=(
                                llm_conf.get("model_package_scope")
                                or llm_conf.get("model_recon")
                                or llm_conf.get("model_orchestrator")
                            ),
                            event_logger=event_logger,
                        )
                        with span("stage.package_scope", stage="package_scope"):
                            with llm_context("package_scope"):
                                package_scope = scope_agent.run(scope_payload)
                        artifact_store.write_json("llm/package_scope.json", package_scope)

                        analyze_prefixes = package_scope.get("analyze_prefixes") if isinstance(package_scope, dict) else []
                        ignore_prefixes = package_scope.get("ignore_prefixes") if isinstance(package_scope, dict) else []
                        if analyze_prefixes or ignore_prefixes:
                            # Rebuild code blocks using LLM-selected package prefixes to reduce false negatives.
                            code_blocks, library_groups = build_code_blocks(
                                hit_groups_payload.get("groups", []) if isinstance(hit_groups_payload, dict) else [],
                                manifest,
                                catalog=sensitive_catalog,
                                extra_app_prefixes=analyze_prefixes if isinstance(analyze_prefixes, list) else None,
                                ignore_prefixes=ignore_prefixes if isinstance(ignore_prefixes, list) else None,
                            )
                            artifact_store.write_json("seeds/code_blocks.json", {
                                "block_count": len(code_blocks),
                                "blocks": code_blocks,
                            })
                            artifact_store.write_json("seeds/library_groups.json", {
                                "group_count": len(library_groups),
                                "groups": library_groups,
                            })

                # Co-occurrence pattern summary across multiple scopes (group/block/app/package).
                # This helps debug "low pattern count" situations where an attack chain is
                # split across multiple classes (e.g., Accessibility in one class, C2 in another).
                pattern_summary = build_cooccurrence_pattern_summary(
                    hit_groups_payload.get("groups", []) if isinstance(hit_groups_payload, dict) else [],
                    code_blocks,
                    callgraph=callgraph_data if isinstance(callgraph_data, dict) else None,
                    manifest=manifest,
                )
                artifact_store.write_json("seeds/cooccurrence_patterns.json", pattern_summary)

                recon_result = {
                    "mode": "final",
                    "risk_score": 0.1,
                    "threat_level": "LOW",
                    "cases": [],
                    "investigation_plan": ["Recon skipped; no sensitive API hits."],
                }
                cases: List[Dict[str, Any]] = []
                had_llm_cases = False
                if sensitive_hits and sensitive_hits.get("hits"):
                    recon_payload = _build_recon_payload(
                        manifest=manifest,
                        sensitive_hits=sensitive_hits,
                        hit_groups=hit_groups_payload,
                        code_blocks=code_blocks,
                        threat_indicators=(full_knox or {}).get("threat_indicators", {}),
                    )
                    tool_runner = ReconToolRunner(
                        sensitive_hits,
                        hit_groups=hit_groups_payload,
                        code_blocks=code_blocks,
                    )
                    max_rounds = llm_conf.get("recon_max_tool_rounds", 2)
                    recon_agent = ReconAgent(
                        self.prompt_dir / "recon.md",
                        llm_client,
                        model=llm_conf.get("model_recon"),
                        tool_runner=tool_runner,
                        max_tool_rounds=max_rounds,
                        event_logger=event_logger,
                    )
                    event_logger.stage_start("recon")
                    with span("stage.recon", stage="recon"):
                        with llm_context("recon"):
                            recon_result = recon_agent.run(recon_payload)
                        recon_meta = recon_result.get("_meta") if isinstance(recon_result, dict) else {}
                        if not isinstance(recon_meta, dict):
                            recon_meta = {}
                        recon_result["_meta"] = recon_meta
                        tool_history = recon_meta.get("tool_history", []) or []
                        if event_logger:
                            list_hits_called = False
                            get_hit_called = False
                            list_groups_called = False
                            get_group_called = False
                            total_calls = 0
                            for round_data in tool_history:
                                requests = round_data.get("requests", [])
                                total_calls += len(requests)
                                for req in requests:
                                    tool_name = req.get("tool", "")
                                    if tool_name == "list_hits":
                                        list_hits_called = True
                                    elif tool_name == "get_hit":
                                        get_hit_called = True
                                    elif tool_name == "list_groups":
                                        list_groups_called = True
                                    elif tool_name == "get_group":
                                        get_group_called = True
                            event_logger.log(
                                "recon.tool_usage",
                                llm_step="recon",
                                total_tool_rounds=len(tool_history),
                                list_hits_called=list_hits_called,
                                get_hit_called=get_hit_called,
                                list_groups_called=list_groups_called,
                                get_group_called=get_group_called,
                                tool_call_count=total_calls,
                            )
                        all_cases = recon_result.get("cases", []) or []
                        had_llm_cases = bool(all_cases)
                        if all_cases:
                            high_confidence_pruned = []
                            low_confidence_pruned = []
                            active_cases = []
                            for case in all_cases:
                                if case.get("should_prune", False):
                                    if case.get("pruning_confidence", 0.0) >= 0.8:
                                        high_confidence_pruned.append(case)
                                    else:
                                        low_confidence_pruned.append(case)
                                else:
                                    active_cases.append(case)
                            cases_for_tier1 = [
                                case for case in all_cases
                                if not (case.get("should_prune", False)
                                        and case.get("pruning_confidence", 0.0) >= 0.8)
                            ]
                            recon_result["cases_pruned"] = high_confidence_pruned
                            recon_meta["pruned_count"] = len(high_confidence_pruned)
                            recon_meta["low_confidence_pruned_count"] = len(low_confidence_pruned)
                            if event_logger:
                                event_logger.log(
                                    "recon.pruning_stats",
                                    llm_step="recon",
                                    total_cases=len(all_cases),
                                    high_confidence_pruned=len(high_confidence_pruned),
                                    low_confidence_pruned=len(low_confidence_pruned),
                                    active_cases=len(active_cases),
                                    tier1_cases=len(cases_for_tier1),
                                    sample_reasons=[c.get("pruning_reasoning", "") for c in high_confidence_pruned[:5]],
                                )
                            recon_result["cases"] = cases_for_tier1
                            cases = cases_for_tier1

                            # Track groups from high-confidence pruned cases
                            # to prevent them from being re-added by fallback
                            pruned_group_ids = _collect_case_group_ids(
                                high_confidence_pruned, hit_groups_by_id
                            )
                        else:
                            cases = []
                            pruned_group_ids: set[str] = set()
                        if hit_groups_by_id:
                            covered_groups = _collect_case_group_ids(cases, hit_groups_by_id)
                            # Exclude both covered groups AND groups from pruned cases
                            missing_groups = set(hit_groups_by_id.keys()) - covered_groups - pruned_group_ids
                            if missing_groups:
                                fallback_cases = _fallback_cases_from_groups(
                                    missing_groups,
                                    hit_groups_by_id,
                                    hits_by_id,
                                )
                                cases.extend(fallback_cases)
                                recon_result["cases"] = cases
                            if event_logger:
                                event_logger.log(
                                    "recon.group_coverage",
                                    total_groups=len(hit_groups_by_id),
                                    covered_groups=len(covered_groups),
                                    pruned_groups=len(pruned_group_ids),
                                    missing_groups=len(missing_groups),
                                    sample_missing_groups=list(missing_groups)[:5],
                                )
                        artifact_store.write_json("llm/recon.json", recon_result)
                    recon_meta = recon_result.get("_meta") if isinstance(recon_result, dict) else {}
                    case_count = len(cases)
                    event_logger.stage_end(
                        "recon",
                        threat_level=recon_result.get("threat_level"),
                        case_count=case_count,
                        llm_valid=(recon_meta or {}).get("llm_valid"),
                        fallback_reason=(recon_meta or {}).get("fallback_reason"),
                        ref=artifact_store.relpath("llm/recon.json"),
                    )
                    if not cases and not had_llm_cases:
                        if hit_groups_by_id:
                            cases = _fallback_cases_from_groups(
                                set(hit_groups_by_id.keys()),
                                hit_groups_by_id,
                                hits_by_id,
                            )
                        else:
                            cases = _fallback_cases_from_hits(
                                sensitive_hits,
                                max_cases=self.settings["analysis"].get("max_seed_count", 20),
                            )
                        recon_result["cases"] = cases
                        artifact_store.write_json("llm/recon.json", recon_result)
                else:
                    artifact_store.write_json("llm/recon.json", recon_result)

                event_logger.stage_start("seeding")
                with span("stage.seeding", stage="seeding"):
                    if sensitive_hits and (cases or had_llm_cases):
                        callsites = _callsites_from_cases(cases, hits_by_id, hit_groups_by_id)
                        # Deduplicate callsites by caller method within same case
                        # This prevents redundant Tier1 analysis of multiple APIs in same method
                        original_count = len(callsites)
                        callsites = _deduplicate_callsites_by_caller(callsites)
                        dedup_count = len(callsites)
                        if dedup_count < original_count:
                            event_logger.log(
                                "seeding.deduplication",
                                original_count=original_count,
                                deduplicated_count=dedup_count,
                                merged_count=original_count - dedup_count,
                            )
                        suspicious_index = SuspiciousApiIndex(
                            apk_id=artifact_store.analysis_id,
                            catalog_version=sensitive_hits.get("catalog_version", "unknown"),
                            callsites=callsites,
                        )
                        _write_suspicious_index(artifact_store, suspicious_index)
                    else:
                        catalog_path = Path("config/suspicious_api_catalog.json")
                        indexer = DexInvocationIndexer(catalog_path)
                        suspicious_index = indexer.build_index(
                            apk_id=artifact_store.analysis_id,
                            apk_path=apk_path,
                            knox_client=knox_client,
                            local_search_fn=local_search_fn,
                            artifact_store=artifact_store,
                        )
                confidence_counts: Dict[str, int] = {}
                category_counts: Dict[str, int] = {}
                for site in suspicious_index.callsites:
                    confidence_key = f"{site.confidence:.1f}"
                    confidence_counts[confidence_key] = confidence_counts.get(confidence_key, 0) + 1
                    category_counts[site.category] = category_counts.get(site.category, 0) + 1
                event_logger.stage_end(
                    "seeding",
                    callsite_count=len(suspicious_index.callsites),
                    category_counts=category_counts,
                    confidence_counts=confidence_counts,
                    ref=artifact_store.relpath("seeds/suspicious_api_index.json"),
                )
                validate_json(
                    artifact_store.read_json("seeds/suspicious_api_index.json"),
                    "config/schemas/SuspiciousApiIndex.schema.json",
                )

                context_builder = ContextBundleBuilder(artifact_store)
                event_logger.stage_start("context_bundles")
                with span("stage.context_bundles", stage="context_bundles"):
                    bundles = context_builder.build_for_index(
                        suspicious_index,
                        static_context=static_context,
                        callgraph_path=callgraph_path,
                        k_hop=self.settings["analysis"].get("k_hop", 2),
                    )
                bundles = _order_bundles_by_cases(bundles, cases, hit_groups_by_id)
                slice_sizes = [
                    len(bundle.get("sliced_cfg", {}).get("units", [])) for bundle in bundles
                ]
                entrypoint_paths = [
                    bundle.get("control_flow_path")
                    for bundle in bundles
                    if bundle.get("control_flow_path", {}).get("path_methods")
                ]
                if entrypoint_paths:
                    artifact_store.write_json("graphs/entrypoint_paths.json", entrypoint_paths)
                    entrypoint_paths_ref = artifact_store.relpath("graphs/entrypoint_paths.json")
                sample_path_refs = [
                    artifact_store.relpath(ref)
                    for ref in (bundle.get("control_flow_path_ref") for bundle in bundles[:5])
                    if ref
                ]
                event_logger.stage_end(
                    "context_bundles",
                    bundle_count=len(bundles),
                    avg_slice_units=(sum(slice_sizes) / len(slice_sizes)) if slice_sizes else 0,
                    sample_slice_refs=[
                        artifact_store.relpath(f"graphs/slices/{bundle['seed_id']}.json")
                        for bundle in bundles[:5]
                    ],
                    sample_path_refs=sample_path_refs,
                    entrypoint_paths_ref=entrypoint_paths_ref,
                )

                # JADX is required for method-centric pipeline
                if not jadx_root:
                    raise ValueError(
                        "JADX is required for analysis. "
                        "Ensure jadx_enabled: true in config and JADX decompilation succeeded."
                    )

                verifier_agent = VerifierAgent(self.prompt_dir / "verifier.md", llm_client)
                tier2_agent = Tier2IntentAgent(
                    self.prompt_dir / "tier2_intent.md",
                    llm_client,
                    model=llm_conf.get("model_tier2"),
                    event_logger=event_logger,
                )

                # Two-phase Tier2 agents (used when tier2_split_enabled=true)
                tier2_split_enabled = llm_conf.get("tier2_split_enabled", False)
                tier2a_agent = None
                tier2b_agent = None
                if tier2_split_enabled:
                    tier2a_agent = Tier2AReasoningAgent(
                        self.prompt_dir / "tier2a_reasoning.md",
                        llm_client,
                        model=llm_conf.get("model_tier2"),
                        event_logger=event_logger,
                    )
                    tier2b_agent = Tier2BCommandsAgent(
                        self.prompt_dir / "tier2b_commands.md",
                        llm_client,
                        model=llm_conf.get("model_tier2"),
                        event_logger=event_logger,
                    )
                report_agent = ReportAgent(
                    self.prompt_dir / "tier3_final.md",
                    llm_client,
                    model=llm_conf.get("model_report"),
                    event_logger=event_logger,
                )

                case_lookup = _case_lookup(cases, hit_groups_by_id)
                flow_summaries: Dict[str, Dict[str, Any]] = {}
                bundle_map: Dict[str, Dict[str, Any]] = {}
                verified_ids: List[str] = []
                evidence_support_index: Dict[str, Any] = {}
                verified_count = 0
                processed_count = 0

                # Generate methods_to_investigate.json early for UI progress display
                # This runs before Tier 1 so the method count is visible immediately
                max_seed_count = self.settings["analysis"].get("max_seed_count", 20)
                generate_methods_to_investigate_early(
                    bundles=bundles[:max_seed_count],
                    artifact_store=artifact_store,
                )

                # Method-centric Tier1 pipeline (the only Tier1 path)
                event_logger.stage_start("method_tier1")
                with span("stage.method_tier1", stage="method_tier1"):
                    method_cache = run_method_tier1_pipeline(
                        bundles=bundles[: self.settings["analysis"].get("max_seed_count", 20)],
                        jadx_root=jadx_root,
                        cfg_dir=artifact_store.path("graphs/cfg"),
                        llm_client=llm_client,
                        artifact_store=artifact_store,
                        event_logger=event_logger,
                        model=llm_conf.get("model_tier1"),
                        prompt_dir=self.prompt_dir,
                    )
                event_logger.stage_end(
                    "method_tier1",
                    methods_analyzed=len(method_cache),
                    methods_with_jadx=sum(1 for m in method_cache.values() if m.jadx_available),
                    methods_with_jimple=sum(1 for m in method_cache.values() if m.jimple_available),
                )

                for seed_index, bundle in enumerate(bundles[: self.settings["analysis"].get("max_seed_count", 20)]):
                    seed_id = bundle["seed_id"]
                    case_info = case_lookup.get(seed_id, {})

                    if not case_info and bundle.get("case_context"):
                        cc = bundle["case_context"]
                        case_info = {
                            "case_id": cc.get("case_id"),
                            "priority": cc.get("priority"),
                            "category_id": bundle.get("api_category"),
                        }

                    processed_count += 1
                    bundle_map[seed_id] = bundle
                    with span("llm.seed", stage="seed_processing", seed_id=seed_id, api_category=bundle.get("api_category")):
                        # Static composition from pre-computed method analyses (method-centric pipeline)
                        composed = compose_flow_analysis(bundle, method_cache)
                        tier1 = tier1_from_composed(composed, bundle)
                        artifact_store.write_json(f"llm/tier1/{seed_id}.json", tier1)

                        # Save composed analysis for debugging
                        artifact_store.write_json(f"llm/tier1/{seed_id}_composed.json", composed.to_dict())

                        # No verifier needed for static composition (methods already verified)
                        verifier = {"status": "COMPOSED", "notes": "Static composition from method analyses"}
                        artifact_store.write_json(f"llm/verifier/{seed_id}.json", verifier)

                    for idx, fact in enumerate(tier1.get("facts", [])):
                        ev_id = f"ev-{bundle['seed_id']}-{idx}"
                        evidence_support_index[ev_id] = {
                            "support_unit_ids": fact.get("support_unit_ids", []),
                            "artifact": artifact_store.relpath(f"graphs/slices/{bundle['seed_id']}.json"),
                        }

                    flow_summaries[seed_id] = {
                        "seed_id": seed_id,
                        "case_id": case_info.get("case_id"),
                        "case_priority": case_info.get("priority"),
                        "category_id": case_info.get("category_id") or bundle.get("api_category"),
                        "package_name": bundle.get("static_context", {}).get("package_name"),
                        "tier1": tier1,
                        "tier2": None,
                    }

                    phase_status = (tier1.get("phase_status") or "").lower()
                    # Accept both VERIFIED (legacy) and COMPOSED (method-centric pipeline)
                    if verifier.get("status") in ("VERIFIED", "COMPOSED") and (not phase_status or phase_status == "ok"):
                        verified_count += 1
                        verified_ids.append(seed_id)

                event_logger.log(
                    "seed.summary",
                    processed_count=processed_count,
                    verified_count=verified_count,
                )

                flowdroid_summary = None
                # FlowDroid disabled - using Soot reachability instead
                # if verified_ids and apk_path:
                #     categories_present = {bundle_map[sid]["api_category"] for sid in verified_ids if sid in bundle_map}
                #     sources_sinks_subset = generate_subset(
                #         "config/SourcesAndSinks.txt",
                #         artifact_store.path("taint/sources_sinks_subset.txt"),
                #         categories_present,
                #     )
                #     flowdroid_jar = self.settings["analysis"].get("flowdroid_jar_path")
                #     android_platforms_dir = self.settings["analysis"].get("android_platforms_dir")
                #     if flowdroid_jar and android_platforms_dir:
                #         jar_path = Path(flowdroid_jar)
                #         platforms_path = Path(android_platforms_dir)
                #     else:
                #         jar_path = None
                #         platforms_path = None
                #     if jar_path and platforms_path and jar_path.exists() and platforms_path.exists():
                #         with span("tool.flowdroid", tool_name="flowdroid"):
                #             flowdroid_summary = run_targeted_taint_analysis(
                #                 apk_path,
                #                 sources_sinks_subset,
                #                 android_platforms_dir,
                #                 flowdroid_jar,
                #                 artifact_store.path("taint"),
                #                 timeout_sec=self.settings["analysis"].get("flowdroid_timeout_sec", 900),
                #             )
                #             artifact_store.write_json("taint/flowdroid_summary.json", flowdroid_summary)
                #         event_logger.log(
                #             "flowdroid.summary",
                #             tool="flowdroid",
                #             flow_count=flowdroid_summary.get("flow_count") if flowdroid_summary else 0,
                #             ref=artifact_store.relpath("taint/flowdroid_summary.json"),
                #         )

                # Initialize package_name from manifest
                package_name = manifest.get("package_name") or manifest.get("package")

                # Process Tier2 per control flow (each seed = one flow path)
                # Each seed represents a complete control flow from entry point to sink
                for seed_id in verified_ids:
                    bundle = bundle_map.get(seed_id)
                    if not bundle:
                        continue

                    tier1 = flow_summaries.get(seed_id, {}).get("tier1", {})
                    if not tier1:
                        continue

                    # Generate flow ID from the control flow path
                    flow_id = _get_flow_id(bundle)

                    # Get case info for context (preserved for traceability, not grouping)
                    case_info = case_lookup.get(seed_id, {})
                    case_id = case_info.get("case_id") or seed_id

                    # Get static context
                    static_ctx = bundle.get("static_context") or {}
                    pkg_name = static_ctx.get("package_name") or package_name

                    # Check if two-phase Tier2 is enabled
                    if tier2_split_enabled and tier2a_agent and tier2b_agent:
                        # Two-phase flow: Phase 2A (reasoning) + Phase 2B (commands)
                        tier2 = _run_flow_tier2(
                            flow_id=flow_id,
                            seed_id=seed_id,
                            bundle=bundle,
                            tier1=tier1,
                            case_info=case_info,
                            static_ctx=static_ctx,
                            manifest=manifest,
                            tier2a_agent=tier2a_agent,
                            tier2b_agent=tier2b_agent,
                            artifact_store=artifact_store,
                            event_logger=event_logger,
                        )
                    else:
                        # Legacy single-phase Tier2 flow (also updated to per-flow)
                        tier2_input = _build_flow_tier2_input(
                            flow_id=flow_id,
                            seed_id=seed_id,
                            bundle=bundle,
                            tier1=tier1,
                            case_info=case_info,
                            static_ctx=static_ctx,
                            component_intents=component_intents,
                            pkg_name=pkg_name,
                        )

                        with llm_context("tier2", seed_id=seed_id):
                            tier2 = tier2_agent.run(tier2_input)

                        intent_contracts_full = static_ctx.get("intent_contracts") or {}
                        file_artifacts_full = static_ctx.get("file_artifacts") or {}
                        log_hints_full = static_ctx.get("log_hints") or {}
                        if isinstance(tier2, dict) and (intent_contracts_full or file_artifacts_full or log_hints_full):
                            exec_guidance = tier2.get("execution_guidance")
                            if isinstance(exec_guidance, dict):
                                tier2["execution_guidance"] = validate_execution_guidance(
                                    exec_guidance,
                                    intent_contracts_full,
                                    file_artifacts=file_artifacts_full,
                                    log_hints=log_hints_full,
                                    package_name=pkg_name,
                                )

                    # Save Tier2 result using flow_id
                    artifact_store.write_json(f"llm/tier2/{flow_id}.json", tier2)

                    # Assign Tier2 result to this seed (each seed gets its own tier2)
                    flow_summaries[seed_id]["tier2"] = tier2
                    flow_summaries[seed_id]["flow_id"] = flow_id
                    flow_summaries[seed_id]["case_id"] = case_id  # Preserved for traceability

                flow_summary_list = list(flow_summaries.values())

                # Generate tier2_summary.json for frontend Attack Chains display
                generate_tier2_summary_json(flow_summary_list, artifact_store)

                mitre_rules = load_rules("config/mitre/mapping_rules.json")
                technique_index = load_technique_index("config/mitre/technique_index.json")
                mitre_candidates = map_evidence(
                    [fact for seed in flow_summary_list for fact in seed.get("tier1", {}).get("facts", [])],
                    mitre_rules,
                    technique_index,
                )

                report_payload = {
                    "analysis_id": artifact_store.analysis_id,
                    "package_name": package_name,  # For method-centric report
                    "verdict": recon_result.get("threat_level", "UNKNOWN"),
                    "summary": "Static analysis completed. LLM summaries may be partial.",
                    # Use "seed_summaries" as the canonical report key (expected by UI/schema).
                    "seed_summaries": flow_summary_list,
                    "evidence_support_index": evidence_support_index,
                    "analysis_artifacts": {
                        "callgraph": artifact_store.relpath("graphs/callgraph.json") if callgraph_path else None,
                        "flowdroid": artifact_store.relpath("taint/flowdroid_summary.json") if flowdroid_summary else None,
                        "sensitive_api_hits": artifact_store.relpath("seeds/sensitive_api_hits.json") if sensitive_hits else None,
                        "recon": artifact_store.relpath("llm/recon.json"),
                        "entrypoint_paths": entrypoint_paths_ref,
                        "class_hierarchy": artifact_store.relpath("graphs/class_hierarchy.json") if class_hierarchy else None,
                        # Method analyses are stored as per-method JSON artifacts; keep only references in the report.
                        "method_cache_dir": artifact_store.relpath("method_cache"),
                    },
                    "mitre_candidates": mitre_candidates,
                    "driver_guidance": _build_driver_guidance(flow_summary_list),
                    "execution_guidance": _build_execution_guidance(flow_summary_list),
                }
                event_logger.stage_start("report")
                with span("stage.report", stage="report"):
                    with llm_context("report"):
                        report = report_agent.run(report_payload)
                    validate_json(report, "config/schemas/ThreatReport.schema.json")
                    artifact_store.write_json("report/threat_report.json", report)
                    artifact_store.write_text("report/threat_report.md", json.dumps(report, indent=2))
                event_logger.stage_end(
                    "report",
                    verdict=report.get("verdict"),
                    ref=artifact_store.relpath("report/threat_report.json"),
                )

                success = True
                return report
        except Exception as exc:
            event_logger.log("run.end", status="error", error=str(exc))
            raise
        finally:
            if success:
                event_logger.log("run.end", status="ok")


def _class_from_method(method_sig: str) -> str:
    if not method_sig:
        return ""
    if method_sig.startswith("<") and ":" in method_sig:
        return method_sig[1:].split(":", 1)[0]
    return ""


def _group_key_for_hit(hit: Dict[str, Any]) -> str:
    caller = hit.get("caller", {}) or {}
    caller_method = caller.get("method")
    if caller_method:
        return str(caller_method)
    signature = hit.get("signature")
    if signature:
        return str(signature)
    return str(hit.get("hit_id") or "UNKNOWN")


# =============================================================================
# CFG String Extraction Helpers
# =============================================================================

# Pattern 1: Quoted string literals in Jimple
_STRING_PATTERN = re.compile(r'"([^"]*)"')

# Pattern 2: Static field references in Jimple
# Matches: staticget <android.provider.Settings: java.lang.String ACTION_ACCESSIBILITY_SETTINGS>
# More permissive regex to handle various field name formats
_FIELD_PATTERN = re.compile(
    r"<([a-zA-Z0-9_.$]+):\s*java\.lang\.String\s+([A-Za-z_][A-Za-z0-9_]*)>"
)

# Known field → string value mappings
# Prevents false negatives on permission-lure flows where apps use field constants
# instead of literal strings (e.g., Settings.ACTION_ACCESSIBILITY_SETTINGS)
KNOWN_FIELD_VALUES: dict[str, str] = {
    "android.provider.Settings.ACTION_ACCESSIBILITY_SETTINGS": "android.settings.ACCESSIBILITY_SETTINGS",
    "android.provider.Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS": "android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS",
    "android.provider.Settings.ACTION_USAGE_ACCESS_SETTINGS": "android.settings.USAGE_ACCESS_SETTINGS",
    "android.provider.Settings.ACTION_MANAGE_OVERLAY_PERMISSION": "android.settings.action.MANAGE_OVERLAY_PERMISSION",
    "android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": "android.settings.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES": "android.settings.MANAGE_UNKNOWN_APP_SOURCES",
    "android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS": "android.settings.APPLICATION_DETAILS_SETTINGS",
}


def _hash_method_sig(signature: str) -> str:
    """Hash method signature for CFG file lookup."""
    return hashlib.sha1(signature.encode("utf-8")).hexdigest()


def _extract_strings_from_cfg(
    caller_method: str,
    artifact_store: ArtifactStore,
) -> set[str]:
    """Extract string literals AND field references from a method's CFG.

    Looks up the CFG from graphs/cfg/{hash}.json or via method_index.json.
    Extracts:
    1. Quoted strings from unit statements
    2. Known field references (Settings actions) mapped to their string values
    """
    if not caller_method or caller_method == "UNKNOWN":
        return set()

    try:
        # Try direct hash lookup first
        method_hash = _hash_method_sig(caller_method)
        cfg_path = artifact_store.path(f"graphs/cfg/{method_hash}.json")
        cfg = None

        if cfg_path.exists():
            cfg = artifact_store.read_json(f"graphs/cfg/{method_hash}.json")
        else:
            # Fall back to method index
            method_index_path = artifact_store.path("graphs/method_index.json")
            if method_index_path.exists():
                method_index = artifact_store.read_json("graphs/method_index.json")
                cfg_key = method_index.get(caller_method)
                if cfg_key:
                    cfg = artifact_store.read_json(f"graphs/cfg/{cfg_key}.json")

        if not cfg:
            return set()

        strings: set[str] = set()
        for unit in cfg.get("units", []):
            stmt = unit.get("stmt", "")

            # Extract quoted string literals
            strings.update(_STRING_PATTERN.findall(stmt))

            # Extract field references and map to known values
            for match in _FIELD_PATTERN.finditer(stmt):
                class_name, field_name = match.groups()
                field_key = f"{class_name}.{field_name}"
                resolved = KNOWN_FIELD_VALUES.get(field_key)
                if resolved:
                    strings.add(resolved)

        return strings

    except Exception:
        return set()


# Whitelist of categories where CFG string matching is appropriate.
# These categories have specific, high-signal string indicators that won't
# cause false positives (unlike C2_NETWORKING which has generic http:// etc.)
STRING_MATCH_CATEGORIES = frozenset({
    "SOCIAL_ENGINEERING_PERMISSION_LURE_SETTINGS",  # Settings intent strings
    "C2_MESSAGING_PLATFORM_ENDPOINTS",              # Telegram/Discord/Pastebin URLs
})


def _match_string_categories(
    strings: set[str],
    catalog: ApiCatalog,
) -> tuple[set[str], Dict[str, List[str]]]:
    """Match extracted strings against whitelisted catalog string indicators.

    Only matches against high-signal categories to avoid false positives from
    generic URL prefixes like http://, https://.

    Uses case-insensitive matching with basic boundary guards for URL/domain
    indicators (indicator in string only).

    Returns:
        (matched_categories, matched_indicators_by_category)
    """
    matched_categories: set[str] = set()
    matched_indicators_by_category: Dict[str, set[str]] = {}

    for string_value in strings:
        if not string_value:
            continue

        string_lower = string_value.lower()

        for category_id in STRING_MATCH_CATEGORIES:
            cat = catalog.categories.get(category_id)
            if not cat:
                continue

            for indicator in cat.string_indicators:
                indicator_lower = indicator.lower()

                # Skip short strings unless they are an exact indicator match.
                if len(string_lower) < 5 and string_lower != indicator_lower:
                    continue

                if indicator_lower not in string_lower:
                    continue

                if category_id == "SOCIAL_ENGINEERING_PERMISSION_LURE_SETTINGS":
                    matched = True  # long/high-signal; substring is safe enough
                else:
                    matched = _indicator_matches_with_boundaries(indicator_lower, string_lower)

                if matched:
                    matched_categories.add(category_id)
                    matched_indicators_by_category.setdefault(category_id, set()).add(indicator)

    return matched_categories, {
        category_id: sorted(indicators)
        for category_id, indicators in matched_indicators_by_category.items()
    }


def _indicator_matches_with_boundaries(indicator_lower: str, haystack_lower: str) -> bool:
    """
    Check indicator presence with simple boundary guards.

    Goal: avoid obvious false positives like matching "t.me" inside "not.me",
    or matching "api.telegram.org" inside "api.telegram.org.evil.com".
    """
    if not indicator_lower or indicator_lower not in haystack_lower:
        return False

    pattern = _compile_string_indicator_regex(indicator_lower)
    return bool(pattern.search(haystack_lower))


@lru_cache(maxsize=256)
def _compile_string_indicator_regex(indicator_lower: str) -> re.Pattern[str]:
    escaped = re.escape(indicator_lower)

    # Indicators with "/" are treated as path-like and can appear after subdomains
    # (e.g., ptb.discord.com/api/webhooks).
    if "/" in indicator_lower:
        return re.compile(rf"(?<![a-z0-9]){escaped}(?![a-z0-9])")

    # Domain-like indicators: disallow extra hostname characters on either side,
    # especially "." (prevents api.telegram.org.evil.com).
    return re.compile(rf"(?<![a-z0-9\.\-]){escaped}(?=$|[^a-z0-9\.\-])")


def _summarize_hit_group(
    group_key: str,
    hits: List[Dict[str, Any]],
    artifact_store: Optional[ArtifactStore] = None,
    catalog: Optional[ApiCatalog] = None,
) -> Dict[str, Any]:
    representative = hits[0] if hits else {}
    caller = representative.get("caller", {}) or {}
    caller_method = caller.get("method") or "UNKNOWN"
    caller_class = caller.get("class") or _class_from_method(caller_method)
    component_context = representative.get("component_context") or {}
    reachability = representative.get("reachability") or {}

    hit_ids: List[str] = []
    signatures: List[str] = []
    categories: set[str] = set()  # API-hit categories only
    priority_counts: Dict[str, int] = {}
    permission_hints: set[str] = set()
    mitre_primary: set[str] = set()
    mitre_aliases: set[str] = set()
    pha_tags: set[str] = set()
    slice_requests: List[Dict[str, Any]] = []
    requires_slice = False
    inv_scores: List[float] = []

    for hit in hits:
        hit_id = hit.get("hit_id")
        if hit_id:
            hit_ids.append(hit_id)
        signature = hit.get("signature")
        if signature:
            signatures.append(signature)
        category = hit.get("category_id")
        if category:
            categories.add(category)
        priority = hit.get("priority")
        if priority:
            priority_counts[priority] = priority_counts.get(priority, 0) + 1
        requires_slice = requires_slice or bool(hit.get("requires_slice"))
        if hit.get("requires_slice") and hit.get("slice_hints"):
            hint = hit.get("slice_hints") or {}
            if hint and hint not in slice_requests:
                slice_requests.append(hint)
        for perm in hit.get("permission_hints", []) or []:
            permission_hints.add(perm)
        if hit.get("mitre_primary"):
            mitre_primary.add(hit.get("mitre_primary"))
        for alias in hit.get("mitre_aliases", []) or []:
            mitre_aliases.add(alias)
        for tag in hit.get("pha_tags", []) or []:
            pha_tags.add(tag)
        # Collect investigability scores from hits
        inv = hit.get("investigability_score")
        if inv is not None:
            inv_scores.append(float(inv))

    # Compute group investigability score (average of hit scores, default 0.5)
    investigability_score = sum(inv_scores) / len(inv_scores) if inv_scores else 0.5

    # Extract strings from CFG and match against whitelisted catalog string indicators
    # Keep string-derived categories separate for traceability
    string_categories: set[str] = set()
    string_indicator_matches: Dict[str, List[str]] = {}
    if artifact_store and catalog:
        cfg_strings = _extract_strings_from_cfg(caller_method, artifact_store)
        string_categories, string_indicator_matches = _match_string_categories(cfg_strings, catalog)

    # Combine for scoring (but keep separate in output for traceability)
    all_categories_for_scoring = categories | string_categories

    if priority_counts:
        priority_max = min(priority_counts.keys(), key=_priority_rank)
    else:
        priority_max = "LOW"

    # Compute co-occurrence threat score using combined categories
    threat_score = 0.0
    threat_score_raw = 0.0
    effective_priority = priority_max
    threat_meta: Dict[str, Any] = {}
    if catalog:
        threat_score, threat_score_raw, effective_priority, threat_meta = compute_threat_score(
            all_categories_for_scoring, catalog, COOCCURRENCE_PATTERNS
        )

    group_id = f"grp-{hashlib.sha1(group_key.encode('utf-8')).hexdigest()}"
    return {
        "group_id": group_id,
        "group_key": group_key,
        "caller_method": caller_method,
        "caller_class": caller_class,
        "component_context": component_context,
        "reachability": {
            "reachable_from_entrypoint": reachability.get("reachable_from_entrypoint", False),
            "shortest_path_len": reachability.get("shortest_path_len", 0),
            "example_path": reachability.get("example_path", []),
        },
        "hit_ids": hit_ids,
        "hit_count": len(hit_ids),
        "categories": sorted(categories),  # API-hit categories only
        "string_categories": sorted(string_categories),  # String-derived (separate for traceability)
        "string_indicator_matches": string_indicator_matches,
        "signatures": signatures,
        "priority_counts": priority_counts,
        "priority_max": priority_max,
        "effective_priority": effective_priority,
        "threat_score": threat_score,
        "threat_score_raw": threat_score_raw,
        "threat_meta": threat_meta,
        "investigability_score": round(investigability_score, 2),
        "requires_slice": requires_slice,
        "slice_requests": slice_requests,
        "tags": {
            "mitre_primary": sorted(mitre_primary),
            "mitre_aliases": sorted(mitre_aliases),
            "pha_tags": sorted(pha_tags),
            "permission_hints": sorted(permission_hints),
        },
        "representative_hit_id": hit_ids[0] if hit_ids else None,
    }


def _group_sensitive_hits(
    hits: List[Dict[str, Any]],
    artifact_store: Optional[ArtifactStore] = None,
    catalog: Optional[ApiCatalog] = None,
) -> Dict[str, Any]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for hit in hits:
        key = _group_key_for_hit(hit)
        grouped.setdefault(key, []).append(hit)

    groups = [
        _summarize_hit_group(key, items, artifact_store, catalog)
        for key, items in grouped.items()
    ]
    return {
        "group_count": len(groups),
        "grouping_key": "caller_method",
        "groups": groups,
    }


def _get_outer_class(class_name: str) -> str:
    """Extract outer class from potentially inner class name.

    Examples:
        com.example.Foo$Bar$Baz → com.example.Foo
        com.example.Foo → com.example.Foo
    """
    if "$" in class_name:
        return class_name.split("$")[0]
    return class_name


def _is_app_code_class(
    caller_class: str,
    component_classes: set[str],
    app_prefixes: List[str],
) -> bool:
    """Check if a class is app code (not library)."""
    if not caller_class:
        return False
    # Check if it's a known component
    outer_class = _get_outer_class(caller_class)
    if outer_class in component_classes or caller_class in component_classes:
        return True
    # Check if it matches app prefixes (package_name or dominant component package)
    for prefix in app_prefixes:
        if not prefix:
            continue
        if caller_class == prefix or caller_class.startswith(prefix):
            return True
    return False


def build_code_blocks(
    groups: List[Dict[str, Any]],
    manifest: Dict[str, Any],
    catalog: Optional[ApiCatalog] = None,
    *,
    extra_app_prefixes: Optional[List[str]] = None,
    ignore_prefixes: Optional[List[str]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Aggregate method-level groups into class-level Code Blocks.

    Groups are aggregated by outer class (inner classes grouped with parent).
    Library groups are separated from app code groups.
    Computes co-occurrence threat scores at block level.

    Args:
        groups: List of method-level groups from _group_sensitive_hits()
        manifest: Parsed manifest for determining app code vs library
        catalog: Optional API catalog for co-occurrence scoring

    Returns:
        Tuple of (app_code_blocks, library_groups)
    """
    from collections import defaultdict

    # Extract app package and component classes from manifest
    app_package = manifest.get("package_name") or manifest.get("package") or ""
    component_classes: set[str] = set()
    for key in ("activities", "services", "receivers", "providers"):
        for comp in manifest.get(key, []) or []:
            if isinstance(comp, dict):
                name = comp.get("name", "")
            else:
                name = comp
            if name:
                if name.startswith(".") and app_package:
                    name = app_package + name
                component_classes.add(name)

    # App code prefix heuristic:
    # - Always include manifest package_name (when present)
    # - Also include the dominant package prefix among non-library manifest components
    #
    # This handles cases where the APK package_name differs from the Java package where
    # most app classes live (e.g., applicationId != source package), which would
    # otherwise misclassify real app code as "library" and cause false negatives.
    app_prefixes: List[str] = []
    if app_package:
        app_prefixes.append(app_package)
        app_prefixes.append(f"{app_package}.")

    component_package_counts: Dict[str, int] = {}
    for class_name in component_classes:
        if not class_name:
            continue
        if class_name.startswith(_LIBRARY_PREFIXES) or class_name.startswith(_COMMON_LIBRARY_PREFIXES):
            continue
        if "." not in class_name:
            continue
        package_prefix = class_name.rsplit(".", 1)[0] + "."
        component_package_counts[package_prefix] = component_package_counts.get(package_prefix, 0) + 1
    if component_package_counts:
        max_count = max(component_package_counts.values())
        for prefix, count in component_package_counts.items():
            if count == max_count:
                app_prefixes.append(prefix)
    app_prefixes = list(dict.fromkeys([p for p in app_prefixes if p]))

    def _normalize_package_prefix(value: str) -> str:
        prefix = (value or "").strip()
        if not prefix:
            return ""
        if prefix.endswith(".*"):
            prefix = prefix[:-2]
        if prefix.endswith("."):
            return prefix
        return prefix + "."

    # Optional LLM-selected prefixes (additive).
    if extra_app_prefixes:
        for p in extra_app_prefixes:
            normalized = _normalize_package_prefix(str(p))
            if normalized:
                app_prefixes.append(normalized)
    app_prefixes = list(dict.fromkeys([p for p in app_prefixes if p]))

    ignore_prefixes_norm: List[str] = []
    if ignore_prefixes:
        ignore_prefixes_norm = [
            normalized
            for p in ignore_prefixes
            if (normalized := _normalize_package_prefix(str(p)))
        ]
    ignore_prefixes_norm = list(dict.fromkeys(ignore_prefixes_norm))

    def _is_ignored_class(class_name: str) -> bool:
        if not class_name:
            return False
        return any(class_name.startswith(prefix) for prefix in ignore_prefixes_norm)

    # Group by outer class
    class_buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    library_groups: List[Dict[str, Any]] = []
    library_class_buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for group in groups:
        caller_class = group.get("caller_class", "")
        outer_class = _get_outer_class(caller_class)

        # Never ignore manifest components.
        is_manifest_component = outer_class in component_classes or caller_class in component_classes
        if is_manifest_component:
            class_buckets[outer_class].append(group)
        elif _is_ignored_class(caller_class):
            library_groups.append(group)
            library_class_buckets[outer_class].append(group)
        elif _is_app_code_class(caller_class, component_classes, app_prefixes):
            class_buckets[outer_class].append(group)
        else:
            library_groups.append(group)
            library_class_buckets[outer_class].append(group)

    def _build_block(outer_class: str, class_groups: List[Dict[str, Any]], *, is_library_code: bool) -> Dict[str, Any]:
        # Aggregate from all groups in this class
        all_hit_ids: List[str] = []
        all_group_ids: List[str] = []
        all_categories: set[str] = set()  # API-hit categories
        all_string_categories: set[str] = set()  # String-derived categories
        all_string_indicator_matches: Dict[str, set[str]] = defaultdict(set)
        all_methods: set[str] = set()
        priorities: List[str] = []
        inv_scores: List[float] = []
        has_reflection = False
        reachable = False
        shortest_path = 999

        # Get component context from first group that has it
        component_context: Dict[str, Any] = {}
        permissions_used: set[str] = set()

        for g in class_groups:
            all_hit_ids.extend(g.get("hit_ids", []))
            all_group_ids.append(g.get("group_id", ""))
            all_categories.update(g.get("categories", []))
            all_string_categories.update(g.get("string_categories", []))
            for category_id, indicators in (g.get("string_indicator_matches") or {}).items():
                if not category_id:
                    continue
                all_string_indicator_matches[category_id].update(indicators or [])
            priorities.append(g.get("priority_max", "LOW"))

            # Extract method name from caller_method
            caller_method = g.get("caller_method", "")
            method_name = _method_name_from_sig(caller_method)
            if method_name:
                all_methods.add(method_name)

            # Investigability
            inv_score = g.get("investigability_score")
            if inv_score is not None:
                inv_scores.append(float(inv_score))

            # Reachability
            reach = g.get("reachability", {})
            if reach.get("reachable_from_entrypoint"):
                reachable = True
                path_len = reach.get("shortest_path_len", 999)
                if path_len < shortest_path:
                    shortest_path = path_len

            # Component context (take first non-empty)
            if not component_context:
                ctx = g.get("component_context", {})
                if ctx.get("component_type") and ctx.get("component_type") != "Unknown":
                    component_context = ctx

            # Check for reflection in any group's path
            path = reach.get("example_path", [])
            for sig in path:
                if any(pattern in sig for pattern in (
                    "java.lang.reflect.",
                    "java.lang.Class.forName",
                    "dalvik.system.DexClassLoader",
                )):
                    has_reflection = True
                    break

            # Collect permission hints
            tags = g.get("tags", {})
            for perm in tags.get("permission_hints", []):
                permissions_used.add(perm)

        # Determine highest priority
        if priorities:
            priority_max = min(priorities, key=lambda p: priority_order.get(p, 99))
        else:
            priority_max = "LOW"

        # Average investigability score
        avg_inv_score = sum(inv_scores) / len(inv_scores) if inv_scores else 0.5

        # Build block ID
        block_id = f"block-{hashlib.sha1(outer_class.encode('utf-8')).hexdigest()[:12]}"

        # Determine component type if not found
        comp_type = component_context.get("component_type", "Unknown")
        comp_name = component_context.get("component_name", outer_class)

        # Check if exported (from manifest)
        is_exported = False
        for comp in manifest.get("services", []) + manifest.get("receivers", []):
            if isinstance(comp, dict):
                if comp.get("name") == comp_name or comp.get("name", "").endswith(outer_class.split(".")[-1]):
                    is_exported = comp.get("exported", False)
                    break

        # Compute co-occurrence threat score at block level using combined categories
        # Use level="block" for reduced boost (40% of group) since distributed
        # co-occurrence across a class is a weaker signal than tight method-level coupling
        all_categories_for_scoring = all_categories | all_string_categories
        threat_score = 0.0
        threat_score_raw = 0.0
        effective_priority = priority_max
        threat_meta: Dict[str, Any] = {}
        if catalog:
            threat_score, threat_score_raw, effective_priority, threat_meta = compute_threat_score(
                all_categories_for_scoring, catalog, COOCCURRENCE_PATTERNS, level="block"
            )

        return {
            "block_id": block_id,
            "caller_class": outer_class,
            "is_library_code": is_library_code,
            # Pre-computed context
            "component_type": comp_type,
            "component_name": comp_name,
            "is_exported": is_exported,
            "permissions_used": sorted(permissions_used),
            # Aggregated threat info
            "categories": sorted(all_categories),  # API-hit categories only
            "string_categories": sorted(all_string_categories),  # String-derived (separate for traceability)
            "string_indicator_matches": {
                category_id: sorted(indicators)
                for category_id, indicators in all_string_indicator_matches.items()
            },
            "priority_max": priority_max,
            "effective_priority": effective_priority,
            "threat_score": threat_score,
            "threat_score_raw": threat_score_raw,
            "threat_meta": threat_meta,
            "hit_count": len(all_hit_ids),
            "group_count": len(class_groups),
            "methods": sorted(all_methods),
            # Investigability signals
            "investigability_score": round(avg_inv_score, 2),
            "has_reflection": has_reflection,
            "reachable_from_entrypoint": reachable,
            "shortest_path_len": shortest_path if shortest_path < 999 else None,
            # Group IDs for drill-down
            "group_ids": all_group_ids,
            "hit_ids": all_hit_ids,
        }

    # Build code blocks from app class buckets (+ optionally keep patterned library blocks)
    code_blocks: List[Dict[str, Any]] = []
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    for outer_class, class_groups in class_buckets.items():
        code_blocks.append(_build_block(outer_class, class_groups, is_library_code=False))

    # Keep only high-signal library code by co-occurrence pattern match.
    # Rationale: third-party SDK code is often noisy, but if it matches an attack-chain
    # co-occurrence pattern we still want to surface it to Recon instead of dropping it.
    if catalog:
        for outer_class, class_groups in library_class_buckets.items():
            block = _build_block(outer_class, class_groups, is_library_code=True)
            if (block.get("threat_meta") or {}).get("pattern_count", 0) > 0:
                code_blocks.append(block)

    # Sort by effective priority, then threat_score_raw (uncapped for separation), then investigability
    code_blocks.sort(key=lambda b: (
        priority_order.get(b.get("effective_priority", b["priority_max"]), 99),
        -b.get("threat_score_raw", 0.0),
        -b["investigability_score"],
    ))

    return code_blocks, library_groups


def _method_name_from_sig(sig: str) -> str:
    """Extract method name from Soot signature."""
    # <com.example.Foo: void bar(int)> → bar
    if ":" in sig and "(" in sig:
        # Find the part after the return type and before the (
        parts = sig.split()
        for part in parts:
            if "(" in part:
                return part.split("(")[0]
    return ""


def _build_recon_payload(
    manifest: Dict[str, Any],
    sensitive_hits: Dict[str, Any],
    threat_indicators: Dict[str, Any],
    hit_groups: Optional[Dict[str, Any]] = None,
    code_blocks: Optional[List[Dict[str, Any]]] = None,
    preview_limit: int = 150,
) -> Dict[str, Any]:
    hits = sensitive_hits.get("hits", []) or []
    preview_limit = min(preview_limit, len(hits))
    preview_hits = _stratified_hits_preview(hits, limit=preview_limit)
    lite_preview = [_make_lite_hit(hit) for hit in preview_hits]
    group_preview = hit_groups.get("groups", []) if isinstance(hit_groups, dict) else []
    blocks_preview = code_blocks or []
    return {
        "manifest_summary": _manifest_summary(manifest),
        "callgraph_summary": sensitive_hits.get("callgraph_summary", {}),
        "sensitive_api_summary": sensitive_hits.get("summary", {}),
        "code_blocks_preview": blocks_preview,
        "sensitive_api_hits_preview": lite_preview,
        "sensitive_api_groups_preview": group_preview,
        "preview_metadata": {
            "preview_count": len(lite_preview),
            "total_count": len(hits),
            "sampling_strategy": "stratified_by_priority_with_redistribution",
            "categories_in_preview": len({hit.get("category_id") for hit in lite_preview}),
            "block_count": len(blocks_preview),
            "group_count": len(group_preview),
            "grouping_key": "caller_method",
            "note": "Code blocks are class-level aggregations. Use get_block/get_group for details.",
        },
        "threat_indicators": threat_indicators,
        "tool_results": [],
        "tool_schema": ReconToolRunner.schema(),
    }


def _manifest_summary(manifest: Dict[str, Any]) -> Dict[str, Any]:
    permissions = manifest.get("permissions") or manifest.get("all_permissions") or []
    return {
        "package_name": manifest.get("package_name") or manifest.get("package"),
        "application_label": manifest.get("application_label"),
        "permissions": permissions[:200],
        "components": {
            "activities": manifest.get("activities", [])[:50],
            "services": manifest.get("services", [])[:50],
            "receivers": manifest.get("receivers", [])[:50],
            "providers": manifest.get("providers", [])[:50],
        },
        "min_sdk": manifest.get("min_sdk_version"),
        "target_sdk": manifest.get("target_sdk_version"),
    }


def _make_lite_hit(hit: Dict[str, Any]) -> Dict[str, Any]:
    lite = dict(hit)
    lite.pop("slice_hints", None)
    reachability = hit.get("reachability") or {}
    if reachability:
        lite["reachability"] = {
            "reachable_from_entrypoint": reachability.get("reachable_from_entrypoint", False),
            "shortest_path_len": reachability.get("shortest_path_len", 0),
        }
    return lite


def _stratified_hits_preview(hits: List[Dict[str, Any]], limit: int = 150) -> List[Dict[str, Any]]:
    if limit <= 0 or not hits:
        return []
    from collections import defaultdict

    by_priority: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for hit in hits:
        priority = hit.get("priority", "LOW")
        by_priority[priority].append(hit)

    for priority_hits in by_priority.values():
        priority_hits.sort(
            key=lambda h: (
                not h.get("caller_is_app", False),
                not h.get("reachability", {}).get("reachable_from_entrypoint", False),
                h.get("hit_id", ""),
            )
        )

    target_quotas = {"CRITICAL": 0.4, "HIGH": 0.3, "MEDIUM": 0.2, "LOW": 0.1}
    priorities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    taken: Dict[str, int] = {}
    for priority in priorities:
        quota = int(limit * target_quotas[priority])
        available = len(by_priority.get(priority, []))
        taken[priority] = min(quota, available)

    total_taken = sum(taken.values())
    remaining_slots = limit - total_taken

    if remaining_slots > 0:
        can_take_more = {
            p: len(by_priority.get(p, [])) - taken[p]
            for p in priorities
            if len(by_priority.get(p, [])) > taken[p]
        }
        total_capacity = sum(can_take_more.values())
        if total_capacity > 0:
            for priority in priorities:
                capacity = can_take_more.get(priority, 0)
                if capacity > 0:
                    extra = min(
                        int(remaining_slots * capacity / total_capacity),
                        capacity,
                    )
                    taken[priority] += extra

    total_allocated = sum(taken.values())
    if total_allocated < limit:
        remaining_after = limit - total_allocated
        capacity_list = [
            (p, len(by_priority.get(p, [])) - taken.get(p, 0))
            for p in priorities
            if len(by_priority.get(p, [])) > taken.get(p, 0)
        ]
        capacity_list.sort(key=lambda x: x[1], reverse=True)
        for priority, capacity in capacity_list:
            if remaining_after <= 0:
                break
            extra = min(capacity, remaining_after)
            taken[priority] += extra
            remaining_after -= extra

    preview: List[Dict[str, Any]] = []
    for priority in priorities:
        count = taken.get(priority, 0)
        preview.extend(by_priority.get(priority, [])[:count])
    return preview


def _priority_rank(priority: str) -> int:
    mapping = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
    return mapping.get(priority or "", 5)


def _case_id_for_group(group_id: str) -> str:
    suffix = group_id.split("-", 1)[-1] if group_id else "unknown"
    return f"CASE-GRP-{suffix[:8]}"


def _get_flow_id(bundle: Dict[str, Any]) -> str:
    """Generate a flow ID from the control flow path methods.

    Each seed represents one control flow path (entry → methods → sink).
    The flow_id is derived from the ordered list of methods in the path.
    """
    import hashlib
    path_methods = bundle.get("control_flow_path", {}).get("path_methods", [])
    if not path_methods:
        # Fallback: use caller_method + sink API
        caller = bundle.get("caller_method", "")
        sink = bundle.get("api_signature", "")
        path_methods = [caller, sink] if caller else [sink]

    # Create stable hash from ordered method list
    path_str = "|".join(path_methods)
    hash_suffix = hashlib.sha1(path_str.encode()).hexdigest()[:8]
    return f"FLOW-{hash_suffix}"


def _fallback_cases_from_groups(
    group_ids: set[str],
    hit_groups_by_id: Dict[str, Dict[str, Any]],
    hits_by_id: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []
    for group_id in sorted(group_ids):
        group = hit_groups_by_id.get(group_id) or {}
        hit_ids = group.get("hit_ids") or []
        categories = group.get("categories") or []
        category_id = categories[0] if len(categories) == 1 else f"MERGED({len(categories)})"
        if not categories:
            category_id = "UNKNOWN"
        priority_max = group.get("priority_max") or "LOW"
        priority = _priority_rank(priority_max)
        representative_hit_id = group.get("representative_hit_id") or (hit_ids[0] if hit_ids else None)
        representative_hit = hits_by_id.get(representative_hit_id or "", {}) if representative_hit_id else {}
        caller = representative_hit.get("caller", {}) or {}
        case_id = _case_id_for_group(group_id)
        cases.append({
            "case_id": case_id,
            "priority": priority,
            "category_id": category_id,
            "evidence_group_ids": [group_id],
            "evidence_hit_ids": hit_ids,
            "primary_hit": {
                "signature": representative_hit.get("signature"),
                "caller_method": caller.get("method"),
                "callee_signature": representative_hit.get("signature"),
            },
            "component_context": group.get("component_context") or representative_hit.get("component_context", {}),
            "reachability": group.get("reachability") or representative_hit.get("reachability", {}),
            "requires_slice": bool(group.get("requires_slice")),
            "slice_requests": group.get("slice_requests") or [],
            "tool_requests": [],
            "rationale": "Auto-added group not covered by recon triage.",
            "confidence": 0.2,
            "tags": group.get("tags") or {},
            "next_stage": "TIER1_SUMMARY",
            "llm_severity": priority_max,
            "severity_reasoning": "Group was not assigned by recon; included for coverage.",
            "severity_confidence": 0.2,
            "severity_factors": ["auto_added_group"],
            "should_prune": False,
            "pruning_reasoning": "",
            "pruning_confidence": 0.0,
        })
    return cases


def _fallback_cases_from_hits(sensitive_hits: Dict[str, Any], max_cases: int) -> List[Dict[str, Any]]:
    cases = []
    hits = sensitive_hits.get("hits", []) or []
    for idx, hit in enumerate(hits[:max_cases], start=1):
        case_id = f"CASE-{idx:03d}"
        requires_slice = bool(hit.get("requires_slice"))
        slice_request = hit.get("slice_hints") or {}
        cases.append({
            "case_id": case_id,
            "priority": idx,
            "category_id": hit.get("category_id"),
            "evidence_hit_ids": [hit.get("hit_id")] if hit.get("hit_id") else [],
            "primary_hit": {
                "signature": hit.get("signature"),
                "caller_method": hit.get("caller", {}).get("method"),
                "callee_signature": hit.get("signature"),
            },
            "component_context": hit.get("component_context", {}),
            "reachability": hit.get("reachability", {}),
            "requires_slice": requires_slice,
            "slice_requests": [slice_request] if requires_slice and slice_request else [],
            "tool_requests": [],
            "rationale": "Deterministic fallback case based on sensitive API hit.",
            "confidence": 0.4,
            "tags": {
                "mitre_primary": hit.get("mitre_primary"),
                "mitre_aliases": hit.get("mitre_aliases", []),
                "pha_tags": hit.get("pha_tags", []),
                "permission_hints": hit.get("permission_hints", []),
            },
            "next_stage": "TIER1_SUMMARY",
        })
    return cases


def _build_hit_group_index(hit_groups_by_id: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    hit_to_group: Dict[str, str] = {}
    for group_id, group in hit_groups_by_id.items():
        for hit_id in group.get("hit_ids", []) or []:
            if hit_id:
                hit_to_group[hit_id] = group_id
    return hit_to_group


def _collect_case_group_ids(
    cases: List[Dict[str, Any]],
    hit_groups_by_id: Dict[str, Dict[str, Any]],
) -> set[str]:
    hit_to_group = _build_hit_group_index(hit_groups_by_id)
    group_ids: set[str] = set()
    for case in cases:
        for group_id in case.get("evidence_group_ids", []) or []:
            if group_id:
                group_ids.add(group_id)
        for hit_id in case.get("evidence_hit_ids", []) or []:
            group_id = hit_to_group.get(hit_id)
            if group_id:
                group_ids.add(group_id)
    return group_ids


def _expand_case_hit_ids(
    case: Dict[str, Any],
    hit_groups_by_id: Dict[str, Dict[str, Any]],
) -> List[str]:
    hit_ids = list(case.get("evidence_hit_ids", []) or [])
    for group_id in case.get("evidence_group_ids", []) or []:
        group = hit_groups_by_id.get(group_id)
        if not group:
            continue
        hit_ids.extend(group.get("hit_ids", []) or [])
    seen = set()
    return [hid for hid in hit_ids if hid and not (hid in seen or seen.add(hid))]


def _case_lookup(
    cases: List[Dict[str, Any]],
    hit_groups_by_id: Dict[str, Dict[str, Any]] | None = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Build a lookup from hit_id to case context.

    Preserves full Recon context for use in Tier1/Tier2 processing.
    Expands evidence_group_ids into hit_ids when group metadata is available.
    """
    hit_groups_by_id = hit_groups_by_id or {}
    lookup: Dict[str, Dict[str, Any]] = {}
    for case in cases:
        priority = case.get("priority", 9999)
        evidence_hit_ids = _expand_case_hit_ids(case, hit_groups_by_id)
        for hit_id in evidence_hit_ids:
            existing = lookup.get(hit_id)
            if existing and existing.get("priority", 9999) <= priority:
                continue
            lookup[hit_id] = {
                # Core identifiers
                "case_id": case.get("case_id"),
                "priority": priority,
                "category_id": case.get("category_id"),
                # Recon context
                "recon_rationale": case.get("rationale"),
                "recon_severity": case.get("llm_severity"),
                "severity_reasoning": case.get("severity_reasoning"),
                "tags": case.get("tags"),
                # Case structure
                "sibling_hit_ids": [h for h in evidence_hit_ids if h != hit_id],
                "total_case_hits": len(evidence_hit_ids),
            }
    return lookup


def _order_bundles_by_cases(
    bundles: List[Dict[str, Any]],
    cases: List[Dict[str, Any]],
    hit_groups_by_id: Dict[str, Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    case_map = _case_lookup(cases, hit_groups_by_id)
    
    def _get_priority(b: Dict[str, Any]) -> int:
        p1 = case_map.get(b.get("seed_id"), {}).get("priority", 9999)
        p2 = b.get("case_context", {}).get("priority", 9999)
        return min(p1, p2)

    return sorted(bundles, key=_get_priority)


def _callsites_from_cases(
    cases: List[Dict[str, Any]],
    hits_by_id: Dict[str, Dict[str, Any]],
    hit_groups_by_id: Dict[str, Dict[str, Any]] | None = None,
) -> List[ApiCallSite]:
    """
    Convert Recon cases to ApiCallSite objects for seeding.

    Preserves full Recon context including:
    - rationale: LLM's reasoning for why this is suspicious
    - llm_severity: LLM's severity assessment (CRITICAL/HIGH/MEDIUM/LOW)
    - severity_reasoning: Detailed explanation of severity
    - tags: MITRE, PHA, permission hints
    - sibling_hit_ids: Other hits in the same case (for case-level analysis)
    - slice_requests: Specific questions to investigate
    - evidence_group_ids: Group-level case references expanded into hit_ids
    """
    hit_groups_by_id = hit_groups_by_id or {}
    hit_to_group = _build_hit_group_index(hit_groups_by_id)
    callsites: List[ApiCallSite] = []
    seen = set()
    for case in cases:
        case_id = case.get("case_id")
        priority = case.get("priority")
        evidence_hit_ids = _expand_case_hit_ids(case, hit_groups_by_id)

        for hit_id in evidence_hit_ids:
            if hit_id in seen:
                continue
            hit = hits_by_id.get(hit_id)
            if not hit:
                continue
            seen.add(hit_id)
            caller = hit.get("caller", {}) or {}
            component_context = hit.get("component_context")
            reachability = hit.get("reachability")

            # Compute sibling hit IDs (other hits in the same case)
            sibling_hit_ids = [h for h in evidence_hit_ids if h != hit_id]
            group_id = hit_to_group.get(hit_id)
            group_hit_ids = []
            if group_id and group_id in hit_groups_by_id:
                group_hit_ids = hit_groups_by_id[group_id].get("hit_ids", []) or []

            callsites.append(
                ApiCallSite(
                    seed_id=hit_id,
                    category=hit.get("category_id", "UNKNOWN"),
                    signature=normalize_signature(hit.get("signature", "")),
                    caller_method=caller.get("method") or "UNKNOWN",
                    caller_class=caller.get("class") or "UNKNOWN",
                    callsite_descriptor={
                        # Core identifiers
                        "hit_id": hit_id,
                        "case_id": case_id,
                        "priority": priority,
                        "source": "sensitive_api_hits",
                        "group_id": group_id,
                        "group_hit_ids": group_hit_ids,
                        # Component and reachability context
                        "component_context": component_context,
                        "reachability": reachability,
                        # NEW: Full Recon context preserved
                        "recon_rationale": case.get("rationale"),
                        "recon_severity": case.get("llm_severity"),
                        "severity_reasoning": case.get("severity_reasoning"),
                        "severity_confidence": case.get("severity_confidence"),
                        "severity_factors": case.get("severity_factors"),
                        # Tags from Recon (MITRE, PHA, permissions)
                        "tags": case.get("tags"),
                        # Case structure (for case-level aggregation)
                        "sibling_hit_ids": sibling_hit_ids,
                        "total_case_hits": len(evidence_hit_ids),
                        # Slice requests from Recon (questions to investigate)
                        "slice_requests": case.get("slice_requests"),
                    },
                    confidence=case.get("confidence", 1.0),
                )
            )
    return callsites


def _deduplicate_callsites_by_caller(
    callsites: List[ApiCallSite],
) -> List[ApiCallSite]:
    """
    Merge callsites that share the same caller method within the same case.

    This prevents redundant Tier1 analysis when multiple API calls exist
    in the same method (e.g., 4 MediaRecorder calls in recordMic()).

    Merged callsites preserve all original hit_ids and signatures for reference.
    """
    from collections import defaultdict

    # Group by (case_id, caller_method)
    by_caller: Dict[tuple, List[ApiCallSite]] = defaultdict(list)
    for site in callsites:
        descriptor = site.callsite_descriptor if isinstance(site.callsite_descriptor, dict) else {}
        case_id = descriptor.get("case_id") or "NONE"
        key = (case_id, site.caller_method)
        by_caller[key].append(site)

    merged: List[ApiCallSite] = []
    for (case_id, caller_method), sites in by_caller.items():
        if len(sites) == 1:
            merged.append(sites[0])
        else:
            # Merge multiple callsites from same method
            # Use highest priority site as primary
            primary = min(
                sites,
                key=lambda s: (
                    (s.callsite_descriptor or {}).get("priority", 9999)
                    if isinstance(s.callsite_descriptor, dict) else 9999
                ),
            )

            # Collect all hit_ids, signatures, categories
            all_hit_ids = []
            all_signatures = []
            all_categories = set()
            for s in sites:
                all_signatures.append(s.signature)
                all_categories.add(s.category)
                if isinstance(s.callsite_descriptor, dict):
                    hid = s.callsite_descriptor.get("hit_id")
                    if hid:
                        all_hit_ids.append(hid)

            # Build merged descriptor
            merged_descriptor = dict(primary.callsite_descriptor) if isinstance(primary.callsite_descriptor, dict) else {}
            merged_descriptor["merged_hit_ids"] = all_hit_ids
            merged_descriptor["merged_signatures"] = all_signatures
            merged_descriptor["merged_categories"] = list(all_categories)
            merged_descriptor["merged_count"] = len(sites)
            # Update sibling_hit_ids to exclude all merged hits
            merged_descriptor["sibling_hit_ids"] = [
                h for h in merged_descriptor.get("sibling_hit_ids", [])
                if h not in all_hit_ids
            ]

            # Use a composite category if multiple
            category = primary.category
            if len(all_categories) > 1:
                category = f"MERGED({len(all_categories)})"

            merged.append(ApiCallSite(
                seed_id=primary.seed_id,
                category=category,
                signature=primary.signature,  # Primary signature
                caller_method=caller_method,
                caller_class=primary.caller_class,
                callsite_descriptor=merged_descriptor,
                confidence=primary.confidence,
            ))

    return merged


def _write_suspicious_index(store: ArtifactStore, index: SuspiciousApiIndex) -> None:
    store.write_json(
        "seeds/suspicious_api_index.json",
        {
            "apk_id": index.apk_id,
            "catalog_version": index.catalog_version,
            "callsites": [asdict(site) for site in index.callsites],
        },
    )


def _build_driver_guidance(flow_summaries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    guidance = []
    for summary in flow_summaries:
        tier2 = summary.get("tier2") or {}
        guidance.append({
            "seed_id": summary.get("seed_id"),
            "case_id": summary.get("case_id"),
            "category_id": summary.get("category_id"),
            "driver_plan": tier2.get("driver_plan", []),
            "environment_setup": tier2.get("environment_setup", []),
            "execution_checks": tier2.get("execution_checks", []),
        })
    return guidance


def _build_execution_guidance(flow_summaries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build top-level execution_guidance array from Tier2 outputs.
    Prefer per-seed guidance when available; fall back to case-level guidance.
    """
    seen_cases: set = set()
    seen_entries: set = set()
    guidance = []
    for summary in flow_summaries:
        tier2 = summary.get("tier2") or {}
        exec_by_seed = tier2.get("execution_guidance_by_seed") or []
        if isinstance(exec_by_seed, list) and exec_by_seed:
            for entry in exec_by_seed:
                if not isinstance(entry, dict):
                    continue
                exec_entry = dict(entry)
                case_id = exec_entry.get("case_id") or summary.get("case_id")
                requirement_id = exec_entry.get("requirement_id") or ""
                primary_seed_id = exec_entry.get("primary_seed_id") or summary.get("seed_id") or ""
                key = (case_id, requirement_id, primary_seed_id)
                if key in seen_entries:
                    continue
                seen_entries.add(key)

                # Fallback: fill in missing fields from seed summary if Tier2 omitted them
                if not exec_entry.get("case_id"):
                    exec_entry["case_id"] = case_id
                if not exec_entry.get("category_id"):
                    exec_entry["category_id"] = summary.get("category_id")
                if not exec_entry.get("package_name"):
                    exec_entry["package_name"] = summary.get("package_name")
                if not exec_entry.get("primary_seed_id"):
                    exec_entry["primary_seed_id"] = primary_seed_id
                if not exec_entry.get("seed_ids"):
                    seed_id = summary.get("seed_id")
                    exec_entry["seed_ids"] = [seed_id] if seed_id else []
                if not exec_entry.get("target_capability"):
                    exec_entry["target_capability"] = exec_entry.get("category_id") or summary.get("category_id")

                guidance.append(exec_entry)
            continue

        exec_guide = tier2.get("execution_guidance")
        if not exec_guide:
            continue
        if not isinstance(exec_guide, dict):
            continue
        exec_guide = dict(exec_guide)
        case_id = exec_guide.get("case_id") or summary.get("case_id")
        if case_id in seen_cases:
            continue  # Already added this case
        seen_cases.add(case_id)

        # Fallback: fill in missing fields from seed summary if Tier2 omitted them
        if not exec_guide.get("case_id"):
            exec_guide["case_id"] = summary.get("case_id")
        if not exec_guide.get("category_id"):
            exec_guide["category_id"] = summary.get("category_id")
        if not exec_guide.get("package_name"):
            exec_guide["package_name"] = summary.get("package_name")
        if not exec_guide.get("primary_seed_id"):
            exec_guide["primary_seed_id"] = summary.get("seed_id")
        if not exec_guide.get("seed_ids"):
            seed_id = summary.get("seed_id")
            exec_guide["seed_ids"] = [seed_id] if seed_id else []
        if not exec_guide.get("target_capability"):
            exec_guide["target_capability"] = exec_guide.get("category_id") or summary.get("category_id")

        guidance.append(exec_guide)
    return guidance


def _parse_target_sdk(manifest: Dict[str, Any]) -> Optional[int]:
    if not manifest:
        return None
    for key in ("target_sdk_version", "target_sdk", "targetSdkVersion"):
        value = manifest.get(key)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


# =============================================================================
# Method-Centric Tier1 Pipeline
# =============================================================================


def run_method_tier1_pipeline(
    bundles: List[Dict[str, Any]],
    jadx_root: Optional[Path],
    cfg_dir: Optional[Path],
    llm_client: Any,
    artifact_store: "ArtifactStore",
    event_logger: Optional["EventLogger"] = None,
    model: Optional[str] = None,
    prompt_dir: Optional[Path] = None,
) -> Dict[str, MethodAnalysis]:
    """
    Run method-centric tier1 analysis pipeline.

    1. Collect unique methods from all seed paths
    2. Batch extract JADX + Jimple IR sources (dual extraction)
    3. Analyze each method once (parallelizable)
    4. Return method cache for static composition

    Args:
        bundles: List of seed bundles with control_flow_path
        jadx_root: JADX output directory (optional)
        cfg_dir: CFG directory for Jimple IR fallback (graphs/cfg/)
        llm_client: LLM client for analysis
        artifact_store: For storing outputs
        event_logger: Optional logger
        model: Optional model name
        prompt_dir: Directory containing prompts

    Returns:
        Dict mapping method_sig -> MethodAnalysis
    """
    prompt_dir = prompt_dir or Path("src/apk_analyzer/prompts")

    # Phase 0.5: Collect unique methods from all paths
    if event_logger:
        event_logger.log("method_tier1.collect_start", bundle_count=len(bundles))

    unique_methods = collect_unique_methods(bundles)

    if event_logger:
        event_logger.log(
            "method_tier1.collect_done",
            unique_methods=len(unique_methods),
        )

    if not unique_methods:
        return {}

    # Phase 0.6: Batch JADX + Jimple IR extraction
    if event_logger:
        event_logger.log("method_tier1.extract_start", methods=len(unique_methods))

    extraction_results = batch_extract_sources(unique_methods, jadx_root, cfg_dir)

    # Count extraction strategies
    jadx_count = sum(1 for e in extraction_results.values() if e.lookup_strategy == "jadx")
    jimple_only_count = sum(1 for e in extraction_results.values() if e.lookup_strategy == "jimple_only")
    jadx_with_jimple_count = sum(1 for e in extraction_results.values() if e.lookup_strategy == "jadx_with_jimple")
    not_found_count = sum(1 for e in extraction_results.values() if e.lookup_strategy == "not_found")

    if event_logger:
        event_logger.log(
            "method_tier1.extract_done",
            jadx=jadx_count,
            jimple_only=jimple_only_count,
            jadx_with_jimple=jadx_with_jimple_count,
            not_found=not_found_count,
        )

    # Setup cache directory
    cache_dir = artifact_store.ensure_dir("method_cache")
    cache = MethodAnalysisCache(cache_dir)

    # Setup agent
    agent = MethodTier1Agent(
        prompt_path=prompt_dir / "tier1_method.md",
        llm_client=llm_client,
        model=model,
        event_logger=event_logger,
    )

    # Phase 0.7: Analyze methods with dual JADX+Jimple sources
    methods_with_source = sum(1 for e in extraction_results.values() if e.has_any_source)
    if event_logger:
        event_logger.log("method_tier1.analyze_start", methods=methods_with_source)

    method_cache = analyze_methods_with_sources(extraction_results, agent, cache)

    # Add placeholders for methods without any source (neither JADX nor Jimple)
    for method_sig in unique_methods:
        if method_sig not in method_cache:
            method_cache[method_sig] = MethodAnalysis.placeholder(method_sig)

    if event_logger:
        analyzed_with_jadx = sum(1 for m in method_cache.values() if m.jadx_available)
        analyzed_with_jimple = sum(1 for m in method_cache.values() if m.jimple_available)
        event_logger.log(
            "method_tier1.analyze_done",
            analyzed=len(method_cache),
            with_jadx=analyzed_with_jadx,
            with_jimple=analyzed_with_jimple,
        )

    # Save method analyses to artifacts
    for method_sig, analysis in method_cache.items():
        safe_name = hashlib.sha256(method_sig.encode()).hexdigest()[:16]
        artifact_store.write_json(f"method_cache/{safe_name}.json", analysis.to_dict())

    # Generate methods_to_investigate.json for frontend display
    generate_methods_to_investigate_json(
        method_cache=method_cache,
        bundles=bundles,
        artifact_store=artifact_store,
    )

    return method_cache


def generate_methods_to_investigate_early(
    bundles: List[Dict[str, Any]],
    artifact_store: "ArtifactStore",
) -> None:
    """
    Generate initial methods_to_investigate.json before Tier 1 starts.

    This provides early visibility into how many methods will be analyzed,
    allowing the UI to show progress indicators before analysis completes.

    All methods are marked as "pending" initially; the file is updated
    with actual statuses after method-centric Tier 1 completes.

    Args:
        bundles: List of seed bundles with control_flow_path
        artifact_store: For storing output
    """
    method_usage: Dict[str, List[str]] = {}

    for bundle in bundles:
        path_id = bundle.get("seed_id", "unknown")
        control_flow_path = bundle.get("control_flow_path", {})
        path_methods = control_flow_path.get("path_methods", [])

        for method_sig in path_methods:
            # Skip framework APIs
            if any(method_sig.startswith(p) for p in ("<android.", "<java.", "<javax.", "<dalvik.")):
                continue
            if method_sig not in method_usage:
                method_usage[method_sig] = []
            method_usage[method_sig].append(path_id)

    methods_list = [
        {
            "method_sig": method_sig,
            "jadx_available": None,  # Unknown yet
            "usage_count": len(path_ids),
            "path_ids": path_ids,
            "analysis_status": "pending",
            "function_summary": None,
            "confidence": 0.0,
        }
        for method_sig, path_ids in method_usage.items()
    ]

    # Sort by usage count (most used first)
    methods_list.sort(key=lambda x: x["usage_count"], reverse=True)

    output = {
        "total_unique": len(methods_list),
        "analyzed_count": 0,
        "with_jadx": 0,
        "methods": methods_list,
    }

    artifact_store.write_json("llm/methods_to_investigate.json", output)


def generate_methods_to_investigate_json(
    method_cache: Dict[str, MethodAnalysis],
    bundles: List[Dict[str, Any]],
    artifact_store: "ArtifactStore",
) -> None:
    """
    Generate methods_to_investigate.json for frontend display.

    This file provides aggregated method information including:
    - Which methods are analyzed
    - Usage count (how many execution paths use each method)
    - Analysis status and summaries

    Args:
        method_cache: Dict of method_sig -> MethodAnalysis
        bundles: List of seed bundles with control_flow_path
        artifact_store: For storing output
    """
    # Count method usage across all execution paths
    method_usage: Dict[str, List[str]] = {}  # method_sig -> list of path_ids

    for bundle in bundles:
        path_id = bundle.get("seed_id", "unknown")
        control_flow_path = bundle.get("control_flow_path", {})
        path_methods = control_flow_path.get("path_methods", [])

        for method_sig in path_methods:
            # Skip framework APIs
            if any(method_sig.startswith(p) for p in ("<android.", "<java.", "<javax.", "<dalvik.")):
                continue
            if method_sig not in method_usage:
                method_usage[method_sig] = []
            method_usage[method_sig].append(path_id)

    # Build methods list
    methods_list = []
    for method_sig, path_ids in method_usage.items():
        analysis = method_cache.get(method_sig)
        if analysis:
            methods_list.append({
                "method_sig": method_sig,
                "jadx_available": analysis.jadx_available,
                "usage_count": len(path_ids),
                "path_ids": path_ids,
                "analysis_status": "complete" if analysis.jadx_available else "no_jadx",
                "function_summary": analysis.function_summary if analysis.jadx_available else None,
                "confidence": analysis.confidence,
            })
        else:
            methods_list.append({
                "method_sig": method_sig,
                "jadx_available": False,
                "usage_count": len(path_ids),
                "path_ids": path_ids,
                "analysis_status": "pending",
                "function_summary": None,
                "confidence": 0.0,
            })

    # Sort by usage count (most used first)
    methods_list.sort(key=lambda x: x["usage_count"], reverse=True)

    # Calculate summary stats
    analyzed_count = sum(1 for m in methods_list if m["analysis_status"] == "complete")
    with_jadx = sum(1 for m in methods_list if m["jadx_available"])

    output = {
        "total_unique": len(methods_list),
        "analyzed_count": analyzed_count,
        "with_jadx": with_jadx,
        "methods": methods_list,
    }

    artifact_store.write_json("llm/methods_to_investigate.json", output)


def generate_tier2_summary_json(
    flow_summary_list: List[Dict[str, Any]],
    artifact_store: "ArtifactStore",
) -> None:
    """
    Generate tier2_summary.json for frontend Attack Chains display.

    Aggregates tier2 results into a summary file with:
    - Chain count
    - Summary per chain with severity and description

    Args:
        flow_summary_list: List of seed summaries with tier2 results
        artifact_store: For storing output
    """
    chains = []

    for summary in flow_summary_list:
        tier2 = summary.get("tier2")
        if not tier2:
            continue

        seed_id = summary.get("seed_id", "unknown")
        case_id = summary.get("tier2_case_id") or summary.get("case_id")

        # Extract key information from tier2
        attack_summary = tier2.get("function_summary") or tier2.get("attack_summary") or ""
        threat_level = tier2.get("threat_level") or tier2.get("severity") or "MEDIUM"

        # Get observable effects if available
        observable_effects = tier2.get("observable_effects", [])
        if observable_effects and isinstance(observable_effects, list):
            effects_summary = "; ".join(observable_effects[:3])
        else:
            effects_summary = ""

        chains.append({
            "seed_id": seed_id,
            "case_id": case_id,
            "attack_summary": attack_summary,
            "severity": threat_level,
            "observable_effects": effects_summary,
            "has_driver_plan": bool(tier2.get("driver_plan")),
            "has_execution_guidance": bool(tier2.get("execution_guidance_by_seed")),
        })

    output = {
        "chain_count": len(chains),
        "chains": chains,
    }

    artifact_store.write_json("llm/tier2_summary.json", output)


def tier1_from_composed(
    composed: ComposedFlowAnalysis,
    bundle: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Convert ComposedFlowAnalysis to tier1 output format with execution_path.

    Includes:
    - Legacy fields for backward compatibility
    - execution_path for new Tier 2 prompts with method-level detail
    """
    # Aggregate function summaries from all methods
    summaries = [
        f"{a.method_sig}: {a.function_summary}"
        for a in composed.path_analyses
        if a.function_summary and a.jadx_available
    ]
    function_summary = " → ".join(summaries) if summaries else "Static composition from method analyses"

    # Build trigger_surface from first method (entrypoint) or component_context
    trigger_surface = composed.component_context.copy()
    for analysis in composed.path_analyses:
        if analysis.trigger_info and analysis.trigger_info.get("is_entrypoint"):
            trigger_surface.update({
                "notes": analysis.function_summary,
            })
            break

    # Build facts from all method facts
    facts = []
    for analysis in composed.path_analyses:
        for fact in analysis.facts:
            facts.append({
                "fact": fact.get("fact", ""),
                "support_unit_ids": [],  # Static composition doesn't have CFG unit IDs
                "source_method": analysis.method_sig,
            })

    # Build observable effects from method summaries
    observable_effects = [
        a.function_summary
        for a in composed.path_analyses
        if a.jadx_available
    ]

    # Aggregate uncertainties
    uncertainties = []
    for analysis in composed.path_analyses:
        uncertainties.extend(analysis.uncertainties)

    # Calculate confidence (average of method confidences)
    confidences = [a.confidence for a in composed.path_analyses if a.jadx_available]
    confidence = sum(confidences) / len(confidences) if confidences else 0.5

    # Build execution_path for new Tier 2 prompts
    execution_path = []
    for analysis in composed.path_analyses:
        execution_path.append({
            "method": analysis.method_sig,
            "jadx_available": analysis.jadx_available,
            "summary": analysis.function_summary,
            "data_flow": analysis.data_flow,
            "trigger_info": analysis.trigger_info,
            "constraints": analysis.path_constraints,
            "facts": analysis.facts,
            "required_inputs": analysis.required_inputs,
            "uncertainties": analysis.uncertainties,
            "confidence": analysis.confidence,
        })

    # Extract permissions from required_inputs
    required_permissions = [
        inp for inp in composed.all_required_inputs
        if inp.get("type") == "permission"
    ]

    return {
        "seed_id": composed.flow_id,  # Access flow_id, output as seed_id for backward compat
        "function_summary": function_summary,
        "path_constraints": composed.all_constraints,
        "required_inputs": composed.all_required_inputs,
        "trigger_surface": trigger_surface,
        "observable_effects": observable_effects,
        "facts": facts,
        "uncertainties": uncertainties,
        "confidence": confidence,
        "mode": "method_composed",

        # NEW: Method-centric fields for Tier 2
        "api_category": composed.api_category,
        "sink_api": composed.sink_api,
        "execution_path": execution_path,
        "required_permissions": required_permissions,
        "component_context": composed.component_context,
        "reachability": composed.reachability,

        "_meta": {
            "llm_valid": True,
            "methods_analyzed": composed.methods_analyzed,
            "methods_with_jadx": composed.methods_with_jadx,
            "composition_type": "static",
        },
    }


# =============================================================================
# Tier2 Payload Shaping (Token Optimization)
# =============================================================================

# Library noise prefixes for FCG filtering
_FCG_NOISE_PREFIXES = [
    "androidx.", "com.google.android.material", "kotlin",
    "java.", "android.", "com.google.android.gms",
]


def _filter_fcg(fcg: Dict[str, Any], package_name: Optional[str]) -> Dict[str, Any]:
    """
    Keep only app-specific methods in FCG, filter library noise.
    """
    if not fcg:
        return {}

    def is_app_method(sig: str) -> bool:
        # Use package_name from manifest if available
        if package_name and package_name in sig:
            return True
        # Fallback: exclude known library prefixes
        return not any(noise in sig for noise in _FCG_NOISE_PREFIXES)

    return {
        "k": fcg.get("k", 2),
        "callers": [c for c in fcg.get("callers", []) if is_app_method(c)][:20],
        "callees": [c for c in fcg.get("callees", []) if is_app_method(c)][:20],
    }


def _class_from_signature(signature: str) -> Optional[str]:
    match = re.match(r"<([^:]+):", signature or "")
    return match.group(1) if match else None


def _referenced_components(seeds: List[Dict[str, Any]]) -> set[str]:
    referenced: set[str] = set()
    for seed in seeds:
        tier1 = seed.get("tier1") or {}
        trigger = tier1.get("trigger_surface") or {}
        comp_name = trigger.get("component_name")
        if comp_name:
            referenced.add(comp_name)
        caller = seed.get("caller_method") or ""
        class_name = _class_from_signature(caller)
        if class_name:
            referenced.add(class_name)
            if "$" in class_name:
                referenced.add(class_name.split("$")[0])
    return referenced


def _filter_component_map(
    component_map: Dict[str, Any],
    seeds: List[Dict[str, Any]],
    fallback_limit: int = 10,
) -> Dict[str, Any]:
    """
    Filter a component->data mapping down to seed-referenced components.
    """
    if not component_map or not seeds:
        return {}

    referenced = _referenced_components(seeds)
    if not referenced:
        return dict(list(component_map.items())[:fallback_limit])

    return {name: info for name, info in component_map.items() if name in referenced}


def _filter_intent_contracts(intent_contracts: Dict[str, Any], seeds: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Filter intent contracts down to components referenced by seeds."""
    return _filter_component_map(intent_contracts, seeds)


def _normalize_observable_effects(effects: List[Any]) -> List[str]:
    """Normalize observable_effects to a list of strings for Tier2 payloads."""
    normalized: List[str] = []
    for effect in effects or []:
        if isinstance(effect, str):
            normalized.append(effect)
            continue
        if isinstance(effect, dict):
            text = effect.get("effect") or effect.get("statement") or effect.get("value")
            if text:
                normalized.append(text)
            continue
        normalized.append(str(effect))
    return normalized


def _consolidate_tier1_for_tier2(tier1: Dict[str, Any], bundle: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract driver-relevant fields from Tier1 output for Tier2.
    Omits verbose fields (facts, uncertainties, full function_summary).
    Used by legacy single-phase Tier2.
    """
    return {
        "seed_id": bundle.get("seed_id"),
        "api_category": bundle.get("api_category"),
        "trigger_surface": tier1.get("trigger_surface", {}),
        "required_inputs": tier1.get("required_inputs", []),
        "path_constraints": tier1.get("path_constraints", []),
        "observable_effects": _normalize_observable_effects(
            tier1.get("observable_effects", [])
        ),
        "observable_effects_detail": tier1.get("observable_effects", []),
        "caller_method": bundle.get("caller_method"),
        # Omit: facts, uncertainties, confidence, full function_summary
    }


def _consolidate_tier1_for_tier2_full(tier1: Dict[str, Any], bundle: Dict[str, Any]) -> Dict[str, Any]:
    """
    Preserve FULL Tier1 output for two-phase Tier2 flow.
    Phase 2A needs facts, confidence, uncertainties for evidence synthesis.

    Supports both legacy format and new method-centric format with execution_path.
    """
    result = {
        "seed_id": bundle.get("seed_id"),
        "api_category": bundle.get("api_category") or tier1.get("api_category", ""),
        "trigger_surface": tier1.get("trigger_surface", {}),
        "required_inputs": tier1.get("required_inputs", []),
        "path_constraints": tier1.get("path_constraints", []),
        "observable_effects": _normalize_observable_effects(
            tier1.get("observable_effects", [])
        ),
        "observable_effects_detail": tier1.get("observable_effects", []),
        "caller_method": bundle.get("caller_method"),
        # NOW PRESERVED for Phase 2A:
        "facts": tier1.get("facts", []),
        "uncertainties": tier1.get("uncertainties", []),
        "confidence": tier1.get("confidence", 0.0),
        "function_summary": tier1.get("function_summary", ""),
    }

    # NEW: Pass through method-centric fields when present (from tier1_from_composed)
    if "execution_path" in tier1:
        result["execution_path"] = tier1["execution_path"]
        result["sink_api"] = tier1.get("sink_api", "")
        result["required_permissions"] = tier1.get("required_permissions", [])
        result["component_context"] = tier1.get("component_context", {})
        result["reachability"] = tier1.get("reachability", {})
        result["all_constraints"] = tier1.get("path_constraints", [])
        result["all_required_inputs"] = tier1.get("required_inputs", [])

    return result


def shape_tier2_payload(
    tier2_input: Dict[str, Any],
    package_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create optimized Tier2 LLM payload.

    Removes:
    - strings_nearby (already processed by Tier1)
    - static_context.permissions (Tier1 extracted relevant ones)
    - Most of case_context (keep only rationale, tags, reachability)

    Filters:
    - FCG to app-specific methods only

    Consolidates:
    - Tier1 outputs to driver-relevant fields only
    """
    # Filter FCG to app methods only
    fcg = tier2_input.get("fcg", {})
    filtered_fcg = _filter_fcg(fcg, package_name)

    # Extract minimal static_context
    static_context = tier2_input.get("static_context", {})
    minimal_static = {
        "package_name": static_context.get("package_name"),
        "component_triggers": static_context.get("component_triggers"),
        # Omit: permissions, strings_nearby (not needed for driver synthesis)
    }

    # Consolidate seeds - keep driver-relevant fields only
    seeds = tier2_input.get("seeds", [])
    # Note: seeds already contain tier1 output and bundle info from caller
    # We keep the existing structure as the orchestrator already passes consolidated data

    # Filter component-scoped artifacts to seed-relevant components
    intent_contracts = _filter_intent_contracts(tier2_input.get("intent_contracts", {}), seeds)
    file_artifacts = _filter_component_map(tier2_input.get("file_artifacts", {}), seeds)
    log_hints = _filter_component_map(tier2_input.get("log_hints", {}), seeds)

    # Extract minimal case_context
    case_context = tier2_input.get("case_context", {})
    minimal_case = None
    if case_context:
        minimal_case = {
            "recon_rationale": case_context.get("recon_rationale"),
            "tags": case_context.get("tags"),
            "reachability": case_context.get("reachability"),
            # Omit: other fields not needed for driver
        }

    payload = {
        "case_id": tier2_input.get("case_id"),
        "primary_seed_id": tier2_input.get("primary_seed_id"),
        "seeds": seeds,
        "seed_count": tier2_input.get("seed_count"),
        "recon_context": tier2_input.get("recon_context"),
        "fcg": filtered_fcg,
        "static_context": minimal_static,
        "component_intents": tier2_input.get("component_intents"),  # Intent-filters for driver synthesis
        "intent_contracts": intent_contracts,
        "file_artifacts": file_artifacts,
        "log_hints": log_hints,
        "case_context": minimal_case,
        "flowdroid_summary": tier2_input.get("flowdroid_summary"),
    }

    return payload


def _build_flow_tier2_input(
    flow_id: str,
    seed_id: str,
    bundle: Dict[str, Any],
    tier1: Dict[str, Any],
    case_info: Dict[str, Any],
    static_ctx: Dict[str, Any],
    component_intents: Dict[str, Any],
    pkg_name: str,
) -> Dict[str, Any]:
    """Build Tier2 input for a single control flow (per-seed).

    Each seed represents one complete control flow from entry point to sink.
    The Tier2 input focuses on this specific execution path.
    """
    control_flow = bundle.get("control_flow_path", {})

    return {
        # Flow identity
        "flow_id": flow_id,
        "seed_id": seed_id,
        "package_name": pkg_name,

        # Execution path (method-by-method breakdown from Tier1)
        "execution_path": tier1.get("execution_path", []),

        # Sink API info
        "api_category": bundle.get("api_category"),
        "sink_api": bundle.get("api_signature"),
        "caller_method": bundle.get("caller_method"),

        # Component context (entry point info)
        "component_context": control_flow.get("component_context", {}),
        "reachability": control_flow.get("reachability", {}),

        # Aggregated constraints from Tier1
        "path_constraints": tier1.get("path_constraints", []),
        "required_inputs": tier1.get("required_inputs", []),
        "required_permissions": tier1.get("required_permissions", []),

        # Threat context from Recon (preserved for context, not grouping)
        "threat_category": case_info.get("category_id"),
        "threat_severity": case_info.get("recon_severity"),
        "threat_tags": case_info.get("tags", []),

        # Static context for driver synthesis
        "intent_contracts": static_ctx.get("intent_contracts", {}),
        "file_artifacts": static_ctx.get("file_artifacts", {}),
        "log_hints": static_ctx.get("log_hints", {}),
        "component_intents": component_intents,
    }


def _run_flow_tier2(
    flow_id: str,
    seed_id: str,
    bundle: Dict[str, Any],
    tier1: Dict[str, Any],
    case_info: Dict[str, Any],
    static_ctx: Dict[str, Any],
    manifest: Dict[str, Any],
    tier2a_agent: "Tier2AReasoningAgent",
    tier2b_agent: "Tier2BCommandsAgent",
    artifact_store: "ArtifactStore",
    event_logger: "EventLogger",
) -> Dict[str, Any]:
    """Run two-phase Tier2 processing for a single control flow.

    Phase 2A: Attack chain reasoning for this specific flow
    Phase 2B: Command generation based on driver requirements

    Each seed = one control flow path. Tier2 reasons about this specific
    method sequence from entry point to sink.
    """
    package_name = static_ctx.get("package_name", "")
    intent_contracts = static_ctx.get("intent_contracts", {})
    file_artifacts = static_ctx.get("file_artifacts", {})
    log_hints = static_ctx.get("log_hints", {})
    control_flow = bundle.get("control_flow_path", {})

    # Build full Tier1 data for this flow
    seed_tier1 = _consolidate_tier1_for_tier2_full(tier1, bundle)

    # Pre-validate
    validation = prevalidate_for_tier2([seed_tier1], manifest, intent_contracts)
    if validation.all_warnings:
        event_logger.log(
            "tier2.prevalidation",
            flow_id=flow_id,
            seed_id=seed_id,
            warnings_count=len(validation.all_warnings),
            summary=format_validation_summary(validation),
        )

    # Phase 2A: Reasoning for this flow
    tier2a_input = {
        "flow_id": flow_id,
        "seed_id": seed_id,
        "case_id": flow_id,  # Use flow_id as case identifier for per-flow processing
        "package_name": package_name,

        # Single flow with execution path
        "execution_path": tier1.get("execution_path", []),
        "api_category": bundle.get("api_category"),
        "sink_api": bundle.get("api_signature"),

        # Component and reachability
        "component_context": control_flow.get("component_context", {}),
        "reachability": control_flow.get("reachability", {}),

        # Aggregated from Tier1
        "path_constraints": tier1.get("path_constraints", []),
        "required_inputs": tier1.get("required_inputs", []),
        "required_permissions": tier1.get("required_permissions", []),

        # Threat context
        "threat_category": case_info.get("category_id"),
        "threat_severity": case_info.get("recon_severity"),

        # Validation status
        "validation": {
            "fully_automatable": validation.fully_automatable_seeds,
            "partially_automatable": validation.partially_automatable_seeds,
            "manual_investigation": validation.manual_investigation_seeds,
        },
    }

    with llm_context("tier2a", seed_id=seed_id):
        tier2a_result = tier2a_agent.run(tier2a_input)

    artifact_store.write_json(f"llm/tier2a/{flow_id}.json", tier2a_result.to_dict())

    # Phase 2B: Commands (per driver requirement)
    tier2b_results: List["Phase2BOutput"] = []

    for driver_req in tier2a_result.driver_requirements:
        # Build value hints for this seed
        value_hints = build_value_hints_for_seed(
            tier1_output=seed_tier1,
            intent_contracts=intent_contracts,
            file_artifacts=file_artifacts,
            log_hints=log_hints,
            manifest=manifest,
            package_name=package_name,
            component_intents=static_ctx.get("component_intents"),
        )

        with llm_context("tier2b", seed_id=seed_id):
            tier2b_result = tier2b_agent.run(
                driver_requirement=driver_req,
                value_hints=value_hints,
                seed_tier1=seed_tier1,
                package_name=package_name,
            )

        # Post-QA validation
        if tier2b_result.steps:
            exec_guidance = {
                "package_name": package_name,
                "steps": [s.to_dict() for s in tier2b_result.steps],
            }
            validated_guidance = validate_execution_guidance(
                exec_guidance,
                intent_contracts,
                file_artifacts=file_artifacts,
                log_hints=log_hints,
                package_name=package_name,
            )
            validated_steps: List["ExecutionStep"] = []
            for step_data in validated_guidance.get("steps", []) if isinstance(validated_guidance, dict) else []:
                validated_steps.append(ExecutionStep(
                    step_id=step_data.get("step_id", f"step_{len(validated_steps)}"),
                    type=step_data.get("type", "adb"),
                    description=step_data.get("description", ""),
                    command=step_data.get("command"),
                    verify=step_data.get("verify"),
                    evidence_citation=step_data.get("evidence_citation"),
                    notes=step_data.get("notes"),
                    template_id=step_data.get("template_id") or step_data.get("_template_id"),
                    template_vars=step_data.get("template_vars", {}),
                ))
            if validated_steps:
                tier2b_result.steps = validated_steps
            tier2b_result.validated = True

        tier2b_results.append(tier2b_result)
        artifact_store.write_json(
            f"llm/tier2b/{flow_id}_{driver_req.requirement_id}.json",
            tier2b_result.to_dict(),
        )

    # Merge into backward-compatible Tier2 output
    return merge_phase_outputs(tier2a_result, tier2b_results, package_name).to_dict()


def _run_two_phase_tier2(
    case_id: str,
    case_seeds_data: List[Dict[str, Any]],
    bundle_map: Dict[str, Any],
    flow_summaries: Dict[str, Any],
    static_ctx: Dict[str, Any],
    manifest: Dict[str, Any],
    tier2a_agent: Tier2AReasoningAgent,
    tier2b_agent: Tier2BCommandsAgent,
    artifact_store: ArtifactStore,
    event_logger: EventLogger,
) -> Dict[str, Any]:
    """
    DEPRECATED: Use _run_flow_tier2 instead.

    This function used case-based aggregation (multiple seeds per case).
    The new _run_flow_tier2 processes per control flow (one seed = one flow).

    Kept for backward compatibility but no longer called in main orchestration.
    """
    package_name = static_ctx.get("package_name", "")
    intent_contracts = static_ctx.get("intent_contracts", {})
    file_artifacts = static_ctx.get("file_artifacts", {})
    log_hints = static_ctx.get("log_hints", {})

    # Build Phase 2A input with full Tier1 outputs
    seeds_for_2a = []
    for seed_data in case_seeds_data:
        sid = seed_data.get("seed_id")
        bundle = bundle_map.get(sid, {})
        tier1 = flow_summaries.get(sid, {}).get("tier1", {})
        seeds_for_2a.append(_consolidate_tier1_for_tier2_full(tier1, bundle))

    # Pre-validate seeds
    validation = prevalidate_for_tier2(seeds_for_2a, manifest, intent_contracts)
    if validation.all_warnings:
        event_logger.log(
            "tier2.prevalidation",
            case_id=case_id,
            warnings_count=len(validation.all_warnings),
            summary=format_validation_summary(validation),
        )

    # Phase 2A: Reasoning
    tier2a_input = {
        "case_id": case_id,
        "package_name": package_name,
        "seeds": seeds_for_2a,
        "validation": {
            "fully_automatable": validation.fully_automatable_seeds,
            "partially_automatable": validation.partially_automatable_seeds,
            "manual_investigation": validation.manual_investigation_seeds,
        },
    }

    with llm_context("tier2a", seed_id=case_seeds_data[0].get("seed_id") if case_seeds_data else None):
        tier2a_result = tier2a_agent.run(tier2a_input)

    artifact_store.write_json(f"llm/tier2a/{case_id}.json", tier2a_result.to_dict())

    # Phase 2B: Commands (per driver requirement)
    tier2b_results: List[Phase2BOutput] = []

    for driver_req in tier2a_result.driver_requirements:
        # Get the relevant seed's Tier1 for grounded generation
        seed_id = driver_req.seed_id
        seed_tier1 = next(
            (s for s in seeds_for_2a if s.get("seed_id") == seed_id),
            seeds_for_2a[0] if seeds_for_2a else {}
        )

        # Build value hints for this seed
        value_hints = build_value_hints_for_seed(
            tier1_output=seed_tier1,
            intent_contracts=intent_contracts,
            file_artifacts=file_artifacts,
            log_hints=log_hints,
            manifest=manifest,
            package_name=package_name,
            component_intents=static_ctx.get("component_intents"),
        )

        with llm_context("tier2b", seed_id=seed_id):
            tier2b_result = tier2b_agent.run(
                driver_requirement=driver_req,
                value_hints=value_hints,
                seed_tier1=seed_tier1,
                package_name=package_name,
            )

        # Post-QA validation using existing validator
        if tier2b_result.steps:
            exec_guidance = {
                "package_name": package_name,
                "steps": [s.to_dict() for s in tier2b_result.steps],
            }
            validated_guidance = validate_execution_guidance(
                exec_guidance,
                intent_contracts,
                file_artifacts=file_artifacts,
                log_hints=log_hints,
                package_name=package_name,
            )
            validated_steps: List[ExecutionStep] = []
            for step_data in validated_guidance.get("steps", []) if isinstance(validated_guidance, dict) else []:
                validated_steps.append(ExecutionStep(
                    step_id=step_data.get("step_id", f"step_{len(validated_steps)}"),
                    type=step_data.get("type", "adb"),
                    description=step_data.get("description", ""),
                    command=step_data.get("command"),
                    verify=step_data.get("verify"),
                    evidence_citation=step_data.get("evidence_citation"),
                    notes=step_data.get("notes"),
                    template_id=step_data.get("template_id") or step_data.get("_template_id"),
                    template_vars=step_data.get("template_vars", {}),
                ))
            if validated_steps:
                tier2b_result.steps = validated_steps
            tier2b_result.validated = True

        tier2b_results.append(tier2b_result)
        artifact_store.write_json(
            f"llm/tier2b/{case_id}_{driver_req.requirement_id}.json",
            tier2b_result.to_dict()
        )

    # Merge for backward compatibility
    merged = merge_phase_outputs(tier2a_result, tier2b_results, package_name)

    return merged.to_dict()


class _noop_context:
    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

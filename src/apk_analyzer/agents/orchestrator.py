from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional

import re

from apk_analyzer.agents.recon import ReconAgent
from apk_analyzer.agents.recon_tools import ReconToolRunner
from apk_analyzer.agents.report import ReportAgent
from apk_analyzer.agents.tier1_summarizer import Tier1SummarizerAgent
from apk_analyzer.agents.tier1a_extraction import Tier1AExtractionAgent
from apk_analyzer.agents.tier1b_interpretation import Tier1BInterpretationAgent
from apk_analyzer.agents.tier1c_synthesis import Tier1CSynthesisAgent
from apk_analyzer.agents.tier1_tool_registry import Tier1ToolRegistry
from apk_analyzer.agents.tier2_intent import Tier2IntentAgent
from apk_analyzer.agents.tier2a_reasoning import Tier2AReasoningAgent
from apk_analyzer.agents.tier2b_commands import Tier2BCommandsAgent
from apk_analyzer.agents.verifier import VerifierAgent
from apk_analyzer.analyzers.context_bundle_builder import ContextBundleBuilder, build_static_context
from apk_analyzer.analyzers.dex_invocation_indexer import ApiCallSite, DexInvocationIndexer, SuspiciousApiIndex
from apk_analyzer.analyzers.jadx_extractors import extract_method_source, run_jadx
from apk_analyzer.analyzers.intent_contracts import extract_intent_contracts
from apk_analyzer.analyzers.code_artifacts import extract_file_artifacts, extract_log_hints
from apk_analyzer.analyzers.execution_guidance_validator import validate_execution_guidance
from apk_analyzer.analyzers.semantic_annotator import annotate_sliced_cfg
from apk_analyzer.analyzers.tier2_prevalidator import prevalidate_for_tier2, format_validation_summary
from apk_analyzer.analyzers.value_hints_builder import build_value_hints_for_seed
from apk_analyzer.models.tier2_phases import merge_phase_outputs, ExecutionStep, Phase2AOutput, Phase2BOutput
from apk_analyzer.analyzers.local_query import search_source_code
from apk_analyzer.analyzers.mitre_mapper import load_rules, load_technique_index, map_evidence
from apk_analyzer.analyzers.sources_sinks_subset import generate_subset
from apk_analyzer.clients.knox_client import KnoxClient
from apk_analyzer.knowledge.api_catalog import ApiCatalog
from apk_analyzer.observability.logger import EventLogger
from apk_analyzer.phase0.sensitive_api_matcher import build_sensitive_api_hits, load_callgraph
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

                llm_conf = self.settings.get("llm", {}) or {}
                llm_client = self.llm_client
                if llm_client:
                    llm_client = InstrumentedLLMClient(llm_client, artifact_store, event_logger=event_logger)

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
                        threat_indicators=(full_knox or {}).get("threat_indicators", {}),
                    )
                    tool_runner = ReconToolRunner(sensitive_hits)
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
                            event_logger.log(
                                "recon.tool_usage",
                                llm_step="recon",
                                total_tool_rounds=len(tool_history),
                                list_hits_called=list_hits_called,
                                get_hit_called=get_hit_called,
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
                        else:
                            cases = []
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
                        hits_by_id = {
                            hit.get("hit_id"): hit
                            for hit in sensitive_hits.get("hits", [])
                            if hit.get("hit_id")
                        }
                        callsites = _callsites_from_cases(cases, hits_by_id)
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
                bundles = _order_bundles_by_cases(bundles, cases)
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

                # Create Tier1 agent (no tools for first pass)
                tier1_agent = Tier1SummarizerAgent(
                    self.prompt_dir / "tier1_summarize.md",
                    llm_client,
                    model=llm_conf.get("model_tier1"),
                    tool_runner=None,
                    event_logger=event_logger,
                )

                # Create repair agent with tools (only used if first pass fails)
                tier1_repair_agent = None
                if jadx_root:
                    from apk_analyzer.agents.tier1_tools import Tier1ToolRunner
                    tier1_tool_runner = Tier1ToolRunner(jadx_root, artifact_store)
                    tier1_repair_agent = Tier1SummarizerAgent(
                        self.prompt_dir / "tier1_repair.md",
                        llm_client,
                        model=llm_conf.get("model_tier1"),
                        tool_runner=tier1_tool_runner,
                        max_tool_rounds=2,
                        event_logger=event_logger,
                    )

                verifier_agent = VerifierAgent(self.prompt_dir / "verifier.md", llm_client)
                tier2_agent = Tier2IntentAgent(
                    self.prompt_dir / "tier2_intent.md",
                    llm_client,
                    model=llm_conf.get("model_tier2"),
                    event_logger=event_logger,
                )

                # Load catalog for Tier1 (Fix 36: MUST be before tier1_split_enabled block)
                tier1_catalog = sensitive_catalog

                # Three-phase Tier1 agents (used when tier1_split_enabled=true)
                tier1_split_enabled = llm_conf.get("tier1_split_enabled", False)
                tier1a_agent = None
                tier1b_agent = None
                tier1c_agent = None
                tier1_tool_registry = None
                if tier1_split_enabled and jadx_root:
                    tier1_tool_registry = Tier1ToolRegistry(
                        store=artifact_store,
                        jadx_dir=jadx_root,
                    )
                    tier1a_agent = Tier1AExtractionAgent(
                        tool_registry=tier1_tool_registry,
                        store=artifact_store,  # Fix 35: Add missing store argument
                        sensitive_catalog=tier1_catalog,  # Fix 38: For sensitive API filtering
                    )
                    tier1b_agent = Tier1BInterpretationAgent(
                        tool_registry=tier1_tool_registry,
                        api_catalog=tier1_catalog,  # Fix 39: Pass ApiCatalog object, not .categories
                    )
                    tier1c_agent = Tier1CSynthesisAgent(
                        tool_registry=tier1_tool_registry,
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

                case_lookup = _case_lookup(cases)
                seed_summaries: Dict[str, Dict[str, Any]] = {}
                bundle_map: Dict[str, Dict[str, Any]] = {}
                verified_ids: List[str] = []
                evidence_support_index: Dict[str, Any] = {}
                verified_count = 0
                processed_count = 0

                # tier1_catalog already loaded above (Fix 36)

                repair_count = 0
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
                        # Check if three-phase Tier1 is enabled
                        if tier1_split_enabled and tier1a_agent and tier1b_agent and tier1c_agent:
                            # Three-phase Tier1 flow (Fix 19: run for ALL seeds)
                            tier1, verifier = _run_three_phase_tier1(
                                seed_id=seed_id,
                                bundle=bundle,
                                tier1a_agent=tier1a_agent,
                                tier1b_agent=tier1b_agent,
                                tier1c_agent=tier1c_agent,
                                tier1_tool_registry=tier1_tool_registry,
                                verifier_agent=verifier_agent,
                                tier1_repair_agent=tier1_repair_agent,
                                tier1_catalog=tier1_catalog,
                                jadx_root=jadx_root,
                                seed_index=seed_index,
                                artifact_store=artifact_store,
                                event_logger=event_logger,
                            )
                        else:
                            # Legacy single-phase Tier1 flow
                            # Shape Tier1 payload for token efficiency
                            tier1_payload = shape_tier1_payload(
                                bundle,
                                tier1_catalog,
                                jadx_root=jadx_root,
                                seed_index=seed_index,
                            )
                            # Pass 1: Normal Tier1 (no tools)
                            with llm_context("tier1", seed_id=seed_id):
                                tier1 = tier1_agent.run(tier1_payload)
                            artifact_store.write_json(f"llm/tier1/{seed_id}.json", tier1)

                            # Verify first pass
                            verifier = verifier_agent.run(tier1, bundle)
                            artifact_store.write_json(f"llm/verifier/{seed_id}.json", verifier)

                            # Pass 2: Repair if failed or low confidence
                            needs_repair = (
                                verifier.get("status") != "VERIFIED" or
                                tier1.get("confidence", 1.0) < 0.7
                            )
                            if needs_repair and tier1_repair_agent:
                                repair_payload = {
                                    **tier1_payload,  # Use shaped payload
                                    "previous_attempt": tier1,
                                    "verifier_feedback": verifier,
                                }
                                with llm_context("tier1_repair", seed_id=seed_id):
                                    tier1 = tier1_repair_agent.run(repair_payload)
                                artifact_store.write_json(f"llm/tier1/{seed_id}_repair.json", tier1)

                                # Re-verify after repair
                                verifier = verifier_agent.run(tier1, bundle)
                                artifact_store.write_json(f"llm/verifier/{seed_id}_repair.json", verifier)

                                repair_count += 1
                                tool_history = tier1.get("_meta", {}).get("tool_history", [])
                                event_logger.log(
                                    "tier1.repair",
                                    seed_id=seed_id,
                                    tool_rounds=len(tool_history),
                                    repair_verified=(verifier.get("status") == "VERIFIED"),
                                )

                    for idx, fact in enumerate(tier1.get("facts", [])):
                        ev_id = f"ev-{bundle['seed_id']}-{idx}"
                        evidence_support_index[ev_id] = {
                            "support_unit_ids": fact.get("support_unit_ids", []),
                            "artifact": artifact_store.relpath(f"graphs/slices/{bundle['seed_id']}.json"),
                        }

                    seed_summaries[seed_id] = {
                        "seed_id": seed_id,
                        "case_id": case_info.get("case_id"),
                        "case_priority": case_info.get("priority"),
                        "category_id": case_info.get("category_id") or bundle.get("api_category"),
                        "package_name": bundle.get("static_context", {}).get("package_name"),
                        "tier1": tier1,
                        "tier2": None,
                    }

                    phase_status = (tier1.get("phase_status") or "").lower()
                    if verifier.get("status") == "VERIFIED" and (not phase_status or phase_status == "ok"):
                        verified_count += 1
                        verified_ids.append(seed_id)

                event_logger.log(
                    "seed.summary",
                    processed_count=processed_count,
                    verified_count=verified_count,
                    repair_count=repair_count,
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

                # Group verified seeds by case_id for case-level Tier2 aggregation
                # This allows Tier2 to reason about attack chains across related seeds
                cases_with_verified_seeds: Dict[str, List[str]] = {}
                for seed_id in verified_ids:
                    case_info = case_lookup.get(seed_id, {})
                    case_id = case_info.get("case_id") or seed_id  # Fallback to seed_id
                    cases_with_verified_seeds.setdefault(case_id, []).append(seed_id)

                # Process Tier2 per case (aggregated)
                for case_id, case_seed_ids in cases_with_verified_seeds.items():
                    # Collect all Tier1 results and context for seeds in this case
                    case_seeds_data = []
                    primary_bundle = None
                    for sid in case_seed_ids:
                        bundle = bundle_map.get(sid)
                        if not bundle:
                            continue
                        if primary_bundle is None:
                            primary_bundle = bundle
                        case_seeds_data.append({
                            "seed_id": sid,
                            "tier1": _consolidate_tier1_for_tier2(seed_summaries[sid]["tier1"], bundle),
                            "api_category": bundle.get("api_category"),
                            "api_signature": bundle.get("api_signature"),
                            "caller_method": bundle.get("caller_method"),
                            "control_flow_path": bundle.get("control_flow_path"),
                        })

                    if not case_seeds_data or not primary_bundle:
                        continue

                    # Get Recon context for this case
                    recon_case_context = case_lookup.get(case_seed_ids[0], {})

                    # Build case-level Tier2 input
                    tier2_input_raw = {
                        # Case-level identifiers
                        "case_id": case_id,
                        "primary_seed_id": case_seed_ids[0],
                        # All seeds in this case with their Tier1 results
                        "seeds": case_seeds_data,
                        "seed_count": len(case_seeds_data),
                        # Recon context (rationale, severity, tags)
                        "recon_context": {
                            "rationale": recon_case_context.get("recon_rationale"),
                            "severity": recon_case_context.get("recon_severity"),
                            "severity_reasoning": recon_case_context.get("severity_reasoning"),
                            "tags": recon_case_context.get("tags"),
                        },
                        # Shared context from primary bundle
                        "fcg": primary_bundle.get("fcg_neighborhood"),
                        "static_context": primary_bundle.get("static_context"),
                        "component_intents": component_intents,  # Intent-filters for driver synthesis
                        "intent_contracts": (primary_bundle.get("static_context") or {}).get("intent_contracts"),
                        "file_artifacts": (primary_bundle.get("static_context") or {}).get("file_artifacts"),
                        "log_hints": (primary_bundle.get("static_context") or {}).get("log_hints"),
                        "case_context": primary_bundle.get("case_context"),
                        # FlowDroid results
                        "flowdroid_summary": flowdroid_summary or {},
                    }

                    # Shape Tier2 payload for token efficiency
                    package_name = (primary_bundle.get("static_context") or {}).get("package_name")
                    static_ctx = primary_bundle.get("static_context") or {}

                    # Check if two-phase Tier2 is enabled
                    if tier2_split_enabled and tier2a_agent and tier2b_agent:
                        # Two-phase flow: Phase 2A (reasoning) + Phase 2B (commands)
                        tier2 = _run_two_phase_tier2(
                            case_id=case_id,
                            case_seeds_data=case_seeds_data,
                            bundle_map=bundle_map,
                            seed_summaries=seed_summaries,
                            static_ctx=static_ctx,
                            manifest=manifest,
                            tier2a_agent=tier2a_agent,
                            tier2b_agent=tier2b_agent,
                            artifact_store=artifact_store,
                            event_logger=event_logger,
                        )
                    else:
                        # Legacy single-phase Tier2 flow
                        tier2_input = shape_tier2_payload(tier2_input_raw, package_name)

                        with llm_context("tier2", seed_id=case_seed_ids[0]):
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
                                    package_name=package_name,
                                )

                    # Save Tier2 result using case_id (or primary seed_id if same)
                    tier2_filename = case_id if case_id != case_seed_ids[0] else case_seed_ids[0]
                    artifact_store.write_json(f"llm/tier2/{tier2_filename}.json", tier2)

                    # Assign same Tier2 result to all seeds in this case
                    for sid in case_seed_ids:
                        seed_summaries[sid]["tier2"] = tier2
                        seed_summaries[sid]["tier2_case_id"] = case_id

                seed_summary_list = list(seed_summaries.values())
                mitre_rules = load_rules("config/mitre/mapping_rules.json")
                technique_index = load_technique_index("config/mitre/technique_index.json")
                mitre_candidates = map_evidence(
                    [fact for seed in seed_summary_list for fact in seed.get("tier1", {}).get("facts", [])],
                    mitre_rules,
                    technique_index,
                )

                report_payload = {
                    "analysis_id": artifact_store.analysis_id,
                    "verdict": recon_result.get("threat_level", "UNKNOWN"),
                    "summary": "Static analysis completed. LLM summaries may be partial.",
                    "seed_summaries": seed_summary_list,
                    "evidence_support_index": evidence_support_index,
                    "analysis_artifacts": {
                        "callgraph": artifact_store.relpath("graphs/callgraph.json") if callgraph_path else None,
                        "flowdroid": artifact_store.relpath("taint/flowdroid_summary.json") if flowdroid_summary else None,
                        "sensitive_api_hits": artifact_store.relpath("seeds/sensitive_api_hits.json") if sensitive_hits else None,
                        "recon": artifact_store.relpath("llm/recon.json"),
                        "entrypoint_paths": entrypoint_paths_ref,
                        "class_hierarchy": artifact_store.relpath("graphs/class_hierarchy.json") if class_hierarchy else None,
                    },
                    "mitre_candidates": mitre_candidates,
                    "driver_guidance": _build_driver_guidance(seed_summary_list),
                    "execution_guidance": _build_execution_guidance(seed_summary_list),
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


def _build_recon_payload(
    manifest: Dict[str, Any],
    sensitive_hits: Dict[str, Any],
    threat_indicators: Dict[str, Any],
    preview_limit: int = 150,
) -> Dict[str, Any]:
    hits = sensitive_hits.get("hits", []) or []
    preview_limit = min(preview_limit, len(hits))
    preview_hits = _stratified_hits_preview(hits, limit=preview_limit)
    lite_preview = [_make_lite_hit(hit) for hit in preview_hits]
    return {
        "manifest_summary": _manifest_summary(manifest),
        "callgraph_summary": sensitive_hits.get("callgraph_summary", {}),
        "sensitive_api_summary": sensitive_hits.get("summary", {}),
        "sensitive_api_hits_preview": lite_preview,
        "preview_metadata": {
            "preview_count": len(lite_preview),
            "total_count": len(hits),
            "sampling_strategy": "stratified_by_priority_with_redistribution",
            "categories_in_preview": len({hit.get("category_id") for hit in lite_preview}),
            "note": "Preview shows lite versions. Use get_hit(hit_id) for full details.",
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


def _case_lookup(cases: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Build a lookup from hit_id to case context.

    Preserves full Recon context for use in Tier1/Tier2 processing.
    """
    lookup: Dict[str, Dict[str, Any]] = {}
    for case in cases:
        priority = case.get("priority", 9999)
        evidence_hit_ids = case.get("evidence_hit_ids", []) or []
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
) -> List[Dict[str, Any]]:
    case_map = _case_lookup(cases)
    
    def _get_priority(b: Dict[str, Any]) -> int:
        p1 = case_map.get(b.get("seed_id"), {}).get("priority", 9999)
        p2 = b.get("case_context", {}).get("priority", 9999)
        return min(p1, p2)

    return sorted(bundles, key=_get_priority)


def _callsites_from_cases(
    cases: List[Dict[str, Any]],
    hits_by_id: Dict[str, Dict[str, Any]],
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
    """
    callsites: List[ApiCallSite] = []
    seen = set()
    for case in cases:
        case_id = case.get("case_id")
        priority = case.get("priority")
        evidence_hit_ids = case.get("evidence_hit_ids", []) or []

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


def _build_driver_guidance(seed_summaries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    guidance = []
    for summary in seed_summaries:
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


def _build_execution_guidance(seed_summaries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build top-level execution_guidance array from Tier2 outputs.
    One entry per case (not per seed). Deduplicates by case_id.
    """
    seen_cases: set = set()
    guidance = []
    for summary in seed_summaries:
        tier2 = summary.get("tier2") or {}
        exec_guide = tier2.get("execution_guidance")
        if not exec_guide:
            continue
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
# Tier1 Payload Shaping (Token Optimization)
# =============================================================================

# Noise patterns for string filtering (library/framework strings)
_STRING_NOISE_PATTERNS = [
    "androidx.", "kotlin", "jackson", "google.android.gms",
    "fasterxml", "apache.org", "coroutines", "java.lang",
    "org.xml", "javax.", "com.google.android.material",
]

# Dangerous permissions for fallback filtering
_DANGEROUS_PERMISSIONS = [
    "RECORD_AUDIO", "CAMERA", "READ_CONTACTS", "ACCESS_FINE_LOCATION",
    "READ_EXTERNAL_STORAGE", "SEND_SMS", "READ_SMS", "INTERNET",
    "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE",
]


def _is_network_indicator(s: str) -> bool:
    """Check if string is a potential network indicator (IP or URL)."""
    # IP address pattern
    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s):
        return True
    # URL pattern
    if s.startswith("http://") or s.startswith("https://"):
        return True
    return False


def _suspicion_score(s: str) -> int:
    """Score a string for suspiciousness (higher = more suspicious)."""
    score = 0
    s_lower = s.lower()
    # Network indicators are highly suspicious
    if _is_network_indicator(s):
        score += 100
    # Suspicious keywords
    suspicious_keywords = [
        "c2", "command", "shell", "root", "payload", "update",
        "socket", "telegram", "backdoor", "exfil", "inject",
        "decrypt", "encrypt", "base64", "exec", "runtime",
    ]
    for keyword in suspicious_keywords:
        if keyword in s_lower:
            score += 10
    # Paths are moderately suspicious
    if "/" in s and len(s) > 5:
        score += 5
    return score


def _filter_permissions(bundle: Dict[str, Any], catalog: Optional["ApiCatalog"]) -> List[str]:
    """
    Filter permissions to only those relevant to the API category.
    Uses suffix matching to handle full vs short permission names.
    """
    api_category = bundle.get("api_category", "")
    static_context = bundle.get("static_context", {})
    full_perms = static_context.get("permissions", [])

    # Get permission hints from catalog for this category
    relevant = set()
    if catalog:
        if api_category and api_category != "MULTIPLE":
            category = catalog.categories.get(api_category)
            if category:
                relevant.update(category.permission_hints or [])

        # Handle merged categories from case_context (not callsite_descriptor!)
        case_ctx = bundle.get("case_context", {}) or {}
        merged_categories = case_ctx.get("merged_categories", [])
        if not merged_categories:
            merged_categories = bundle.get("api_categories", [])

        for cat in merged_categories:
            category = catalog.categories.get(cat)
            if category:
                relevant.update(category.permission_hints or [])

    # Always include common malware permissions
    relevant.update(["INTERNET", "FOREGROUND_SERVICE"])

    def matches_hint(perm: str, hint: str) -> bool:
        """Use suffix match to handle full vs short permission names."""
        return perm.endswith(hint) or perm == hint

    # Filter to matching permissions (exact or suffix match)
    filtered = [p for p in full_perms if any(matches_hint(p, h) for h in relevant)]

    # FALLBACK: If no matches, use dangerous permissions subset
    if not filtered:
        filtered = [
            p for p in full_perms
            if any(matches_hint(p, d) for d in _DANGEROUS_PERMISSIONS)
        ][:10]

    return filtered[:10]


def _filter_strings(bundle: Dict[str, Any]) -> List[str]:
    """
    Filter strings to remove library noise and prioritize suspicious strings.
    Preserves IPs and URLs even if they match noise patterns.
    """
    static_context = bundle.get("static_context", {})
    raw = static_context.get("strings_nearby", [])

    def should_keep(s: str) -> bool:
        # Always keep network indicators (potential C2)
        if _is_network_indicator(s):
            return True
        # Filter library noise (case-insensitive)
        s_lower = s.lower()
        return not any(n.lower() in s_lower for n in _STRING_NOISE_PATTERNS)

    filtered = [s for s in raw if should_keep(s)]

    # Score and sort by suspiciousness
    scored = [(s, _suspicion_score(s)) for s in filtered]
    scored.sort(key=lambda x: -x[1])

    return [s for s, _ in scored[:50]]


def _should_include_source(bundle: Dict[str, Any], seed_index: int, max_with_source: int = 10) -> bool:
    """Determine if this seed should get JADX source."""
    # Gate 1: Priority from case_context (if present)
    case_ctx = bundle.get("case_context") or {}
    priority = case_ctx.get("priority")
    if priority is not None and priority <= 2:
        return True

    # Gate 2: Fallback - include source for top N seeds by index
    if seed_index < max_with_source:
        return True

    return False


def shape_tier1_payload(
    bundle: Dict[str, Any],
    catalog: "ApiCatalog",
    jadx_root: Optional[Path] = None,
    seed_index: int = 0,
) -> Dict[str, Any]:
    """
    Create optimized Tier1 LLM payload from full bundle.

    Excludes:
    - fcg_neighborhood (Tier2 needs it, Tier1 doesn't)
    - callsite_descriptor (raw recon data - case_context is sufficient)
    - Full static_context (replaced with filtered versions)

    Adds:
    - permissions_relevant (filtered permissions)
    - strings_filtered (filtered strings)
    - caller_method_source (JADX source for high-priority seeds)
    """
    payload = {
        "seed_id": bundle.get("seed_id"),
        "api_category": bundle.get("api_category"),
        "api_signatures": bundle.get("api_signatures", []),
        "caller_method": bundle.get("caller_method"),
        "sliced_cfg": bundle.get("sliced_cfg"),
        "branch_conditions": bundle.get("branch_conditions"),
        "control_flow_path": bundle.get("control_flow_path"),
        "case_context": bundle.get("case_context"),
        # Shaped fields
        "permissions_relevant": _filter_permissions(bundle, catalog),
        "strings_filtered": _filter_strings(bundle),
    }

    # Optionally add JADX source for high-priority seeds
    if jadx_root and jadx_root.exists() and _should_include_source(bundle, seed_index):
        caller = bundle.get("caller_method")
        if caller:
            source = extract_method_source(jadx_root, caller, max_lines=80, max_chars=2500)
            if source:
                payload["caller_method_source"] = source

    return payload


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
        # NOW PRESERVED for Phase 2A:
        "facts": tier1.get("facts", []),
        "uncertainties": tier1.get("uncertainties", []),
        "confidence": tier1.get("confidence", 0.0),
        "function_summary": tier1.get("function_summary", ""),
    }


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


def _run_two_phase_tier2(
    case_id: str,
    case_seeds_data: List[Dict[str, Any]],
    bundle_map: Dict[str, Any],
    seed_summaries: Dict[str, Any],
    static_ctx: Dict[str, Any],
    manifest: Dict[str, Any],
    tier2a_agent: Tier2AReasoningAgent,
    tier2b_agent: Tier2BCommandsAgent,
    artifact_store: ArtifactStore,
    event_logger: EventLogger,
) -> Dict[str, Any]:
    """
    Run two-phase Tier2 processing.

    Phase 2A: Attack chain reasoning
    Phase 2B: Command generation (per driver requirement)

    Returns merged Tier2 output for backward compatibility.
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
        tier1 = seed_summaries.get(sid, {}).get("tier1", {})
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


# =============================================================================
# Three-Phase Tier1 Processing (Fix 19, 27, 29, 30)
# =============================================================================


def _run_three_phase_tier1(
    seed_id: str,
    bundle: Dict[str, Any],
    tier1a_agent: Tier1AExtractionAgent,
    tier1b_agent: Tier1BInterpretationAgent,
    tier1c_agent: Tier1CSynthesisAgent,
    tier1_tool_registry: Tier1ToolRegistry,
    verifier_agent: VerifierAgent,
    tier1_repair_agent: Optional[Tier1SummarizerAgent],
    tier1_catalog: ApiCatalog,
    jadx_root: Optional[Path],
    seed_index: int,
    artifact_store: ArtifactStore,
    event_logger: EventLogger,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Run three-phase Tier1 analysis.

    Phase 1A: Structural extraction (deterministic + validation)
    Phase 1B: Semantic interpretation (behavioral claims)
    Phase 1C: Evidence synthesis (combine 1A + 1B)

    Fix 19: Run for ALL seeds with sensitive API callsites.
    Fix 27: Track unclaimed_apis for repair flow.
    Fix 29: Use ArtifactStore paths only (no AnalysisContext paths).
    Fix 30: Cache keys use run_id.

    Args:
        seed_id: The seed ID to process.
        bundle: The context bundle for this seed.
        tier1a_agent: Phase 1A agent.
        tier1b_agent: Phase 1B agent.
        tier1c_agent: Phase 1C agent.
        tier1_tool_registry: Tool registry for data access.
        verifier_agent: Verifier agent for consistency checking.
        artifact_store: Artifact store for saving outputs.
        event_logger: Event logger for telemetry.

    Returns:
        Tuple of (tier1_output, verifier_result).
    """
    from apk_analyzer.models.tier1_phases import (
        ExtractedStructure,
        ExtractionCoverage,
        InterpretedBehavior,
        PhaseStatus,
    )

    caller_method = bundle.get("caller_method", "")

    # Phase 1A: Structural Extraction
    # Fix 37: Don't pass sliced_cfg - agent reads CFG via tool_registry
    event_logger.log("tier1.phase_start", seed_id=seed_id, phase="1A")
    phase1a_error = None
    try:
        with llm_context("tier1a", seed_id=seed_id):
            extracted = tier1a_agent.run(
                seed_id=seed_id,
                caller_method=caller_method,
                # pre_extracted=None - agent will call _run_deterministic_extraction
            )
    except Exception as exc:
        phase1a_error = str(exc)
        event_logger.log(
            "tier1.phase_error",
            seed_id=seed_id,
            phase="1A",
            error=phase1a_error,
        )
        extracted = ExtractedStructure(
            seed_id=seed_id,
            api_calls=[],
            control_guards=[],
            component_hints=None,
            semantic_annotations=[],
            permissions=[],
            ambiguous_units=[],
            flagged_for_review=[f"Phase 1A failed: {phase1a_error}"],
            extraction_coverage=ExtractionCoverage.MINIMAL,
            extraction_confidence=0.0,
            phase_status=PhaseStatus.FAILED,
            status_reason="phase1a_exception",
        )

    # Save Phase 1A output
    phase1a_output = {
        "seed_id": seed_id,
        "api_calls": [
            {
                "unit_id": ac.unit_id,
                "signature": ac.signature,
                "class_name": ac.class_name,
                "method_name": ac.method_name,
                "sensitivity_source": ac.sensitivity_source,
                "sensitivity_confidence": ac.sensitivity_confidence,
            }
            for ac in extracted.api_calls
        ],
        "control_guards": [
            {"unit_id": cg.unit_id, "condition": cg.condition, "guard_type": cg.guard_type}
            for cg in extracted.control_guards
        ],
        "permissions": [
            {"permission": p.permission, "scope": p.scope, "evidence_unit_ids": p.evidence_unit_ids, "confidence": p.confidence}
            for p in extracted.permissions
        ],
        "ambiguous_units": extracted.ambiguous_units,
        "flagged_for_review": extracted.flagged_for_review,
        "extraction_coverage": extracted.extraction_coverage.value,
        "extraction_confidence": extracted.extraction_confidence,
        "phase_status": extracted.phase_status.value,
        "status_reason": extracted.status_reason,
    }
    artifact_store.write_json(f"llm/tier1a/{seed_id}.json", phase1a_output)

    event_logger.log(
        "tier1.phase_end",
        seed_id=seed_id,
        phase="1A",
        api_call_count=len(extracted.api_calls),
        ambiguous_count=len(extracted.ambiguous_units),
        coverage=extracted.extraction_coverage.value,
        status="failed" if phase1a_error else "ok",
        error=phase1a_error,
    )

    # Phase 1B: Semantic Interpretation (if any interpretation is needed)
    interpreted: InterpretedBehavior
    phase1b_error = None
    if extracted.phase_status == PhaseStatus.FAILED:
        interpreted = InterpretedBehavior(
            seed_id=seed_id,
            claims=[],
            source_lookups=[],
            unresolved=extracted.ambiguous_units,
            unclaimed_apis=[c.unit_id for c in extracted.api_calls],
            phase_status=PhaseStatus.FAILED,
            status_reason="phase1a_failed",
        )
        event_logger.log(
            "tier1.phase_skip",
            seed_id=seed_id,
            phase="1B",
            reason="phase1a_failed",
        )
    elif extracted.needs_interpretation():
        event_logger.log("tier1.phase_start", seed_id=seed_id, phase="1B")
        try:
            with llm_context("tier1b", seed_id=seed_id):
                interpreted = tier1b_agent.run(
                    seed_id=seed_id,
                    extracted=extracted,
                )
        except Exception as exc:
            phase1b_error = str(exc)
            event_logger.log(
                "tier1.phase_error",
                seed_id=seed_id,
                phase="1B",
                error=phase1b_error,
            )
            interpreted = InterpretedBehavior(
                seed_id=seed_id,
                claims=[],
                source_lookups=[],
                unresolved=extracted.ambiguous_units,
                unclaimed_apis=[c.unit_id for c in extracted.api_calls],
                phase_status=PhaseStatus.FAILED,
                status_reason="phase1b_exception",
            )

        # Save Phase 1B output
        phase1b_output = {
            "seed_id": seed_id,
            "claims": [
                {
                    "claim_id": c.claim_id,
                    "unit_id": c.unit_id,
                    "claim_type": c.claim_type,
                    "tier1_field": c.tier1_field,
                    "interpretation": c.interpretation,
                    "source_unit_ids": c.source_unit_ids,
                    "resolved_by": c.resolved_by,
                    "confidence": c.confidence,
                    "needs_investigation": c.needs_investigation,
                }
                for c in interpreted.claims
            ],
            "source_lookups": [
                {
                    "unit_id": sl.unit_id,
                    "tool_used": sl.tool_used,
                    "tool_args": sl.tool_args,
                    "success": sl.success,
                    "failure_reason": sl.failure_reason,
                }
                for sl in interpreted.source_lookups
            ],
            "unresolved": interpreted.unresolved,
            "unclaimed_apis": interpreted.unclaimed_apis,
            "phase_status": interpreted.phase_status.value,
            "status_reason": interpreted.status_reason,
        }
        artifact_store.write_json(f"llm/tier1b/{seed_id}.json", phase1b_output)

        event_logger.log(
            "tier1.phase_end",
            seed_id=seed_id,
            phase="1B",
            claim_count=len(interpreted.claims),
            unclaimed_count=len(interpreted.unclaimed_apis),
            status=interpreted.phase_status.value,
            error=phase1b_error,
        )

        # Check for unclaimed APIs and potentially repair (Fix 27)
        if interpreted.unclaimed_apis:
            event_logger.log(
                "tier1.unclaimed_apis",
                seed_id=seed_id,
                unclaimed_count=len(interpreted.unclaimed_apis),
                unclaimed_ids=interpreted.unclaimed_apis[:5],  # Log first 5
            )
    else:
        # No API calls - create empty interpretation
        interpreted = InterpretedBehavior(
            seed_id=seed_id,
            claims=[],
            source_lookups=[],
            unresolved=[],
            unclaimed_apis=[],
            phase_status=PhaseStatus.OK,
        )
        event_logger.log(
            "tier1.phase_skip",
            seed_id=seed_id,
            phase="1B",
            reason="no_api_calls",
        )

    # Phase 1C: Evidence Synthesis
    event_logger.log("tier1.phase_start", seed_id=seed_id, phase="1C")
    phase1c_error = None
    try:
        with llm_context("tier1c", seed_id=seed_id):
            tier1_output = tier1c_agent.run(
                seed_id=seed_id,
                extracted=extracted,
                interpreted=interpreted,
            )
    except Exception as exc:
        phase1c_error = str(exc)
        event_logger.log(
            "tier1.phase_error",
            seed_id=seed_id,
            phase="1C",
            error=phase1c_error,
        )
        tier1_output = {
            "seed_id": seed_id,
            "function_summary": f"Phase 1C failed: {phase1c_error}",
            "trigger_surface": {},
            "required_inputs": [],
            "path_constraints": [],
            "observable_effects": [],
            "facts": [],
            "uncertainties": [f"Phase 1C failed: {phase1c_error}"],
            "confidence": 0.0,
            "phase_status": PhaseStatus.FAILED.value,
            "extraction_coverage": extracted.extraction_coverage.value,
        }

    schema_valid = True
    try:
        validate_json(tier1_output, "config/schemas/Tier1Summary.schema.json")
    except Exception as exc:
        schema_valid = False
        event_logger.log(
            "tier1.schema_invalid",
            seed_id=seed_id,
            error=str(exc),
        )

    artifact_store.write_json(f"llm/tier1/{seed_id}.json", tier1_output)

    event_logger.log(
        "tier1.phase_end",
        seed_id=seed_id,
        phase="1C",
        effect_count=len(tier1_output.get("observable_effects", [])),
        fact_count=len(tier1_output.get("facts", [])),
        confidence=tier1_output.get("confidence", 0.0),
        status="failed" if phase1c_error else "ok",
        error=phase1c_error,
    )

    # Verify using SliceProvider interface (Fix 10)
    if bundle.get("sliced_cfg"):
        verifier_result = verifier_agent.run(tier1_output, bundle)
    else:
        verifier_result = verifier_agent.run_by_seed_id(
            tier1_output=tier1_output,
            seed_id=seed_id,
            tool_registry=tier1_tool_registry,
        )
    phase_status_value = tier1_output.get("phase_status")
    if phase_status_value and phase_status_value != PhaseStatus.OK.value:
        verifier_result["status"] = "FAILED"
        verifier_result.setdefault("repair_hint", "Tier1 phase status not OK.")
    if not schema_valid:
        verifier_result["status"] = "FAILED"
        verifier_result.setdefault("repair_hint", "Tier1 output failed schema validation.")
    artifact_store.write_json(f"llm/verifier/{seed_id}.json", verifier_result)

    event_logger.log(
        "tier1.verified",
        seed_id=seed_id,
        status=verifier_result.get("status"),
        missing_units=len(verifier_result.get("missing_unit_ids", [])),
    )

    repair_reasons = []
    if interpreted.unclaimed_apis:
        repair_reasons.append("unclaimed_apis")
    if interpreted.phase_status != PhaseStatus.OK:
        repair_reasons.append(f"phase1b_{interpreted.phase_status.value}")
    if extracted.phase_status != PhaseStatus.OK:
        repair_reasons.append(f"phase1a_{extracted.phase_status.value}")
    if verifier_result.get("status") != "VERIFIED":
        repair_reasons.append("verifier_failed")
    if tier1_output.get("confidence", 1.0) < 0.7:
        repair_reasons.append("low_confidence")
    if not schema_valid:
        repair_reasons.append("schema_invalid")

    if repair_reasons and tier1_repair_agent:
        repair_payload = shape_tier1_payload(
            bundle,
            tier1_catalog,
            jadx_root=jadx_root,
            seed_index=seed_index,
        )
        repair_payload["previous_attempt"] = tier1_output
        repair_payload["verifier_feedback"] = {
            **(verifier_result or {}),
            "phase_status": tier1_output.get("phase_status"),
            "schema_valid": schema_valid,
            "unclaimed_apis": interpreted.unclaimed_apis,
            "extraction_status": extracted.phase_status.value,
        }
        try:
            with llm_context("tier1_repair", seed_id=seed_id):
                repaired = tier1_repair_agent.run(repair_payload)
            repaired.setdefault("seed_id", seed_id)
            artifact_store.write_json(f"llm/tier1/{seed_id}_repair.json", repaired)
            if bundle.get("sliced_cfg"):
                verifier_result = verifier_agent.run(repaired, bundle)
            else:
                verifier_result = verifier_agent.run_by_seed_id(
                    tier1_output=repaired,
                    seed_id=seed_id,
                    tool_registry=tier1_tool_registry,
                )
            artifact_store.write_json(f"llm/verifier/{seed_id}_repair.json", verifier_result)
            tier1_output = repaired

            tool_history = repaired.get("_meta", {}).get("tool_history", []) if isinstance(repaired, dict) else []
            event_logger.log(
                "tier1.repair",
                seed_id=seed_id,
                repair_reasons=repair_reasons,
                tool_rounds=len(tool_history),
                repair_verified=(verifier_result.get("status") == "VERIFIED"),
            )
        except Exception as exc:
            event_logger.log(
                "tier1.repair_error",
                seed_id=seed_id,
                error=str(exc),
            )

    return tier1_output, verifier_result

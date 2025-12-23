from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional

from apk_analyzer.agents.recon import ReconAgent
from apk_analyzer.agents.recon_tools import ReconToolRunner
from apk_analyzer.agents.report import ReportAgent
from apk_analyzer.agents.tier1_summarizer import Tier1SummarizerAgent
from apk_analyzer.agents.tier2_intent import Tier2IntentAgent
from apk_analyzer.agents.verifier import VerifierAgent
from apk_analyzer.analyzers.context_bundle_builder import ContextBundleBuilder, build_static_context
from apk_analyzer.analyzers.dex_invocation_indexer import ApiCallSite, DexInvocationIndexer, SuspiciousApiIndex
from apk_analyzer.analyzers.jadx_extractors import run_jadx
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

        temp_ctx = TemporaryDirectory(prefix="jadx-") if mode == "apk-only" else _noop_context()
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

                if mode == "apk-only":
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
                static_context = build_static_context(manifest, strings)

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
                        run_soot_extractor(
                            apk_path,
                            android_platforms,
                            out_dir,
                            soot_jar,
                            cg_algo=self.settings["analysis"].get("callgraph_algo", "SPARK"),
                            k_hop=self.settings["analysis"].get("k_hop", 2),
                            target_sdk=target_sdk,
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
                        catalog = ApiCatalog.load("config/android_sensitive_api_catalog.json")
                        sensitive_hits = build_sensitive_api_hits(
                            callgraph_data,
                            catalog,
                            manifest,
                            apk_path=apk_path,
                            class_hierarchy=class_hierarchy,
                            entrypoints_override=entrypoints_override if isinstance(entrypoints_override, list) else None,
                        )
                        artifact_store.write_json("seeds/sensitive_api_hits.json", sensitive_hits)
                        artifact_store.write_json(
                            "graphs/callgraph_summary.json",
                            sensitive_hits.get("callgraph_summary", {}),
                        )
                    event_logger.stage_end(
                        "sensitive_api",
                        total_hits=sensitive_hits.get("summary", {}).get("total_hits", 0),
                        ref=artifact_store.relpath("seeds/sensitive_api_hits.json"),
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
                if sensitive_hits and sensitive_hits.get("hits"):
                    recon_payload = _build_recon_payload(
                        manifest=manifest,
                        sensitive_hits=sensitive_hits,
                        threat_indicators=(full_knox or {}).get("threat_indicators", {}),
                    )
                    tool_runner = ReconToolRunner(sensitive_hits)
                    recon_agent = ReconAgent(
                        self.prompt_dir / "recon.md",
                        llm_client,
                        model=llm_conf.get("model_recon"),
                        tool_runner=tool_runner,
                    )
                    event_logger.stage_start("recon")
                    with span("stage.recon", stage="recon"):
                        with llm_context("recon"):
                            recon_result = recon_agent.run(recon_payload)
                        artifact_store.write_json("llm/recon.json", recon_result)
                    case_count = len(recon_result.get("cases", []) or [])
                    event_logger.stage_end(
                        "recon",
                        threat_level=recon_result.get("threat_level"),
                        case_count=case_count,
                        ref=artifact_store.relpath("llm/recon.json"),
                    )
                    cases = recon_result.get("cases", []) or []
                    if not cases:
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
                    if cases and sensitive_hits:
                        hits_by_id = {
                            hit.get("hit_id"): hit
                            for hit in sensitive_hits.get("hits", [])
                            if hit.get("hit_id")
                        }
                        callsites = _callsites_from_cases(cases, hits_by_id)
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

                tier1_agent = Tier1SummarizerAgent(
                    self.prompt_dir / "tier1_summarize.md",
                    llm_client,
                    model=llm_conf.get("model_tier1"),
                )
                verifier_agent = VerifierAgent(self.prompt_dir / "verifier.md", llm_client)
                tier2_agent = Tier2IntentAgent(
                    self.prompt_dir / "tier2_intent.md",
                    llm_client,
                    model=llm_conf.get("model_tier2"),
                )
                report_agent = ReportAgent(
                    self.prompt_dir / "tier3_final.md",
                    llm_client,
                    model=llm_conf.get("model_report"),
                )

                case_lookup = _case_lookup(cases)
                seed_summaries: Dict[str, Dict[str, Any]] = {}
                bundle_map: Dict[str, Dict[str, Any]] = {}
                verified_ids: List[str] = []
                evidence_support_index: Dict[str, Any] = {}
                verified_count = 0
                processed_count = 0

                for bundle in bundles[: self.settings["analysis"].get("max_seed_count", 20)]:
                    seed_id = bundle["seed_id"]
                    case_info = case_lookup.get(seed_id, {})
                    processed_count += 1
                    bundle_map[seed_id] = bundle
                    with span("llm.seed", stage="seed_processing", seed_id=seed_id, api_category=bundle.get("api_category")):
                        with llm_context("tier1", seed_id=seed_id):
                            tier1 = tier1_agent.run(bundle)
                        artifact_store.write_json(f"llm/tier1/{seed_id}.json", tier1)
                        verifier = verifier_agent.run(tier1, bundle)
                        artifact_store.write_json(f"llm/verifier/{seed_id}.json", verifier)

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
                        "tier1": tier1,
                        "tier2": None,
                    }

                    if verifier.get("status") == "VERIFIED":
                        verified_count += 1
                        verified_ids.append(seed_id)

                event_logger.log(
                    "seed.summary",
                    processed_count=processed_count,
                    verified_count=verified_count,
                )

                flowdroid_summary = None
                if verified_ids and apk_path:
                    categories_present = {bundle_map[sid]["api_category"] for sid in verified_ids if sid in bundle_map}
                    sources_sinks_subset = generate_subset(
                        "config/SourcesAndSinks.txt",
                        artifact_store.path("taint/sources_sinks_subset.txt"),
                        categories_present,
                    )
                    flowdroid_jar = self.settings["analysis"].get("flowdroid_jar_path")
                    android_platforms_dir = self.settings["analysis"].get("android_platforms_dir")
                    if flowdroid_jar and android_platforms_dir:
                        jar_path = Path(flowdroid_jar)
                        platforms_path = Path(android_platforms_dir)
                    else:
                        jar_path = None
                        platforms_path = None
                    if jar_path and platforms_path and jar_path.exists() and platforms_path.exists():
                        with span("tool.flowdroid", tool_name="flowdroid"):
                            flowdroid_summary = run_targeted_taint_analysis(
                                apk_path,
                                sources_sinks_subset,
                                android_platforms_dir,
                                flowdroid_jar,
                                artifact_store.path("taint"),
                                timeout_sec=self.settings["analysis"].get("flowdroid_timeout_sec", 900),
                            )
                            artifact_store.write_json("taint/flowdroid_summary.json", flowdroid_summary)
                        event_logger.log(
                            "flowdroid.summary",
                            tool="flowdroid",
                            flow_count=flowdroid_summary.get("flow_count") if flowdroid_summary else 0,
                            ref=artifact_store.relpath("taint/flowdroid_summary.json"),
                        )

                for seed_id in verified_ids:
                    bundle = bundle_map.get(seed_id)
                    if not bundle:
                        continue
                    tier1 = seed_summaries[seed_id]["tier1"]
                    case_info = case_lookup.get(seed_id, {})
                    with llm_context("tier2", seed_id=seed_id):
                        tier2 = tier2_agent.run({
                            "seed_id": seed_id,
                            "tier1": tier1,
                            "fcg": bundle.get("fcg_neighborhood"),
                            "static_context": bundle.get("static_context"),
                            "case_context": bundle.get("case_context"),
                            "control_flow_path": bundle.get("control_flow_path"),
                            "flowdroid_summary": flowdroid_summary or {},
                        })
                    artifact_store.write_json(f"llm/tier2/{seed_id}.json", tier2)
                    seed_summaries[seed_id]["tier2"] = tier2

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
    preview_limit: int = 50,
) -> Dict[str, Any]:
    return {
        "manifest_summary": _manifest_summary(manifest),
        "callgraph_summary": sensitive_hits.get("callgraph_summary", {}),
        "sensitive_api_summary": sensitive_hits.get("summary", {}),
        "sensitive_api_hits_preview": _hits_preview(sensitive_hits.get("hits", []), preview_limit),
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


def _hits_preview(hits: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
    return list(hits[:limit])


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
    lookup: Dict[str, Dict[str, Any]] = {}
    for case in cases:
        priority = case.get("priority", 9999)
        for hit_id in case.get("evidence_hit_ids", []) or []:
            existing = lookup.get(hit_id)
            if existing and existing.get("priority", 9999) <= priority:
                continue
            lookup[hit_id] = {
                "case_id": case.get("case_id"),
                "priority": priority,
                "category_id": case.get("category_id"),
            }
    return lookup


def _order_bundles_by_cases(
    bundles: List[Dict[str, Any]],
    cases: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    case_map = _case_lookup(cases)
    return sorted(bundles, key=lambda b: case_map.get(b.get("seed_id"), {}).get("priority", 9999))


def _callsites_from_cases(
    cases: List[Dict[str, Any]],
    hits_by_id: Dict[str, Dict[str, Any]],
) -> List[ApiCallSite]:
    callsites: List[ApiCallSite] = []
    seen = set()
    for case in cases:
        case_id = case.get("case_id")
        priority = case.get("priority")
        for hit_id in case.get("evidence_hit_ids", []) or []:
            if hit_id in seen:
                continue
            hit = hits_by_id.get(hit_id)
            if not hit:
                continue
            seen.add(hit_id)
            caller = hit.get("caller", {}) or {}
            component_context = hit.get("component_context")
            reachability = hit.get("reachability")
            callsites.append(
                ApiCallSite(
                    seed_id=hit_id,
                    category=hit.get("category_id", "UNKNOWN"),
                    signature=normalize_signature(hit.get("signature", "")),
                    caller_method=caller.get("method") or "UNKNOWN",
                    caller_class=caller.get("class") or "UNKNOWN",
                    callsite_descriptor={
                        "hit_id": hit_id,
                        "case_id": case_id,
                        "priority": priority,
                        "source": "sensitive_api_hits",
                        "component_context": component_context,
                        "reachability": reachability,
                    },
                    confidence=1.0,
                )
            )
    return callsites


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


class _noop_context:
    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

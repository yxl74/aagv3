from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, Optional

from apk_analyzer.agents.recon import ReconAgent
from apk_analyzer.agents.report import ReportAgent
from apk_analyzer.agents.tier1_summarizer import Tier1SummarizerAgent
from apk_analyzer.agents.tier2_intent import Tier2IntentAgent
from apk_analyzer.agents.verifier import VerifierAgent
from apk_analyzer.analyzers.context_bundle_builder import ContextBundleBuilder, build_static_context
from apk_analyzer.analyzers.dex_invocation_indexer import DexInvocationIndexer
from apk_analyzer.analyzers.jadx_extractors import run_jadx
from apk_analyzer.analyzers.local_query import search_source_code
from apk_analyzer.analyzers.mitre_mapper import load_rules, load_technique_index, map_evidence
from apk_analyzer.analyzers.sources_sinks_subset import generate_subset
from apk_analyzer.clients.knox_client import KnoxClient
from apk_analyzer.tools.flowdroid_tools import run_targeted_taint_analysis
from apk_analyzer.tools.soot_tools import run_soot_extractor
from apk_analyzer.tools.static_tools import run_static_extractors
from apk_analyzer.utils.artifact_store import ArtifactStore
from apk_analyzer.utils.json_schema import validate_json


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
        artifact_store = ArtifactStore.from_inputs(
            self.settings["analysis"]["artifacts_dir"],
            apk_path=apk_path,
            knox_apk_id=knox_apk_id,
        )
        artifact_store.ensure_dir("input")
        artifact_store.ensure_dir("static")
        artifact_store.ensure_dir("seeds")
        artifact_store.ensure_dir("graphs")
        artifact_store.ensure_dir("llm")
        artifact_store.ensure_dir("taint")
        artifact_store.ensure_dir("report")

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
            )
            full_knox = knox_client.get_full_analysis(knox_apk_id)

        temp_ctx = TemporaryDirectory(prefix="jadx-") if mode == "apk-only" else _noop_context()
        with temp_ctx as tmpdir:
            static_outputs: Dict[str, Any] = {}
            manifest = {}
            if apk_path:
                static_outputs = run_static_extractors(apk_path, artifact_store)
                manifest = static_outputs.get("manifest", {})

            if mode == "apk-only":
                jadx_path = self.settings.get("analysis", {}).get("jadx_path", "jadx")
                jadx_timeout = self.settings.get("analysis", {}).get("jadx_timeout_sec", 600)
                if tmpdir:
                    jadx_root = run_jadx(apk_path, Path(tmpdir), jadx_path=jadx_path, timeout_sec=jadx_timeout)
                if jadx_root:
                    local_search_fn = lambda query, limit=10: search_source_code(jadx_root, query, limit)

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

            catalog_path = Path("config/suspicious_api_catalog.json")
            indexer = DexInvocationIndexer(catalog_path)
            suspicious_index = indexer.build_index(
                apk_id=artifact_store.analysis_id,
                apk_path=apk_path,
                knox_client=knox_client,
                local_search_fn=local_search_fn,
                artifact_store=artifact_store,
            )
            validate_json(
                artifact_store.read_json("seeds/suspicious_api_index.json"),
                "config/schemas/SuspiciousApiIndex.schema.json",
            )

            callgraph_path = None
            android_platforms = self.settings["analysis"].get("android_platforms_dir")
            soot_jar = self.settings["analysis"].get("soot_extractor_jar_path") or "java/soot-extractor/build/libs/soot-extractor.jar"
            if apk_path and android_platforms:
                out_dir = artifact_store.path("graphs")
                run_soot_extractor(
                    apk_path,
                    android_platforms,
                    out_dir,
                    soot_jar,
                    cg_algo=self.settings["analysis"].get("callgraph_algo", "SPARK"),
                    k_hop=self.settings["analysis"].get("k_hop", 2),
                )
                callgraph_path = artifact_store.path("graphs/callgraph.json")
                if callgraph_path.exists():
                    validate_json(json.loads(callgraph_path.read_text(encoding="utf-8")), "config/schemas/CallGraph.schema.json")

            context_builder = ContextBundleBuilder(artifact_store)
            bundles = context_builder.build_for_index(
                suspicious_index,
                static_context=static_context,
                callgraph_path=callgraph_path,
                k_hop=self.settings["analysis"].get("k_hop", 2),
            )

            llm_conf = self.settings.get("llm", {}) or {}
            recon_agent = ReconAgent(
                self.prompt_dir / "recon.md",
                self.llm_client,
                model=llm_conf.get("model_recon"),
            )
            tier1_agent = Tier1SummarizerAgent(
                self.prompt_dir / "tier1_summarize.md",
                self.llm_client,
                model=llm_conf.get("model_tier1"),
            )
            verifier_agent = VerifierAgent(self.prompt_dir / "verifier.md", self.llm_client)
            tier2_agent = Tier2IntentAgent(
                self.prompt_dir / "tier2_intent.md",
                self.llm_client,
                model=llm_conf.get("model_tier2"),
            )
            report_agent = ReportAgent(
                self.prompt_dir / "tier3_final.md",
                self.llm_client,
                model=llm_conf.get("model_report"),
            )

            counts: Dict[str, int] = {}
            for callsite in suspicious_index.callsites:
                counts[callsite.category] = counts.get(callsite.category, 0) + 1
            recon_payload = {
                "manifest_summary": manifest,
                "threat_indicators": (full_knox or {}).get("threat_indicators", {}),
                "suspicious_api_counts": counts,
                "context_bundle_metadata": [{"seed_id": b["seed_id"], "category": b["api_category"]} for b in bundles],
            }
            recon_result = recon_agent.run(recon_payload)
            artifact_store.write_json("llm/recon.json", recon_result)

            seed_summaries = []
            evidence_support_index: Dict[str, Any] = {}
            for bundle in bundles[: self.settings["analysis"].get("max_seed_count", 20)]:
                tier1 = tier1_agent.run(bundle)
                artifact_store.write_json(f"llm/tier1/{bundle['seed_id']}.json", tier1)
                verifier = verifier_agent.run(tier1, bundle)
                artifact_store.write_json(f"llm/verifier/{bundle['seed_id']}.json", verifier)
                if verifier.get("status") != "VERIFIED":
                    continue
                tier2 = tier2_agent.run({
                    "seed_id": bundle["seed_id"],
                    "tier1": tier1,
                    "fcg": bundle.get("fcg_neighborhood"),
                    "static_context": bundle.get("static_context"),
                })
                artifact_store.write_json(f"llm/tier2/{bundle['seed_id']}.json", tier2)

                for idx, fact in enumerate(tier1.get("facts", [])):
                    ev_id = f"ev-{bundle['seed_id']}-{idx}"
                    evidence_support_index[ev_id] = {
                        "support_unit_ids": fact.get("support_unit_ids", []),
                        "artifact": f"graphs/slices/{bundle['seed_id']}.json",
                    }

                seed_summaries.append({
                    "seed_id": bundle["seed_id"],
                    "tier1": tier1,
                    "tier2": tier2,
                })

            flowdroid_summary = None
            if seed_summaries and apk_path:
                categories_present = {b["api_category"] for b in bundles}
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
                    flowdroid_summary = run_targeted_taint_analysis(
                        apk_path,
                        sources_sinks_subset,
                        android_platforms_dir,
                        flowdroid_jar,
                        artifact_store.path("taint"),
                        timeout_sec=self.settings["analysis"].get("flowdroid_timeout_sec", 900),
                    )
                    artifact_store.write_json("taint/flowdroid_summary.json", flowdroid_summary)

            mitre_rules = load_rules("config/mitre/mapping_rules.json")
            technique_index = load_technique_index("config/mitre/technique_index.json")
            mitre_candidates = map_evidence(
                [fact for seed in seed_summaries for fact in seed.get("tier1", {}).get("facts", [])],
                mitre_rules,
                technique_index,
            )

            report_payload = {
                "analysis_id": artifact_store.analysis_id,
                "verdict": recon_result.get("threat_level", "UNKNOWN"),
                "summary": "Static analysis completed. LLM summaries may be partial.",
                "seed_summaries": seed_summaries,
                "evidence_support_index": evidence_support_index,
                "analysis_artifacts": {
                    "callgraph": "graphs/callgraph.json" if callgraph_path else None,
                    "flowdroid": "taint/flowdroid_summary.json" if flowdroid_summary else None,
                },
                "mitre_candidates": mitre_candidates,
            }
            report = report_agent.run(report_payload)
            validate_json(report, "config/schemas/ThreatReport.schema.json")
            artifact_store.write_json("report/threat_report.json", report)
            artifact_store.write_text("report/threat_report.md", json.dumps(report, indent=2))

            return report


class _noop_context:
    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

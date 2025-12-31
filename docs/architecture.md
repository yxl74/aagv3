# Architecture

This document describes the detailed architecture of the APK Malware Analysis Agent pipeline.

## Pipeline Overview

The pipeline has two modes:

- **Combined (default):** requires the local APK path + Knox APK ID.
- **APK-only:** requires the local APK path only, uses JADX to decompile into a temp dir, and falls back to local source search when Knox is unavailable.

### Identifiers

- `analysis_id` is the APK SHA-256 hash (or the Knox ID if no APK is provided).
- `run_id` is generated per run; artifacts live under `artifacts/{analysis_id}/runs/{run_id}/`.

---

## Token Optimization Architecture

The pipeline separates **stored bundles** (full data for debugging/downstream) from **LLM payloads** (optimized subsets for token efficiency).

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Token Optimization Flow                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Context Bundle (Full)              Tier1 Payload (Shaped)                   │
│  ├── seed_id                   ──►  ├── seed_id                              │
│  ├── api_category                   ├── api_category                         │
│  ├── sliced_cfg                     ├── sliced_cfg                           │
│  ├── branch_conditions              ├── branch_conditions                    │
│  ├── control_flow_path              ├── control_flow_path                    │
│  ├── case_context                   ├── case_context                         │
│  ├── static_context ────────────►   ├── permissions_relevant (filtered)     │
│  │   ├── permissions (full)         ├── strings_filtered (scored)           │
│  │   ├── strings_nearby (raw)       └── caller_method_source (JADX, gated)  │
│  │   └── ...                                                                 │
│  ├── fcg_neighborhood ──────────►   (excluded from Tier1, kept for Tier2)   │
│  └── callsite_descriptor            (excluded, case_context is sufficient)   │
│                                                                              │
│  Savings: ~25-35% tokens per Tier1 call                                      │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Tier2 Two-Phase Flow                                                        │
│                                                                              │
│  Phase 2A Input                     Phase 2A Output                          │
│  ├── seeds[].tier1 (full)      ──►  ├── intent_verdict                       │
│  │   ├── facts (preserved!)         ├── attack_chain_summary                 │
│  │   ├── confidence                 ├── evidence[] (with citations)          │
│  │   └── uncertainties              └── driver_requirements[]                │
│  └── case_context                        ├── component_name                  │
│                                          ├── trigger_method                  │
│                                          └── evidence_citations[]            │
│                                                                              │
│  Phase 2B Input                     Phase 2B Output                          │
│  ├── driver_requirement        ──►  ├── steps[] (ADB/Frida)                  │
│  ├── value_hints_bundle             │   ├── command (concrete)               │
│  │   ├── intent_extras              │   ├── verify                           │
│  │   ├── file_hints                 │   └── evidence_citation                │
│  │   └── log_hints                  ├── manual_steps[]                       │
│  ├── relevant_seed_tier1            └── automation_feasibility               │
│  └── command_templates                                                       │
│                                                                              │
│  Benefits: Cognitive separation, reduced hallucination, evidence grounding   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Tier1 Payload Shaping

- **Permission filtering**: Only permissions matching the API category's `permission_hints` from the catalog (suffix matching). Falls back to dangerous permissions if no matches.
- **String filtering**: Removes library noise (androidx, kotlin, etc.), preserves IPs/URLs, scores by suspiciousness.
- **JADX source gating**: Includes decompiled Java source for high-priority seeds (priority ≤ 2) or top 10 by index.
- **Compact JSON**: All LLM payloads use compact JSON serialization (no indentation).

### Tier2 Two-Phase Architecture

The Tier2 stage is split into two cognitive phases for maximum accuracy:

**Phase 2A: Attack Chain Reasoning** (`tier2a_reasoning.py`)
- Receives full Tier1 outputs with `facts`, `confidence`, and `uncertainties` preserved
- Synthesizes evidence across seeds to determine malicious intent
- Outputs structured `driver_requirements` with evidence citations
- Does NOT generate commands (that's Phase 2B's job)

**Phase 2B: Command Generation** (`tier2b_commands.py`)
- Receives single `driver_requirement` + `ValueHintsBundle` + relevant seed's Tier1
- Uses component-type-aware templates as guardrails (not restrictions)
- Generates concrete, grounded ADB/Frida commands
- Marks non-automatable steps in `manual_steps` list
- Integrates with `execution_guidance_validator.py` for post-QA

**Anti-Hallucination Measures**:
- **Semantic annotation**: Method-context-aware constant annotation (e.g., `setAudioSource(1)` → `setAudioSource(1 /* MIC */)`)
- **Pre-validation**: Warns/downgrades seeds with missing component names instead of blocking
- **ValueHintsBundle**: Consolidates intent extras, file hints, log hints from existing extractors
- **Template guardrails**: 23 component-type-aware templates prevent fabricated syntax

---

## Detailed Workflow Stages

### Stage A: Static Preprocess (Local APK + Knox)

- **Androguard APK parser** (`src/apk_analyzer/analyzers/static_extractors.py`): extracts manifest metadata (package, version, permissions, components, SDK) from the APK.
- **Component intent-filters** (`extract_component_intents`): extracts intent-filter data (actions, categories, data schemes) for activities, services, and receivers. Component names are normalized (`.MyService` → `com.pkg.MyService`).
- **ZIP parsing** (built-in `zipfile`): extracts ASCII strings from `classes*.dex` and assets; extracts cert blobs from `META-INF/*.RSA|*.DSA|*.EC`.
- **Knox Vision API** (`src/apk_analyzer/clients/knox_client.py`, combined mode): pulls full analysis, manifest, components, threat indicators; if present, Knox manifest overrides the local manifest.
- **Artifacts**: `static/manifest.json`, `strings.json`, `cert.json`, `component_intents.json`, `knox_full.json`, `components.json`, `permissions.json`.

### Stage A2: JADX Decompile (If Enabled)

- **JADX** (`src/apk_analyzer/analyzers/jadx_extractors.py`): decompiles APK to a temp directory for local search and Tier1 repair tool access. Runs when `analysis.jadx_enabled: true`. The temp directory is deleted after analysis.
- JADX exit code handling: JADX often exits with code 1 due to minor decompilation errors (obfuscated code, etc.) but still produces useful output. The pipeline checks for actual `.java` file output rather than relying on exit code.
- **Local search helper** (`src/apk_analyzer/analyzers/local_query.py`): scans JADX output (`.java`, `.kt`, `.xml`, `.smali`) for method-name hits; used as fallback for seeding and by the Tier1 repair agent.
- **Method body extractor** (`extract_method_source` in `jadx_extractors.py`): extracts decompiled Java source for specific methods, used by the Tier1 repair agent.
- **Code artifacts**: extracts intent extra contracts, file write hints, and log tags/messages from decompiled source.
- **Artifacts**: `static/intent_contracts.json`, `static/file_artifacts.json`, `static/log_hints.json`.

### Stage B: Graph Extraction

- **Soot extractor (Java)** (`java/soot-extractor`): builds call graph + per-method CFGs using Android platform jars.
- Entry points are derived from Android component lifecycles (Activity/Service/Receiver/Provider/Application/AccessibilityService) across application classes.
- **FlowDroid callback analyzer** (optional, enabled by default): adds framework-invoked callbacks (listeners/observers/etc.) as entrypoints. Outputs `graphs/callbacks.json` and embeds callback metadata in `graphs/callgraph.json`.
- Android jar selection uses the APK target SDK when available:
  - exact match if present,
  - otherwise nearest higher available,
  - otherwise highest available as fallback.
- Callgraph edges combine Soot callgraph edges with direct Jimple invoke edges to avoid missing framework calls.
- **Outputs**: `graphs/callgraph.json`, `graphs/cfg/*.json`, `graphs/method_index.json`, `graphs/class_hierarchy.json`, `graphs/entrypoints.json`, `graphs/callbacks.json`.

### Stage C: Dangerous API Matching (Catalog-Driven)

- **Dangerous API catalog** (`config/android_sensitive_api_catalog.json`): maps Soot signatures to categories, priorities, and tags. Includes:
  - Surveillance APIs (audio, camera, screen capture, location)
  - Data collection APIs (contacts, SMS, call log, media, clipboard)
  - Abuse patterns (accessibility, overlay, device admin)
  - C2/networking, persistence, and evasion indicators
  - DeviceAdminReceiver callbacks (onEnabled, onDisabled, onDisableRequested, etc.)
  - App launch detection (getLaunchIntentForPackage with banking app package strings)
- **Matcher** (`src/apk_analyzer/phase0/sensitive_api_matcher.py`): walks callgraph edges, matches callees to catalog signatures, maps callers to manifest components, and computes reachability from entrypoints.
- If the callgraph resolves an interface/superclass instead of the catalog class, the matcher uses `class_hierarchy.json` to accept compatible classes with the same method signature.
- Caller filtering: by default, all non-framework callers are allowed (including third-party SDKs). Set `analysis.allow_third_party_callers: false` to restrict hits to the app package.
- **Artifacts**: `seeds/sensitive_api_hits.json`.

### Stage C2: Hit Grouping & Threat Scoring

- **Hit grouping** (`_group_sensitive_hits` in `orchestrator.py`): groups sensitive API hits by caller method signature, creating method-level "groups" for analysis.
- **String extraction** (`_extract_strings_from_cfg`): extracts string literals and known field references (e.g., `Settings.ACTION_ACCESSIBILITY_SETTINGS`) from method CFGs to enhance threat detection with whitelisted string indicators.
- **Co-occurrence scoring** (`src/apk_analyzer/phase0/cooccurrence_scorer.py`): computes threat scores based on:
  - Base score: maximum weight of detected categories
  - Synergy boost: pattern-based boost when multiple categories co-occur (e.g., package install + accessibility = dropper pattern)
  - Per-level differentiation: method-level groups receive full boost (`boost_group`); class-level blocks receive 40% (`boost_block`) since distributed co-occurrence is a weaker signal
- **Code block aggregation** (`build_code_blocks`): aggregates method groups into class-level blocks for report synthesis, separating app code from library code.
- **18 research-backed patterns** detect attack chains: droppers, ODF/ATS banking trojans, OTP theft, stalkerware bundles, smishing, toll fraud, etc.
- **Artifacts**: `seeds/sensitive_api_groups.json`, `seeds/code_blocks.json`.

### Stage D: Recon + Threat Category Creation (LLM)

- **Recon agent** (`src/apk_analyzer/agents/recon.py`): consumes manifest summary + callgraph summary + dangerous API hits and returns `threat categories` for investigation.
- **Category correction**: generic APIs like `ContentResolver.query()` are disambiguated by examining caller method context (e.g., `getPhotos` → COLLECTION_FILES_MEDIA, `readContacts` → COLLECTION_CONTACTS).
- **Recon tools** (`src/apk_analyzer/agents/recon_tools.py`): LLM may call `get_hit`, `list_hits`, `get_summary`, `get_entrypoints` to refine threat categories.
- **Artifacts**: `llm/recon.json`.

### Stage E: Seeding (SuspiciousApiIndex)

- If recon threat categories exist, they are converted into a `SuspiciousApiIndex` (code blocks to investigate).
- Otherwise, **DEX invocation indexing** (`src/apk_analyzer/analyzers/dex_invocation_indexer.py`) scans DEX with Androguard and matches `config/suspicious_api_catalog.json`.
- If DEX parsing fails or yields no hits, fallback seeding uses Knox source search (combined mode) or JADX local search (apk-only mode), with lower confidence.
- **Artifacts**: `seeds/suspicious_api_index.json`.

### Stage F: Context Bundles + CFG Slices

- **Context bundle builder** (`src/apk_analyzer/analyzers/context_bundle_builder.py`): builds per-seed backward slices from Soot CFGs, extracts branch conditions, and computes k-hop callgraph neighborhoods.
- Bundles include static context (permissions, receiver triggers, string hints) and case context (priority, reachability).
- **Control-flow paths**: derives entrypoint -> sink method chains using callgraph reachability + callsite statements, and attaches branch conditions from slices.
- **Artifacts**: `graphs/slices/<seed_id>.json`, `graphs/context_bundles/<seed_id>.json`, `graphs/entrypoint_paths/<seed_id>.json`.

### Stage G: Tier1 + Verifier + Repair (LLM)

The pipeline supports two Tier1 modes: **seed-centric** (legacy) and **method-centric** (new).

#### Method-Centric Mode (`method_tier1_enabled: true`)

When `llm.method_tier1_enabled: true`, the pipeline uses a method-centric architecture that analyzes each unique method ONCE with JADX source, then statically composes seed-level analyses:

```
┌─────────────────────────────────────────────────────────────────┐
│ Method-Centric Tier1 Pipeline                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ Phase 0.5: Collect unique methods from all seed paths           │
│            → Filter out framework APIs (android.*, java.*)      │
│            → ~33 unique app methods (from 20 seeds, 53 total)   │
│                                                                 │
│ Phase 0.6: Batch JADX extraction for all unique methods         │
│            → Extract decompiled Java source in one pass         │
│                                                                 │
│ Phase 0.7: Method-Level Tier1 Analysis (PARALLELIZABLE)         │
│            → ~33 LLM calls (one per unique app method)          │
│            → Each method analyzed with its JADX source          │
│            → Results cached to disk for cross-run reuse         │
│                                                                 │
│ Phase 1: Static Composition (NO LLM)                            │
│          → For each seed, assemble method analyses              │
│          → Aggregate constraints, inputs, facts                 │
│          → Output: ComposedSeedAnalysis → legacy tier1 format   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Key components:**
- **MethodAnalysis** (`src/apk_analyzer/agents/method_tier1.py`): Dataclass for per-method analysis results
- **MethodTier1Agent**: Analyzes individual methods with JADX source using `tier1_method.md` prompt
- **MethodAnalysisCache**: Disk-based cache enabling cross-run reuse of method analyses
- **SeedComposer** (`src/apk_analyzer/agents/seed_composer.py`): Static composition of method analyses

**Benefits:**
- Every path method analyzed with JADX source (not inferred from name)
- Method analyses parallelizable (no inter-dependencies)
- Cross-run caching: subsequent runs on same APK skip already-analyzed methods
- Richer tier2 input: method-by-method execution path breakdown

**Artifacts**: `method_cache/*.json` (per-method analyses), `llm/tier1/*_composed.json`

#### Seed-Centric Mode (Legacy, Default)

- **Payload shaping** (`shape_tier1_payload` in `orchestrator.py`): optimizes context bundles before LLM calls:
  - Filters permissions to category-relevant subset (suffix matching against catalog `permission_hints`)
  - Filters strings to remove library noise, preserves IPs/URLs, scores by suspiciousness
  - Optionally includes JADX-decompiled source for high-priority seeds
  - Excludes `fcg_neighborhood` (Tier2 only) and `callsite_descriptor` (redundant with `case_context`)
- **Tier1** (`src/apk_analyzer/agents/tier1_summarizer.py`): summarizes behavior and extracts execution constraints (branch predicates, required inputs, triggers).
- **Verifier**: enforces evidence grounding against slice units and context bundles; only verified seeds advance.
- **Tier1 Repair** (`src/apk_analyzer/agents/tier1_tools.py`): if verification fails or confidence < 0.7, a repair pass runs with JADX-based tools:
  - `search_source`: searches decompiled Java source for patterns/keywords
  - `get_method_body`: extracts the full decompiled Java source of a specific method
- LLM JSON is parsed with a tolerant parser (`src/apk_analyzer/utils/llm_json.py`) and falls back to safe defaults on invalid output.
- **Artifacts**: `llm/tier1/*.json`, `llm/tier1/*_repair.json`, `llm/verifier/*.json`.

### Stage H: Targeted Taint Analysis (Optional)

> **Note**: FlowDroid taint analysis is currently disabled in the pipeline.

- **FlowDroid CLI jar** (`src/apk_analyzer/tools/flowdroid_tools.py`): runs taint analysis using a generated sources/sinks subset based on categories present in verified seeds.
- **Usage**: summary is fed into Tier2 as data-flow evidence (not required for driver paths).
- **Artifacts**: `taint/flowdroid_summary.json`.

### Stage I: Tier2 Intent + Driver Guidance (LLM)

When `llm.tier2_split_enabled: true` (default), Tier2 runs in two phases:

**Phase 2A: Attack Chain Reasoning** (`tier2a_reasoning.py`)
- **Full Tier1 preservation**: Uses `_consolidate_tier1_for_tier2_full()` to preserve `facts`, `confidence`, and `uncertainties` from all seeds
- **Evidence synthesis**: Determines `intent_verdict` (confirmed_malicious, likely_malicious, suspicious, benign, insufficient_evidence)
- **Driver requirements**: Extracts structured requirements with component name, trigger method, expected behavior, and evidence citations
- **Artifacts**: `llm/tier2a/{case_id}.json`

**Phase 2B: Command Generation** (`tier2b_commands.py`)
- Runs per `driver_requirement` from Phase 2A
- **ValueHintsBundle**: Consolidates intent_extras, file_hints, log_hints from existing extractors
- **Template guardrails**: Uses 23 component-type-aware templates (start_service, send_broadcast, grant_permission, etc.)
- **Semantic annotations**: Constants are annotated with meanings (e.g., `setAudioSource(1 /* MIC */)`)
- **Pre-validation**: Warns/downgrades seeds with missing info instead of blocking
- **Artifacts**: `llm/tier2b/{case_id}_{seed_id}.json`

**Legacy mode** (`tier2_split_enabled: false`): Uses single-phase Tier2 with the original prompt.

**Execution-ready format**: `execution_guidance` is a case-level, machine-readable format designed for consumption by a smaller execution LLM:
- Commands are complete and copy-pasteable (full package names, component names)
- ADB commands must start with `adb` or `adb shell` prefix
- Frida commands must be full executable format: `frida -U -n <pkg> -e "<js>"`
- Each step includes verification commands and expected output
- Failure handling is explicit (`on_fail`: abort/retry/skip only)

### Stage J: Reporting + MITRE Mapping

- **MITRE mapping** (`config/mitre/` + `src/apk_analyzer/analyzers/mitre_mapper.py`): maps extracted evidence to ATT&CK techniques.
- **Report** (`src/apk_analyzer/agents/report.py`): merges a small LLM delta (verdict/summary/insights) into a locally assembled report. `driver_guidance` and `execution_guidance` are copied from Tier2 outputs without LLM round-tripping.
- **Driver guidance fields** (assembled from Tier2 outputs):
  - `case_id`, `primary_seed_id`, `seed_ids_analyzed`: traceability to threat categories
  - `driver_plan`: human-readable array of executable steps with `method` (adb/frida/manual/netcat), `details` (concrete command), `targets_seeds`
  - `environment_setup`: required setup (listeners, permissions, Frida hooks)
  - `execution_checks`: how to verify the behavior was triggered
  - `execution_guidance`: machine-executable format with `prerequisites`, `steps`, `success_criteria`, and `cleanup`
- **Artifacts**: `report/threat_report.json`.

---

## Artifact Structure

All artifacts are stored under `artifacts/{analysis_id}/runs/{run_id}/`:

```
artifacts/{analysis_id}/runs/{run_id}/
├── static/
│   ├── manifest.json
│   ├── strings.json
│   ├── cert.json
│   ├── permissions.json
│   ├── components.json
│   ├── component_intents.json
│   ├── intent_contracts.json
│   ├── file_artifacts.json
│   └── log_hints.json
├── graphs/
│   ├── callgraph.json
│   ├── callgraph_summary.json
│   ├── class_hierarchy.json
│   ├── method_index.json
│   ├── entrypoints.json
│   ├── callbacks.json
│   ├── cfg/
│   │   └── <method_signature>.json
│   ├── slices/
│   │   └── <seed_id>.json
│   ├── context_bundles/
│   │   └── <seed_id>.json
│   └── entrypoint_paths/
│       └── <seed_id>.json
├── seeds/
│   ├── sensitive_api_hits.json
│   ├── sensitive_api_groups.json
│   ├── code_blocks.json
│   └── suspicious_api_index.json
├── method_cache/                          # Method-centric Tier1 (when enabled)
│   └── <method_hash>.json                 # Per-method analysis cache
├── llm/
│   ├── recon.json
│   ├── tier1/
│   │   ├── <seed_id>.json
│   │   ├── <seed_id>_repair.json
│   │   └── <seed_id>_composed.json        # Static composition output
│   ├── verifier/
│   │   └── <seed_id>.json
│   ├── tier2a/
│   │   └── <case_id>.json
│   └── tier2b/
│       └── <case_id>_<seed_id>.json
├── llm_inputs/
│   └── <stage>_<id>.txt
├── llm_outputs/
│   └── <stage>_<id>.txt
├── taint/
│   └── flowdroid_summary.json
└── report/
    └── threat_report.json
```

---

## Key Source Files

| Component | Path |
|-----------|------|
| Main entry point | `src/apk_analyzer/main.py` |
| Orchestrator | `src/apk_analyzer/agents/orchestrator.py` |
| Recon agent | `src/apk_analyzer/agents/recon.py` |
| Tier1 summarizer | `src/apk_analyzer/agents/tier1_summarizer.py` |
| Method-centric Tier1 | `src/apk_analyzer/agents/method_tier1.py` |
| Seed composer | `src/apk_analyzer/agents/seed_composer.py` |
| Tier2A reasoning | `src/apk_analyzer/agents/tier2a_reasoning.py` |
| Tier2B commands | `src/apk_analyzer/agents/tier2b_commands.py` |
| Verifier | `src/apk_analyzer/agents/verifier.py` |
| Report generator | `src/apk_analyzer/agents/report.py` |
| Sensitive API matcher | `src/apk_analyzer/phase0/sensitive_api_matcher.py` |
| Co-occurrence scorer | `src/apk_analyzer/phase0/cooccurrence_scorer.py` |
| Context bundle builder | `src/apk_analyzer/analyzers/context_bundle_builder.py` |
| LLM factory | `src/apk_analyzer/clients/llm_factory.py` |
| Soot extractor | `java/soot-extractor/` |

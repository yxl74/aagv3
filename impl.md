# APK Malware Analysis Agent — LAMD-aligned Implementation Plan (v2)

> **Purpose**: This document is an executable implementation plan for coding agents (Codex, SWE agents, etc.) to build an LLM-assisted Android APK malware analysis system using Google ADK + Vertex AI, Knox Vision API (static artifacts), and *targeted* FlowDroid taint analysis.
>
> **Core change vs v1**: Align pipeline to LAMD-style decomposition:
> 1) **Recognize suspicious/sensitive APIs deterministically** (rule catalog + DEX invocation index)
> 2) **Extract structured context** (CFG slices + Function Call Graph neighborhoods) around those seeds
> 3) Run **tiered LLM reasoning** over *structured* context, with **factual consistency verification**
> 4) Run **FlowDroid only on-demand** for end-to-end flow confirmation (targeted sources/sinks)

**Last updated**: 2025-12-21

---

## 0. Non-Goals and Constraints

### 0.1 Non-Goals
- No dynamic sandbox, VirusTotal, or external reputation/intel dependencies.
- No full-scale malware family attribution beyond **behavioral similarity hypotheses**.

### 0.2 Constraints
- Assume you have:
  - (A) an **APK path** on disk (required for Soot/FlowDroid), and/or
  - (B) a **Knox APK ID** (for static pre-analysis and decompiled code retrieval).
- Any claim in reports must be **evidence-grounded** (callsite, slice statement id, CFG/FCG reference, taint flow, manifest entry).

---

## 1. Architecture

### 1.1 LAMD-aligned multi-stage pipeline

```
APK (apk_path, optional knox_apk_id)
   |
   |  (deterministic)
   v
[Stage A] Static Preprocessing
   - Manifest / permissions / components
   - APKiD / evasion flags
   - Strings / endpoints / URLs / suspicious assets
   - (Optional) Knox “full analysis” cache
   |
   |  (deterministic, LAMD Step 1)
   v
[Stage B] Suspicious API Seed Identification
   - Build SuspiciousApiIndex (call sites + categories)
   |
   |  (deterministic, LAMD Step 2)
   v
[Stage C] Context Extraction
   - Build call graph (FCG)
   - Extract per-seed: CFG + backward slice + control predicates
   - Extract FCG k-hop neighborhood per seed
   - Emit ContextBundle(s)
   |
   |  (LLM)
   v
[Stage D] Recon Agent (triage + prioritization)
   |
   |  (LLM, Tier 1)
   v
[Stage E] Tier-1 Summarization Agent (function behavior over slices)
   |
   |  (deterministic + LLM retry loop, Tier 1.5)
   v
[Stage F] Verifier Agent (factual consistency + evidence gating)
   |
   |  (LLM, Tier 2)
   v
[Stage G] Tier-2 Intent Agent (API intent over FCG neighborhood)
   |
   |  (optional, deterministic)
   v
[Stage H] Targeted FlowDroid (confirm sensitive source → sink)
   |
   |  (LLM, Tier 3)
   v
[Stage I] Report Agent (verdict + ATT&CK mapping + dynamic test plan)
```

### 1.2 Deterministic vs LLM responsibilities

| Responsibility | Deterministic module/tool | LLM agent |
|---|---|---|
| Identify suspicious/sensitive APIs | ✅ required | ❌ |
| Extract CFG slices + FCG neighborhoods | ✅ required | ❌ |
| Summarize behavior of a function slice | ❌ | ✅ |
| Ensure summary claims match evidence | ✅ required | ✅ (retry) |
| Infer intent across call graph | ❌ | ✅ |
| Confirm flows source→sink | ✅ optional (FlowDroid) | ❌ |
| MITRE mapping | ✅ rule-assisted | ✅ narrative |

---

## 2. Artifact Model and On-Disk Cache

Create a single per-analysis directory so results are reproducible and debuggable.

```
artifacts/
  {apk_id_or_hash}/
    input/
      app.apk
      knox_full.json
    static/
      manifest.json
      permissions.json
      components.json
      strings.json
      apkid.json
      file_types.json
      embedded_code.json
    seeds/
      suspicious_api_catalog.json
      suspicious_api_index.json
    graphs/
      callgraph.json
      cfg/
        {method_sig_hash}.json
      slices/
        {seed_id}.json
      context_bundles/
        {seed_id}.json
    llm/
      recon.json
      tier1/
        {seed_id}.json
      verifier/
        {seed_id}.json
      tier2/
        {seed_id}.json
      tier3_final.json
    taint/
      sources_sinks_subset.txt
      flowdroid.xml
      flowdroid_summary.json
    report/
      threat_report.json
      threat_report.md
```

### 2.1 JSON schemas (MUST implement)

Implement JSON Schema files under `config/schemas/` and validate outputs at runtime.

Required schemas:
- `SuspiciousApiCatalog.schema.json`
- `SuspiciousApiIndex.schema.json`
- `CallGraph.schema.json`
- `Cfg.schema.json`
- `BackwardSlice.schema.json`
- `ContextBundle.schema.json`
- `Tier1Summary.schema.json`
- `VerifierResult.schema.json`
- `Tier2Intent.schema.json`
- `ThreatReport.schema.json`

---

## 3. Static Preprocessing (Stage A)

### 3.1 Inputs
- `apk_path` (required for Soot/FlowDroid)
- `knox_apk_id` (optional, but strongly recommended for additional metadata)

### 3.2 Knox Vision API integration (Python)

Keep the existing `KnoxClient` implementation pattern, but **remove/disable external verification endpoints** (VirusTotal, impersonation) unless you have them privately.

File: `src/apk_analyzer/clients/knox_client.py`

- MUST implement:
  - `get_full_analysis(apk_id)`
  - `get_manifest(apk_id)`
  - `get_permissions(apk_id)`
  - `get_components(apk_id)`
  - `get_apkid_detections(apk_id)`
  - `get_threat_indicators(apk_id)`
  - `get_file_types(apk_id)`
  - `get_native_libraries(apk_id)`
  - `search_source_code(apk_id, query, ...)`
  - `get_source_file(apk_id, file_path)`
  - `get_bytecode_methods(apk_id, class_descriptor)` (best-effort fallback)

- SHOULD implement:
  - `download_apk(apk_id) -> bytes` if your Knox deployment supports it.

### 3.3 Local static extractors (Python)

File: `src/apk_analyzer/analyzers/static_extractors.py`

Implement:
- `extract_manifest(apk_path) -> dict` (fallback to `apkanalyzer`/`aapt2` or androguard)
- `extract_strings(apk_path) -> dict`
  - URLs/domains/IPs
  - base64-ish blobs
  - suspicious keywords (e.g., "dex", "payload", "update", "socket", "telegram")
- `extract_cert_info(apk_path) -> dict`

All extracted artifacts MUST be written to `artifacts/{id}/static/*.json`.

---

## 4. Suspicious API Seed Identification (Stage B, LAMD Step 1)

### 4.1 Suspicious API catalog

Create a versioned catalog file:

`config/suspicious_api_catalog.json`

Structure (example):
```json
{
  "version": "2025-12-21",
  "categories": {
    "SENSITIVE_DATA_ACCESS": {
      "description": "APIs that read private/sensitive data",
      "signatures": [
        "<android.telephony.TelephonyManager: java.lang.String getDeviceId()>",
        "<android.accounts.AccountManager: android.accounts.Account[] getAccounts()>"
      ]
    },
    "DATA_TRANSMISSION": {
      "description": "APIs commonly used to transmit data off-device",
      "signatures": [
        "<java.net.URL: java.net.URLConnection openConnection()>",
        "<okhttp3.OkHttpClient: okhttp3.Call newCall(okhttp3.Request)>"
      ]
    },
    "DYNAMIC_CODE_LOADING": {
      "signatures": [
        "<dalvik.system.DexClassLoader: void <init>(java.lang.String,java.lang.String,java.lang.String,java.lang.ClassLoader)>",
        "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>"
      ]
    },
    "REFLECTION": {
      "signatures": [
        "<java.lang.Class: java.lang.reflect.Method getDeclaredMethod(java.lang.String,java.lang.Class[])>",
        "<java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])>"
      ]
    },
    "ACCESSIBILITY_ABUSE": {
      "signatures": [
        "<android.accessibilityservice.AccessibilityService: void onAccessibilityEvent(android.view.accessibility.AccessibilityEvent)>"
      ]
    }
  }
}
```

**Implementation rule**: Catalog signatures MUST use a Soot/FlowDroid compatible method signature format when possible.

### 4.2 Build SuspiciousApiIndex (DEX-first, source fallback)

File: `src/apk_analyzer/analyzers/dex_invocation_indexer.py`

Implement:
```python
@dataclass
class ApiCallSite:
    seed_id: str
    category: str
    signature: str               # API signature from catalog
    caller_method: str           # caller method signature
    caller_class: str
    callsite_descriptor: dict    # instruction offset or smali line or decompiled line
    confidence: float            # 0-1 (DEX match=1.0; decompiled search < 1.0)

@dataclass
class SuspiciousApiIndex:
    apk_id: str
    catalog_version: str
    callsites: list[ApiCallSite]
```

**Preferred approach**:
- Use `androguard` to parse DEX and enumerate invoke instructions.
- Match invoked method signatures against catalog signatures (normalize both).

**Fallback approach** (when DEX parse fails or for obfuscated libs):
- Use Knox `search_source_code()` queries to find textual API usage.
- Mark those callsites with lower confidence and missing offsets.

Output: `artifacts/{id}/seeds/suspicious_api_index.json`

### 4.3 Minimal normalization rules (MUST)

Implement signature normalization:
- Convert dex descriptors to dotted Java names.
- Normalize inner classes `$`.
- Normalize primitive/array types.
- Strip generic types from decompiled code.

File: `src/apk_analyzer/utils/signature_normalize.py`

---

## 5. Graph + Slice Extraction (Stage C, LAMD Step 2)

### 5.1 Build call graph (FCG) using Soot

You MUST implement a Java-based extractor (Soot is Java) and call it from Python.

Directory:
```
java/soot-extractor/
  build.gradle
  src/main/java/.../SootExtractorMain.java
```

#### 5.1.1 CLI contract (MUST)

The Java CLI MUST support:

```
java -jar soot-extractor.jar \
  --apk {apk_path} \
  --android-platforms {android_platforms_dir} \
  --out {out_dir} \
  --cg-algo SPARK|CHA \
  --k-hop 2
```

Outputs (JSON):
- `callgraph.json`
- `cfg/{method_sig_hash}.json` for all methods needed
- Optionally, `method_index.json` mapping hashes to signatures

#### 5.1.2 Call graph JSON (MUST)

`callgraph.json` structure:
```json
{
  "nodes": [{"method": "sig", "class": "L...;", "is_android_framework": false}],
  "edges": [{"caller": "sig", "callee": "sig", "callsite": {"unit_id": "..."} }],
  "metadata": {"algo": "SPARK", "generated_at": "..."}
}
```

### 5.2 Extract per-seed CFG + backward slice

For each `ApiCallSite.seed_id`:

1) Locate `caller_method` body in Soot
2) Build CFG (e.g., ExceptionalUnitGraph)
3) Identify the invoke statement unit(s) corresponding to the suspicious API callsite
4) Run **intra-procedural backward slicing** over:
   - API argument values (defs/uses)
   - base object (receiver)
   - relevant string constants/endpoints
5) Add **control predicate context**:
   - include dominating `if`/`switch` statements
   - include predicates guarding execution of the invoke statement

#### 5.2.1 Slice JSON (MUST)

File: `artifacts/{id}/graphs/slices/{seed_id}.json`

Structure:
```json
{
  "seed_id": "...",
  "api_signature": "...",
  "caller_method": "...",
  "slice": {
    "units": [
      {"unit_id": "u17", "stmt": "r2 = virtualinvoke r1.<...>()", "tags": ["DEF","USE","SEED"] }
    ],
    "edges": [{"from": "u10", "to": "u17", "type": "data_dep|control_dep"}]
  },
  "cfg_ref": "cfg/{hash}.json",
  "notes": {"slice_algo": "intra_backward_v1"}
}
```

### 5.3 Build per-seed ContextBundle (MUST)

File: `src/apk_analyzer/analyzers/context_bundle_builder.py`

For each seed, emit:
`artifacts/{id}/graphs/context_bundles/{seed_id}.json`

Structure:
```json
{
  "seed_id": "...",
  "api_category": "...",
  "api_signature": "...",
  "caller_method": "...",
  "caller_class": "...",
  "sliced_cfg": { ... },               // from slice json (inline or referenced)
  "fcg_neighborhood": {
    "k": 2,
    "callers": ["..."],
    "callees": ["..."],
    "paths": [{"from": "entry", "to": "caller_method", "path": ["..."]}]
  },
  "static_context": {
    "permissions": ["..."],
    "component_triggers": ["BOOT_COMPLETED", "..."],
    "strings_nearby": ["http://...", "..."]
  }
}
```

---

## 6. ADK Agent System (Stages D–I)

### 6.1 Model configuration

Keep the model separation, but reassign responsibilities:

- Orchestrator: Gemini Pro (coordination)
- Recon: Flash (triage & prioritization)
- Tier1 Summarizer: Flash (structured summarization)
- Verifier: Pro (consistency enforcement + mapping)
- Tier2 Intent: Pro or Flash (graph reasoning)
- Report: Pro (final synthesis + test plan)

File: `src/apk_analyzer/models/model_config.py`

### 6.2 Orchestrator Agent (protocol MUST change)

File: `src/apk_analyzer/agents/orchestrator.py`

Orchestrator MUST run phases in this order:

1. `static_preprocess(apk_path, knox_apk_id?)`
2. `build_suspicious_api_index(...)`
3. `build_context_bundles(...)`
4. Dispatch `ReconAgent` with:
   - manifest summary
   - threat indicators
   - SuspiciousApiIndex summary (counts by category)
   - ContextBundle metadata (NOT full slices)

5. For top-N prioritized seeds:
   - Dispatch `Tier1SummarizerAgent(seed_context_bundle)`
   - Dispatch `VerifierAgent(tier1_output, context_bundle)` (loop until verified or max retries)

6. For verified seeds:
   - Dispatch `Tier2IntentAgent(verified_summaries, fcg_neighborhood)`
7. If Tier2 indicates possible sensitive-data exfil and evidence is incomplete:
   - Run targeted FlowDroid
8. Dispatch `ReportAgent` with full evidence store

### 6.3 Evidence store changes (MUST)

Modify the evidence model to support **statement-level grounding**.

File: `src/apk_analyzer/models/evidence.py`

Add fields:
```python
@dataclass
class EvidenceSupport:
    artifact: str              # path in artifacts/
    unit_ids: list[str]        # statement IDs supporting the claim
    excerpt: str | None

@dataclass
class Evidence:
    ...
    supports: list[EvidenceSupport] = field(default_factory=list)
    seed_id: str | None = None
```

Rules:
- Any evidence produced by Tier1/Tier2 MUST contain at least one `EvidenceSupport`.

---

## 7. Agent Prompts (MUST rewrite)

Store prompts in `src/apk_analyzer/prompts/` and load at runtime.

### 7.1 Recon prompt (`prompts/recon.md`)

Recon MUST:
- Never search entire codebase.
- Never invent call sites.
- Only prioritize **existing seed IDs** and **context bundles**.

Output:
```json
{
  "risk_score": 0.0-1.0,
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "prioritized_seeds": [
    {
      "seed_id": "...",
      "priority": 1,
      "why": ["..."],
      "next_steps": ["TIER1_SUMMARY", "OPTIONAL_TAINT"]
    }
  ],
  "investigation_plan": ["..."]
}
```

### 7.2 Tier-1 Summarizer prompt (`prompts/tier1_summarize.md`)

Inputs: single ContextBundle.

Tier1 MUST output a **strict JSON** containing:
- `behavior_summary`
- `data_sources`
- `data_sinks`
- `suspicious_indicators`
- **facts**: a list of atomic facts, each with `support_unit_ids`

Example:
```json
{
  "seed_id": "...",
  "function_summary": "Reads SMS messages and formats them for upload.",
  "facts": [
    {
      "fact": "Queries content://sms via ContentResolver.query(...)",
      "support_unit_ids": ["u12","u13"]
    },
    {
      "fact": "POSTs data using OkHttpClient.newCall(...)",
      "support_unit_ids": ["u31"]
    }
  ],
  "uncertainties": ["..."],
  "confidence": 0.0-1.0
}
```

Hard constraint:
- If the slice does not show something, Tier1 MUST place it in `uncertainties`, not in `facts`.

### 7.3 Verifier prompt (`prompts/verifier.md`)

Verifier MUST:
1. Run `consistency_check(tier1_json, context_bundle)` tool
2. If failed, produce a **repair instruction** and request Tier1 retry with constraints:
   - "Only claim facts directly supported by these unit_ids"
3. If passed, emit:
```json
{
  "seed_id": "...",
  "status": "VERIFIED|FAILED",
  "validated_facts": [...],
  "rejected_facts": [...],
  "mitre_candidates": [{"technique_id": "...", "why": "...", "support_unit_ids": ["..."]}]
}
```

### 7.4 Tier-2 Intent prompt (`prompts/tier2_intent.md`)

Inputs:
- verified Tier1 summaries (facts + supports)
- FCG neighborhood
- manifest + permissions + triggers
- strings/endpoints

Output:
```json
{
  "seed_id": "...",
  "intent_verdict": "likely_legitimate|suspicious|likely_malicious",
  "rationale": ["..."],
  "evidence": [
    {"claim": "...", "support_unit_ids": ["..."], "fcg_refs": ["..."]}
  ],
  "taint_recommended": true,
  "taint_question": "Does SMS content reach OkHttpClient request body?"
}
```

### 7.5 Tier-3 Final judgment prompt (`prompts/tier3_final.md`)

Inputs:
- all verified evidence
- optional FlowDroid flows
- ATT&CK candidates

Output:
- `ThreatReport` JSON + Markdown summary.

---

## 8. Deterministic Factual Consistency Checker (Stage F)

File: `src/apk_analyzer/analyzers/consistency_checker.py`

### 8.1 Tool API (MUST)

Expose as ADK tool:
```python
@tool
def consistency_check(tier1_summary: dict, context_bundle: dict) -> dict:
    """Validate that every fact.support_unit_ids exists in the slice and the fact text matches the referenced statements."""
```

### 8.2 Checks (MUST implement v1)

For each fact:
- unit_ids exist in `context_bundle.sliced_cfg.slice.units`
- statement text contains at least one keyword/entity mentioned in `fact` (simple heuristic)
- if fact mentions URL/domain/IP, it must appear in `static_context.strings_nearby` or slice statements

Return:
```json
{
  "ok": true/false,
  "missing_unit_ids": [...],
  "mismatched_facts": [{"fact": "...", "reason": "..."}],
  "repair_hint": "..."
}
```

---

## 9. Targeted FlowDroid (Stage H)

### 9.1 Why targeted
Full-taint runs are slow and noisy. We only run FlowDroid when Tier2 asks a concrete flow question.

### 9.2 Generate SourcesAndSinks subset (MUST)

File: `src/apk_analyzer/analyzers/sources_sinks_subset.py`

Inputs:
- base `config/SourcesAndSinks.txt`
- suspicious api categories present
- tier2 `taint_question`

Output: `artifacts/{id}/taint/sources_sinks_subset.txt`

Rules:
- Always include standard sensitive sources (device id, sms, contacts, location) unless you want strict minimization.
- Add sinks relevant to the suspected exfil:
  - network sinks (OkHttp, HttpURLConnection, sockets)
  - SMS send sinks if SMS fraud suspected
  - file sinks if dropper suspected

### 9.3 FlowDroid runner update (MUST)

Replace `run_taint_analysis(apk_path)` with:
```python
@tool
async def run_targeted_taint_analysis(apk_path: str, sources_sinks_path: str) -> dict:
    ...
```

Outputs:
- `flowdroid.xml`
- `flowdroid_summary.json` including critical flows and call chains.

---

## 10. ATT&CK Mobile Mapping (Offline-first)

### 10.1 Maintain ATT&CK dataset locally (MUST)

Add a script:
`scripts/update_mitre_mobile_dataset.py`

It must:
- download or ingest a pinned `mobile-attack.json` (STIX) into `config/mitre/mobile-attack.json`
- build `config/mitre/technique_index.json` mapping `{technique_id -> {name,tactics}}`

### 10.2 Rule-assisted mapping (MUST)

File: `src/apk_analyzer/analyzers/mitre_mapper.py`

Inputs:
- verified evidence (with categories and indicators)
- technique_index.json
- local rules `config/mitre/mapping_rules.json`

Output:
- list of techniques with evidence IDs + unit supports

Rules must be conservative:
- If the evidence is ambiguous, output technique candidates with lower confidence.

---

## 11. Report Generation

### 11.1 ThreatReport JSON schema (MUST)

Modify the existing schema to include:
- `seed_summaries`: per seed id
- `evidence_support_index`: map evidence_id → supports
- `analysis_artifacts`: paths used

### 11.2 Dynamic test plan generation (KEEP, but evidence-driven)

The report agent must generate:
- UI sequences
- broadcast triggers
- Frida hooks

But every test step must tie back to:
- component triggers in manifest, or
- verified seed behaviors, or
- FlowDroid flows.

---

## 12. Project Structure (Updated)

```
apk-analysis-agent/
├── pyproject.toml
├── README.md
├── config/
│   ├── SourcesAndSinks.txt
│   ├── suspicious_api_catalog.json
│   ├── schemas/
│   ├── mitre/
│   │   ├── mobile-attack.json
│   │   ├── technique_index.json
│   │   └── mapping_rules.json
│   └── settings.yaml
├── java/
│   └── soot-extractor/
├── src/
│   └── apk_analyzer/
│       ├── main.py
│       ├── agents/
│       │   ├── orchestrator.py
│       │   ├── recon.py
│       │   ├── tier1_summarizer.py
│       │   ├── verifier.py
│       │   ├── tier2_intent.py
│       │   └── report.py
│       ├── analyzers/
│       │   ├── static_extractors.py
│       │   ├── dex_invocation_indexer.py
│       │   ├── context_bundle_builder.py
│       │   ├── consistency_checker.py
│       │   ├── sources_sinks_subset.py
│       │   └── mitre_mapper.py
│       ├── clients/
│       │   └── knox_client.py
│       ├── models/
│       │   ├── evidence.py
│       │   └── threat_report.py
│       ├── prompts/
│       │   ├── recon.md
│       │   ├── tier1_summarize.md
│       │   ├── verifier.md
│       │   ├── tier2_intent.md
│       │   └── tier3_final.md
│       ├── tools/
│       │   ├── knox_tools.py
│       │   ├── static_tools.py
│       │   └── flowdroid_tools.py
│       └── utils/
│           ├── signature_normalize.py
│           ├── json_schema.py
│           └── artifact_store.py
├── scripts/
│   ├── analyze_apk.py
│   ├── batch_analyze.py
│   └── update_mitre_mobile_dataset.py
└── tests/
    ├── fixtures/
    ├── test_dex_indexer.py
    ├── test_context_bundle.py
    ├── test_consistency_checker.py
    └── test_flowdroid_subset.py
```

---

## 13. Detailed Workplan (Task Breakdown)

This section is written as an execution checklist for coding agents.

### Phase 1 — Artifact store and schema validation
- [ ] Implement `ArtifactStore` (create per-run dir, write/read helpers)
- [ ] Implement `json_schema.validate(data, schema_path)`
- [ ] Add schemas under `config/schemas/` (start with permissive schemas, tighten later)

### Phase 2 — Static preprocessing
- [ ] Implement local `extract_manifest`, `extract_strings`, `extract_cert_info`
- [ ] Implement Knox fetch + cache `knox_full.json`
- [ ] Build normalized `manifest.json`, `permissions.json`, `components.json`

### Phase 3 — Suspicious API seeding (DEX-first)
- [ ] Create `config/suspicious_api_catalog.json`
- [ ] Implement `SignatureNormalizer`
- [ ] Implement `DexInvocationIndexer` using `androguard`
- [ ] Implement Knox fallback search seeding
- [ ] Emit and validate `suspicious_api_index.json`

### Phase 4 — Soot extractor (Java)
- [ ] Create `java/soot-extractor` Gradle project
- [ ] Implement CLI arg parsing
- [ ] Configure Soot for Android APK input
- [ ] Build call graph (SPARK default)
- [ ] Export `callgraph.json`
- [ ] Add API to export CFG JSON per requested method

### Phase 5 — Slice + context bundle
- [ ] For each seed, request CFG for `caller_method`
- [ ] Implement backward slice (data dep v1)
- [ ] Add control predicate approximation
- [ ] Emit `slice/{seed_id}.json`
- [ ] Build `context_bundles/{seed_id}.json`

### Phase 6 — ADK agents + orchestration
- [ ] Rewrite Orchestrator protocol to enforce Stage order
- [ ] Implement Recon agent prompt + output parsing
- [ ] Implement Tier1 summarizer prompt + output parsing
- [ ] Implement Verifier agent with retry loop (max 2 retries)
- [ ] Implement Tier2 intent agent prompt + output parsing
- [ ] Implement Report agent for JSON + markdown outputs

### Phase 7 — Consistency checker tool
- [ ] Implement `consistency_check()`
- [ ] Integrate into Verifier agent
- [ ] Add unit tests for missing/mismatched facts

### Phase 8 — Targeted FlowDroid
- [ ] Implement subset generator from Tier2 request
- [ ] Update FlowDroid runner to accept subset file
- [ ] Parse and summarize flows
- [ ] Integrate Orchestrator trigger logic

### Phase 9 — ATT&CK offline mapping
- [ ] Implement dataset updater script
- [ ] Implement `MitreMapper`
- [ ] Integrate mapping into Verifier + Report

### Phase 10 — Evaluation harness
- [ ] Add `scripts/analyze_apk.py` to run single sample end-to-end
- [ ] Add `scripts/batch_analyze.py` for datasets
- [ ] Collect metrics:
  - seeds found
  - verification pass rate
  - FlowDroid trigger rate
  - runtime breakdown per stage

---

## 14. Operational Guidelines (Quality Gates)

### 14.1 Hard gates (MUST)
- No Tier2 reasoning unless Tier1 is VERIFIED.
- No report claim without `EvidenceSupport`.
- All persisted JSON must validate against schemas.

### 14.2 Soft gates (SHOULD)
- If Recon risk is LOW and no suspicious seeds exist: stop after basic report.
- If obfuscation/packing detected: raise “INCONCLUSIVE risk” and prioritize dynamic plan.

---

## Appendix A — Environment setup

### Python dependencies
Add to `pyproject.toml`:
- `google-adk` (or internal equivalent)
- `google-cloud-aiplatform`
- `httpx`
- `pydantic`
- `jsonschema`
- `androguard` (for DEX indexing)
- `rich` (optional logging)

### Java dependencies
- Soot (via Maven/Gradle)
- Minimal JSON writer (Jackson or Gson)

### External tools
- Android platforms for Soot/FlowDroid (`$ANDROID_HOME/platforms`)
- FlowDroid command jar

---

## Appendix B — Minimal end-to-end entry point

File: `src/apk_analyzer/main.py`

Pseudo-flow:
1. Resolve `analysis_id` = sha256(apk) or knox apk_id
2. Create ArtifactStore
3. Static preprocess
4. Seeds
5. Context bundles
6. Orchestrator: agents + optional taint
7. Write `threat_report.json` and `threat_report.md`

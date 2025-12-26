# APK Malware Analysis Agent (PoC)

LLM-assisted Android APK malware analysis pipeline aligned to LAMD: deterministic preprocessing + suspicious API seeding + structured context extraction + tiered LLM reasoning with evidence gating + targeted FlowDroid taint confirmation.

## What This Implements

- Knox Vision API client for static metadata, decompiled source access, bytecode method lookup, and APK download.
- Local static extractors (manifest, strings, certs, component intent-filters) using Androguard + ZIP parsing.
- Callgraph-sensitive API matcher (catalog-driven) with reachability from Android entrypoints.
- Recon agent with tool runner to build threat categories from dangerous API hits.
- Suspicious API seeding via recon threat categories or DEX invocation indexing (Androguard 4.x tested), with Knox/JADX fallback.
- Java-based Soot extractor that exports call graph JSON and per-method CFG JSON, using component lifecycle entrypoints plus FlowDroid callback analysis (fast/default) to include framework-invoked callbacks.
- Context bundle builder with backward CFG slices, branch conditions, and k-hop callgraph neighborhoods.
- **Token-optimized LLM payloads**: Tier1 and Tier2 inputs are shaped to maximize value per token (filtered permissions, filtered strings, filtered FCG, optional JADX source).
- Tiered LLM reasoning (Recon -> Tier1 -> Verifier -> Tier1 Repair -> Tier2 -> Report) with tolerant JSON parsing and structured driver guidance output.
- Tier1 repair agent with JADX-based tool access (source lookup, method body extraction) for failed or low-confidence verifications.
- **Execution-ready driver guidance**: Tier2 output includes both human-readable `driver_plan` and machine-executable `execution_guidance` for consumption by a smaller execution LLM (e.g., Qwen 30B) with explicit commands, verification steps, and failure handling.
- Targeted FlowDroid execution via CLI jar + sources/sinks subset generation.
- MITRE Mobile ATT&CK mapping via local rules and optional dataset fetch.
- Artifacts are stored under `artifacts/{analysis_id}/runs/{run_id}/` for traceability, with per-run logs in `artifacts/{analysis_id}/observability/runs/{run_id}.jsonl`.

## Workflow

The pipeline has two modes:

- **Combined (default):** requires the local APK path + Knox APK ID.
- **APK-only (opt-in):** requires the local APK path only, uses JADX to decompile into a temp dir, and falls back to local source search when Knox is unavailable. The temp dir is deleted after analysis.

Identifiers:
- `analysis_id` is the APK SHA-256 hash (or the Knox ID if no APK is provided).
- `run_id` is generated per run; artifacts live under `artifacts/{analysis_id}/runs/{run_id}/` and logs under `artifacts/{analysis_id}/observability/runs/{run_id}.jsonl`.

### Workflow overview (no diagram)

1) Initialize the run and derive `analysis_id` + `run_id`.
2) Static preprocess:
   - Always parse the APK locally (manifest, strings, certs).
   - In combined mode, fetch Knox metadata (manifest/components/threat indicators) and let it override local manifest fields when present.
3) APK-only decompile (opt-in):
   - Decompile the APK with JADX into a temp directory and set a local search fallback (used only if DEX indexing yields no hits).
4) Graph extraction:
   - Build callgraph + per-method CFGs with Soot using Android platform jars (target SDK -> nearest higher jar selection).
   - Default callgraph algorithm is SPARK; use CHA only if you need extra coverage and can tolerate more noise.
5) Dangerous API matching:
   - Match callgraph edges against the dangerous API catalog and compute entrypoint reachability.
6) Recon + seeding:
   - Recon turns dangerous API hits into threat categories.
   - Seeding produces a `SuspiciousApiIndex` from threat categories; if none, fall back to DEX invocation indexing, then Knox/JADX search.
7) Context bundles + control-flow paths:
   - Build backward CFG slices and branch conditions per seed.
   - Derive entrypoint -> sink control-flow paths (method chain + callsite statements) and attach branch constraints.
8) Tier1 + Verifier + Repair:
   - Tier1 extracts behavior + constraints from slices.
   - Verifier filters Tier1 facts against evidence.
   - If verification fails or confidence is low, Tier1 Repair runs with JADX tool access (source lookup, method body extraction) to refine the summary.
9) Optional FlowDroid:
   - If enabled and verified seeds exist, run targeted taint analysis and pass the summary to Tier2 (data-flow evidence only).
10) Tier2:
   - Generates driver guidance grounded in the control-flow path, constraints, case context, and FlowDroid summary (if present).
11) Reporting:
   - Produce the final threat report + MITRE mappings + driver guidance.

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
│  Tier2 Input (Raw)                  Tier2 Payload (Shaped)                   │
│  ├── seeds[].tier1 (full)      ──►  ├── seeds[].tier1 (consolidated)         │
│  ├── fcg (150+ methods)             ├── fcg (app methods only, ~20)          │
│  ├── static_context (full)          ├── static_context (minimal)             │
│  │   ├── permissions                │   ├── package_name                     │
│  │   ├── strings_nearby             │   └── component_triggers               │
│  │   └── ...                        ├── case_context (minimal)               │
│  └── case_context (full)            │   ├── recon_rationale                  │
│                                     │   ├── tags                             │
│                                     │   └── reachability                     │
│                                                                              │
│  Savings: ~30-40% tokens per Tier2 call                                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Tier1 Payload Shaping

- **Permission filtering**: Only permissions matching the API category's `permission_hints` from the catalog (suffix matching). Falls back to dangerous permissions if no matches.
- **String filtering**: Removes library noise (androidx, kotlin, etc.), preserves IPs/URLs, scores by suspiciousness.
- **JADX source gating**: Includes decompiled Java source for high-priority seeds (priority ≤ 2) or top 10 by index.
- **Compact JSON**: All LLM payloads use compact JSON serialization (no indentation).

### Tier2 Payload Shaping

- **FCG filtering**: Removes library methods (androidx, android, java, kotlin), keeps only app-specific callers/callees (max 20 each).
- **Tier1 consolidation**: Extracts driver-relevant fields only (trigger_surface, required_inputs, path_constraints, observable_effects).
- **Context minimization**: Removes strings_nearby, permissions (already processed by Tier1), keeps component_triggers and reachability.

## Detailed Workflow and Tool Usage

Stage A: Static preprocess (local APK + Knox)
- **Androguard APK parser** (`src/apk_analyzer/analyzers/static_extractors.py`): extracts manifest metadata (package, version, permissions, components, SDK) from the APK.
- **Component intent-filters** (`extract_component_intents`): extracts intent-filter data (actions, categories, data schemes) for activities, services, and receivers. Component names are normalized (`.MyService` → `com.pkg.MyService`).
- **ZIP parsing** (built-in `zipfile`): extracts ASCII strings from `classes*.dex` and assets; extracts cert blobs from `META-INF/*.RSA|*.DSA|*.EC`.
- **Knox Vision API** (`src/apk_analyzer/clients/knox_client.py`, combined mode): pulls full analysis, manifest, components, threat indicators; if present, Knox manifest overrides the local manifest.
- **Artifacts**: `artifacts/{analysis_id}/runs/{run_id}/static/manifest.json`, `strings.json`, `cert.json`, `component_intents.json`, `knox_full.json`, `components.json`, `permissions.json`.

Stage A2: JADX decompile (if enabled)
- **JADX** (`src/apk_analyzer/analyzers/jadx_extractors.py`): decompiles APK to a temp directory for local search and Tier1 repair tool access. Runs for any APK analysis when `analysis.jadx_enabled: true`. The temp directory is deleted after analysis.
- JADX exit code handling: JADX often exits with code 1 due to minor decompilation errors (obfuscated code, etc.) but still produces useful output. The pipeline checks for actual `.java` file output rather than relying on exit code.
- **Local search helper** (`src/apk_analyzer/analyzers/local_query.py`): scans JADX output (`.java`, `.kt`, `.xml`, `.smali`) for method-name hits; used as fallback for seeding and by the Tier1 repair agent.
- **Method body extractor** (`extract_method_source` in `jadx_extractors.py`): extracts decompiled Java source for specific methods, used by the Tier1 repair agent to provide additional context.
- **Code artifacts**: extracts intent extra contracts, file write hints, and log tags/messages from decompiled source to improve execution guidance quality.
- **Artifacts**: `artifacts/{analysis_id}/runs/{run_id}/static/intent_contracts.json`, `static/file_artifacts.json`, `static/log_hints.json`.
- If JADX is missing or produces no output, the pipeline continues with DEX-only seeding (lower recall), no repair tools, and no code-artifact hints.

Stage B: Graph extraction
- **Soot extractor (Java)** (`java/soot-extractor`): builds call graph + per-method CFGs using Android platform jars.
- Entry points are derived from Android component lifecycles (Activity/Service/Receiver/Provider/Application/AccessibilityService) across application classes.
- **FlowDroid callback analyzer** (optional, enabled by default): adds framework-invoked callbacks (listeners/observers/etc.) as entrypoints. Outputs `graphs/callbacks.json` and embeds callback metadata in `graphs/callgraph.json`.
- Android jar selection uses the APK target SDK when available:
  - exact match if present,
  - otherwise nearest higher available,
  - otherwise highest available as fallback.
- Callgraph edges combine Soot callgraph edges with direct Jimple invoke edges to avoid missing framework calls.
- **Outputs**: `artifacts/{analysis_id}/runs/{run_id}/graphs/callgraph.json`, `graphs/cfg/*.json`, `graphs/method_index.json`, `graphs/class_hierarchy.json`, `graphs/entrypoints.json`.
- **Callback outputs**: `graphs/callbacks.json` (FlowDroid callback methods + registration sites), and `callgraph.json` metadata includes `callback_count` and `flowdroid_callbacks_enabled`.

Stage C: Dangerous API matching (catalog-driven)
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
- **Artifacts**: `artifacts/{analysis_id}/runs/{run_id}/seeds/sensitive_api_hits.json`.

Stage D: Recon + threat category creation (LLM)
- **Recon agent** (`src/apk_analyzer/agents/recon.py`): consumes manifest summary + callgraph summary + dangerous API hits and returns `threat categories` for investigation.
- **Category correction**: generic APIs like `ContentResolver.query()` are disambiguated by examining caller method context (e.g., `getPhotos` → COLLECTION_FILES_MEDIA, `readContacts` → COLLECTION_CONTACTS, not SMS).
- **Recon tools** (`src/apk_analyzer/agents/recon_tools.py`): LLM may call `get_hit`, `list_hits`, `get_summary`, `get_entrypoints` to refine threat categories.
- **Artifacts**: `artifacts/{analysis_id}/runs/{run_id}/llm/recon.json`.

Stage E: Seeding (SuspiciousApiIndex)
- If recon threat categories exist, they are converted into a `SuspiciousApiIndex` (code blocks to investigate).
- Otherwise, **DEX invocation indexing** (`src/apk_analyzer/analyzers/dex_invocation_indexer.py`) scans DEX with Androguard (4.x tested) and matches `config/suspicious_api_catalog.json`.
- If DEX parsing fails or yields no hits, fallback seeding uses Knox source search (combined mode) or JADX local search (apk-only mode), with lower confidence.
- **Artifacts**: `artifacts/{analysis_id}/runs/{run_id}/seeds/suspicious_api_index.json`.

Stage F: Context bundles + CFG slices
- **Context bundle builder** (`src/apk_analyzer/analyzers/context_bundle_builder.py`): builds per-seed backward slices from Soot CFGs, extracts branch conditions, and computes k-hop callgraph neighborhoods.
- Bundles include static context (permissions, receiver triggers, string hints) and case context (priority, reachability).
- **Control-flow paths**: derives entrypoint -> sink method chains using callgraph reachability + callsite statements, and attaches branch conditions from slices.
- **Artifacts**: `artifacts/{analysis_id}/runs/{run_id}/graphs/slices/<seed_id>.json`, `graphs/context_bundles/<seed_id>.json`, `graphs/entrypoint_paths/<seed_id>.json`, `graphs/entrypoint_paths.json`.

Stage G: Tier1 + Verifier + Repair (LLM grounding)
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
  - The repair agent receives verifier feedback and previous attempt, then produces a refined summary with tool-grounded evidence.
- LLM JSON is parsed with a tolerant parser (`src/apk_analyzer/utils/llm_json.py`) and falls back to safe defaults on invalid output.
- **Artifacts**: `artifacts/{analysis_id}/runs/{run_id}/llm/tier1/*.json`, `llm/tier1/*_repair.json`, `llm/verifier/*.json`, plus `llm_inputs/` and `llm_outputs/` for raw prompts/returns.

Stage H: Targeted taint analysis (optional)
- **FlowDroid CLI jar** (`src/apk_analyzer/tools/flowdroid_tools.py`): runs taint analysis using a generated sources/sinks subset based on categories present in verified seeds.
- **Usage**: summary is fed into Tier2 as data-flow evidence (not required for driver paths).
- **Artifacts**: `artifacts/{analysis_id}/runs/{run_id}/taint/flowdroid_summary.json`.

Stage I: Tier2 intent + driver guidance
- **Payload shaping** (`shape_tier2_payload` in `orchestrator.py`): optimizes Tier2 input:
  - Filters FCG to app-specific methods only (removes androidx, android, kotlin, java prefixes)
  - Consolidates Tier1 outputs to driver-relevant fields (trigger_surface, required_inputs, path_constraints, observable_effects)
  - Minimizes static_context (keeps package_name, component_triggers only)
  - Minimizes case_context (keeps recon_rationale, tags, reachability only)
- **Tier2**: produces driver guidance (ADB/UI Automator/Frida-friendly) using shaped Tier1 + control-flow paths + filtered static context + FlowDroid summary (if present).
- **Execution-ready format**: `execution_guidance` is a case-level, machine-readable format designed for consumption by a smaller execution LLM (e.g., Qwen 30B):
  - Commands are complete and copy-pasteable (full package names, component names)
  - ADB commands must start with `adb` or `adb shell` prefix
  - Frida commands must be full executable format: `frida -U -n <pkg> -e "<js>"`
  - Each step includes verification commands and expected output (no placeholder commands)
  - Failure handling is explicit (`on_fail`: abort/retry/skip only)
  - Assumes full device control (Samsung engineering device with OEM access)
- **driver_plan vs execution_guidance**: `driver_plan` is for human/UI consumption; `execution_guidance` is the machine-executable format with case_id, seed_ids, prerequisites, steps, success_criteria, and cleanup.
- **Artifacts**: `artifacts/{analysis_id}/runs/{run_id}/llm/tier2/*.json`.

Stage J: Reporting + MITRE mapping
- **MITRE mapping** (`config/mitre/` + `src/apk_analyzer/analyzers/mitre_mapper.py`): maps extracted evidence to ATT&CK techniques.
- **Report** (`src/apk_analyzer/agents/report.py`): synthesizes final threat report with structured `driver_guidance` for dynamic analysis automation.
- **Driver guidance fields**: each Tier2 output includes:
  - `case_id`, `primary_seed_id`, `seed_ids_analyzed`: traceability to threat categories
  - `driver_plan`: human-readable array of executable steps with `method` (adb/frida/manual/netcat), `details` (concrete command), `targets_seeds`
  - `environment_setup`: required setup (listeners, permissions, Frida hooks)
  - `execution_checks`: how to verify the behavior was triggered
  - `execution_guidance`: machine-executable format with `prerequisites`, `steps` (each with `command`, `verify`, `on_fail`, `timeout_sec`), `success_criteria`, and `cleanup`
- **Artifacts**: `artifacts/{analysis_id}/runs/{run_id}/report/threat_report.json`.

## Repo Layout

- `src/apk_analyzer/`: Python pipeline and agent logic
  - `agents/`: LLM agents (recon, tier1, tier1_tools, tier2, verifier, report)
  - `analyzers/`: static analyzers (jadx_extractors, context_bundle_builder, etc.)
  - `prompts/`: LLM prompt templates (recon.md, tier1_summarize.md, tier1_repair.md, tier2_intent.md, tier3_final.md)
- `java/soot-extractor/`: Java Soot extractor (Gradle)
- `config/`: settings, schemas, suspicious API catalogs, SourcesAndSinks, MITRE mapping
- `config/android_sensitive_api_catalog.json`: catalog-driven dangerous API definitions for recon (includes DeviceAdminReceiver, banking app detection, etc.)
- `config/suspicious_api_catalog.json`: fallback catalog for DEX-based seeding
- `scripts/`: entrypoints and helpers
- `server/`: FastAPI observability UI (runs at `http://localhost:8000`)
- `tests/`: unit tests
- `FlowDroid/`: upstream FlowDroid repo (for CLI build)

## Requirements (Local)

- Python >= 3.10
- JDK 17 (Soot extractor + FlowDroid)
- Android SDK platforms directory (for Soot/FlowDroid)
- Maven + Gradle (to build FlowDroid CLI jar and Soot extractor)

## Quickstart (Local)

1) Install Python deps:

```bash
python -m pip install -r requirements.txt
export PYTHONPATH="$(pwd)/src"
```

Optional (instead of setting `PYTHONPATH`):

```bash
python -m pip install .
```

2) Build FlowDroid CLI jar (required for Soot callback analysis):

```bash
mvn -f FlowDroid/pom.xml -pl soot-infoflow-cmd -am package -DskipTests
```

This produces `FlowDroid/soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar`, which the Soot extractor uses at build time.

3) Build the Soot extractor:

```bash
gradle -p java/soot-extractor jar
```

4) Configure `config/settings.yaml`:

- `analysis.android_platforms_dir` should point to your Android SDK `platforms/` directory.
- `analysis.flowdroid_jar_path` should point to `FlowDroid/soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar`.
- `analysis.soot_extractor_jar_path` should point to `java/soot-extractor/build/libs/soot-extractor.jar`.
- `analysis.flowdroid_callbacks_enabled` enables FlowDroid callback analysis for entrypoints (default: true).
- `analysis.flowdroid_callbacks_mode` controls callback analysis precision: `fast` (higher coverage) or `default` (more conservative).

5) Run analysis (default combined mode requires both APK path and Knox APK ID):

```bash
python -m apk_analyzer.main --apk /path/to/app.apk --knox-id <apk_id>
```

APK-only mode (opt-in):

```bash
python -m apk_analyzer.main --mode apk-only --apk /path/to/app.apk
```

Artifacts are written under `artifacts/{analysis_id}/runs/{run_id}/` (the same APK hash yields the same `analysis_id`, while each run gets a new `run_id`).

## Docker Setup (Recommended for FlowDroid/Soot)

Docker provides a consistent Ubuntu + JDK + Android SDK environment with Android platforms 25-36 preinstalled.

### First-time setup

1) Initialize submodules (FlowDroid):

```bash
git submodule update --init --recursive
```

2) Build the Docker image:

```bash
docker compose build
```

3) Bootstrap toolchain inside the container (Python deps + FlowDroid jar + Soot extractor):

```bash
docker compose run --rm aag ./scripts/docker_bootstrap.sh
```

The bootstrap script builds the FlowDroid fat jar first (used as a dependency by the Soot extractor), then builds `soot-extractor.jar`.

By default this builds a **release** FlowDroid jar (v2.14.1) in a temp dir to avoid snapshot dependency issues.
To build from the submodule instead:

```bash
docker compose run --rm \
  -e FLOWDROID_BUILD_MODE=source \
  aag ./scripts/docker_bootstrap.sh
```

To override the release tag used for the temp build:

```bash
docker compose run --rm \
  -e FLOWDROID_TAG=v2.14.1 \
  aag ./scripts/docker_bootstrap.sh
```

### Run analysis (Docker)

Place APKs inside the repo (or mount a folder) so they are visible under `/workspace`:

```bash
cp /path/to/app.apk ./data/app.apk
```

APK + Knox ID:

```bash
docker compose run --rm aag \
  python -m apk_analyzer.main --apk /workspace/path/to/app.apk --knox-id <apk_id>
```

APK-only mode (JADX-based):

```bash
docker compose run --rm aag \
  python -m apk_analyzer.main --mode apk-only --apk /workspace/path/to/app.apk
```

Interactive shell:

```bash
docker compose run --rm aag
```

## Telemetry UI (Grafana + Tempo + Loki)

The project ships a Docker-based telemetry stack so you can inspect agent progress, LLM I/O, and tool/API spans in a browser.

### Start the UI stack

```bash
docker compose up -d grafana tempo loki otel-collector
```

### Enable telemetry in settings

Edit `config/settings.yaml`:

```yaml
telemetry:
  enabled: true
  service_name: "apk-analysis-agent"
  otlp_endpoint: "http://otel-collector:4317"
  otlp_insecure: true
```

### Run an analysis (emits traces)

```bash
docker compose run --rm aag \
  python -m apk_analyzer.main --mode apk-only --apk /workspace/path/to/app.apk
```

### Open Grafana and view traces

1) Open `http://localhost:3000` (Grafana).
2) Navigate to **Explore** -> select **Tempo** datasource.
3) Filter by attributes like:
   - `analysis_id`
   - `run_id`
   - `stage`
   - `tool_name`
4) For LLM calls, span events include:
   - `llm.input` -> `artifacts/{analysis_id}/runs/{run_id}/llm_inputs/...`
   - `llm.output` -> `artifacts/{analysis_id}/runs/{run_id}/llm_outputs/...`

Notes:
- Tempo stores traces; Loki is provisioned but log export is not enabled yet.
- If you change `requirements.txt` or telemetry config files, rebuild the image with `docker compose build`.

## Run Observability UI (FastAPI)

This UI is purpose-built for debugging the pipeline: it shows **seeding details, recon output, Soot stats, entrypoint paths, slice counts, Knox API calls, tool invocations, and exact LLM prompts/returns** per run.

### Features

- **Live SSE streaming**: Real-time event updates via Server-Sent Events
- **Progress bar**: Shows overall pipeline progress with glowing indicator when stages are running
- **Stage animations**: Running stages pulse, completed stages flash green
- **Event animations**: New events slide in with blue highlight
- **Auto-reconnect**: Exponential backoff (1s, 2s, 4s... max 30s) with polling fallback
- **Connection status**: Visual indicator showing Connected/Reconnecting/Polling/Disconnected

### Start the UI server

```bash
docker compose up -d obs-ui
```

To restart after code changes:

```bash
docker compose restart obs-ui
```

### Run an analysis (emits run ledger)

```bash
docker compose run --rm aag \
  python -m apk_analyzer.main --mode apk-only --apk /workspace/path/to/app.apk
```

### Open the UI

- **Run list**: `http://localhost:8000/runs` - Live-updating list of all analysis runs
- **Run details**: Click an analysis/run ID to view:
  - Stage timeline with live progress
  - Execution flow (all events with filtering)
  - LLM I/O table
  - API/tool events table
  - Direct links to artifacts

Each run writes its own `observability/runs/<run_id>.jsonl` log, so reruns of the same APK no longer mix trace events.
Artifacts are linked directly (e.g. `runs/<run_id>/llm_inputs/`, `runs/<run_id>/llm_outputs/`, `runs/<run_id>/graphs/slices/`, `runs/<run_id>/graphs/entrypoint_paths/`) so you can inspect the exact payloads.

### Rebuild after FlowDroid changes

```bash
docker compose run --rm aag \
  mvn -f FlowDroid/pom.xml -pl soot-infoflow-cmd -am package -DskipTests
```

### Rebuild after Soot extractor changes

```bash
docker compose run --rm aag \
  gradle -p java/soot-extractor jar
```

Notes:
- The repo is mounted at `/workspace`.
- `ANDROID_SDK_ROOT` is set to `/opt/android-sdk`, and `analysis.android_platforms_dir` auto-resolves to `/opt/android-sdk/platforms` if unset.
- `jadx` is preinstalled at `/opt/jadx/bin/jadx` and available on `PATH`.
- `KNOX_BASE_URL` defaults to `http://105.145.72.82:8081/api/v1` in `docker-compose.yml` and can be overridden via env.
- Artifacts are written to `/workspace/artifacts/{analysis_id}/runs/{run_id}/` on the host.

## Input Requirements

Default (combined) mode requires both:
- `--apk` path on disk
- `--knox-id` (Knox APK ID)

APK-only mode requires:
- `--apk` path on disk
- `--mode apk-only`

## Configuration

Key settings live in `config/settings.yaml`:

- `knox.base_url`: Knox Vision API base URL.
- `analysis.artifacts_dir`: Base artifacts folder (default `artifacts/`).
- `analysis.android_platforms_dir`: Android SDK platforms folder.
- `analysis.flowdroid_jar_path`: FlowDroid CLI jar path.
- `analysis.soot_extractor_jar_path`: Soot extractor jar path.
- `analysis.jadx_path`: JADX binary or jar (used when `analysis.jadx_enabled` is true).
- `analysis.jadx_enabled`: Enable JADX decompilation for APK analyses (default true).
- `analysis.jadx_timeout_sec`: JADX decompile timeout.
- `analysis.callgraph_algo`: `SPARK` (default) or `CHA`.
- `analysis.allow_third_party_callers`: Allow non-framework third-party callers in dangerous API hits (default `true`).
- `analysis.k_hop`: call graph neighborhood hops.
- `analysis.max_seed_count`: maximum seeds to process.
- `analysis.flowdroid_timeout_sec`: FlowDroid timeout in seconds.
- `llm.enabled`: Enable or disable LLM calls.
- `llm.provider`: LLM provider (use `vertex` for API key auth).
- `llm.api_key`: API key (or use `VERTEX_API_KEY` / `GOOGLE_API_KEY` env).
- `llm.base_url`: Vertex API base URL.
- `llm.verify_ssl`: Set `false` to disable SSL verification for Vertex calls (PoC only).
- `llm.timeout_sec`: HTTP timeout for LLM calls.
- `llm.model_orchestrator`: Default model if a stage-specific model is not set.
- `llm.model_recon`: Recon model.
- `llm.model_tier1`: Tier-1 summarizer model.
- `llm.model_verifier`: Verifier model.
- `llm.model_tier2`: Tier-2 intent model.
- `llm.model_report`: Report model.
- `telemetry.enabled`: Enable OpenTelemetry export.
- `telemetry.otlp_endpoint`: OTLP endpoint for traces (default `http://otel-collector:4317` in Docker).
- `observability.enabled`: Enable the run ledger (`observability/runs/<run_id>.jsonl`) consumed by the UI.

Env overrides:

- `KNOX_BASE_URL` overrides `knox.base_url`.
- `ANDROID_SDK_ROOT` will auto-set `analysis.android_platforms_dir` to `$ANDROID_SDK_ROOT/platforms` if unset.

## Vertex AI (LLM) Setup

The PoC includes a minimal Vertex client that supports **API key auth** for public Gemini models. Enable `llm.enabled` in `config/settings.yaml` and configure an API key (supported) or add your own OAuth-based client for service accounts (not wired here).

### Option A) API key (supported)

1) Enable Vertex AI API + billing in GCP Console.

2) Create an API key in the same project.

3) Export the key (or set it in `config/settings.yaml`):

```bash
export VERTEX_API_KEY=your_api_key
```

You can also use `GOOGLE_API_KEY` if preferred.

4) Update settings:

```yaml
llm:
  enabled: true
  provider: "vertex"
  api_key: ""  # optional if VERTEX_API_KEY is set
  model_orchestrator: "gemini-3-pro-preview"
  model_recon: "gemini-3-flash-preview"
  model_tier1: "gemini-3-flash-preview"
  model_verifier: "gemini-3-pro-preview"
  model_tier2: "gemini-3-flash-preview"
  model_report: "gemini-3-flash-preview"
```

### Option B) Service account (not wired in this PoC)

If you need ADC/service-account auth (for private models), you'll need to add an OAuth-based client. The basic credential steps are:

1) Create a service account with `Vertex AI User` role.
2) Download its JSON key.
3) Set:

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
export GOOGLE_CLOUD_PROJECT=<your-gcp-project-id>
export GOOGLE_CLOUD_LOCATION=<your-region>
```

### Docker + Vertex credentials

Service account in Docker:

```bash
docker compose run --rm \
  -e GOOGLE_APPLICATION_CREDENTIALS=/workspace/keys/sa.json \
  -e GOOGLE_CLOUD_PROJECT=<project-id> \
  -e GOOGLE_CLOUD_LOCATION=us-central1 \
  -v /local/keys:/workspace/keys \
  aag
```

API key in Docker:

```bash
docker compose run --rm \
  -e VERTEX_API_KEY=your_api_key \
  aag
```

## Tests

```bash
pytest
```

## Notes

- FlowDroid and Soot require Android platform jars. If analyses fail with classpath errors, verify `analysis.android_platforms_dir`.
- APK-only mode runs JADX in a temp directory that is deleted after analysis. JADX exit code 1 is tolerated (common with obfuscated code); the pipeline checks for actual `.java` file output instead. If JADX produces no output, the pipeline falls back to DEX-only seeding with reduced recall and no repair tools.
- The Tier1 repair agent requires JADX output to function. In combined mode without APK-only decompilation, repair tools are not available.
- LLM integration uses Vertex API keys for public Gemini models; service-account auth requires a custom client.
- **Token optimization**: Tier1 and Tier2 payloads are shaped to reduce token usage by 25-40% while preserving all driver-relevant information. Full context bundles are preserved in artifacts for debugging.
- **Execution LLM compatibility**: The Tier2 output's `execution_guidance` is designed for consumption by a smaller execution LLM (e.g., Qwen Code 30B) that can drive dynamic analysis via ADB, Frida, or manual steps. Commands are complete (ADB with `adb shell` prefix, Frida with full `frida -U -n <pkg> -e "<js>"` format), verification is explicit (no placeholder commands), and failure handling follows strict rules (`on_fail`: abort/retry/skip only).

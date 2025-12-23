# APK Malware Analysis Agent (PoC)

LLM-assisted Android APK malware analysis pipeline aligned to LAMD: deterministic preprocessing + suspicious API seeding + structured context extraction + tiered LLM reasoning with evidence gating + targeted FlowDroid taint confirmation.

## What This Implements

- Knox Vision API client for static metadata, decompiled source access, bytecode method lookup, and APK download.
- Local static extractors (manifest, strings, certs) using Androguard + ZIP parsing.
- Callgraph-sensitive API matcher (catalog-driven) with reachability from Android entrypoints.
- Recon agent with tool runner to build investigation cases from sensitive API hits.
- Suspicious API seeding via recon cases or DEX invocation indexing (Androguard 4.x tested), with Knox/JADX fallback.
- Java-based Soot extractor that exports call graph JSON and per-method CFG JSON, using component lifecycle entrypoints and the latest `android.jar`.
- Context bundle builder with backward CFG slices, branch conditions, and k-hop callgraph neighborhoods.
- Tiered LLM reasoning (Recon -> Tier1 -> Verifier -> Tier2 -> Report) with tolerant JSON parsing and driver guidance output.
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
5) Sensitive API matching:
   - Match callgraph edges against the sensitive API catalog and compute entrypoint reachability.
6) Recon + seeding:
   - Recon turns sensitive hits into investigation cases.
   - Seeding produces a `SuspiciousApiIndex` from cases; if no cases, fall back to DEX invocation indexing, then Knox/JADX search.
7) Context bundles + control-flow paths:
   - Build backward CFG slices and branch conditions per seed.
   - Derive entrypoint -> sink control-flow paths (method chain + callsite statements) and attach branch constraints.
8) Tier1 + Verifier:
   - Tier1 extracts behavior + constraints from slices.
   - Verifier filters Tier1 facts against evidence.
9) Optional FlowDroid:
   - If enabled and verified seeds exist, run targeted taint analysis and pass the summary to Tier2 (data-flow evidence only).
10) Tier2:
   - Generates driver guidance grounded in the control-flow path, constraints, case context, and FlowDroid summary (if present).
11) Reporting:
   - Produce the final threat report + MITRE mappings + driver guidance.

## Detailed Workflow and Tool Usage

Stage A: Static preprocess (local APK + Knox)
- **Androguard APK parser** (`src/apk_analyzer/analyzers/static_extractors.py`): extracts manifest metadata (package, version, permissions, components, SDK) from the APK.
- **ZIP parsing** (built-in `zipfile`): extracts ASCII strings from `classes*.dex` and assets; extracts cert blobs from `META-INF/*.RSA|*.DSA|*.EC`.
- **Knox Vision API** (`src/apk_analyzer/clients/knox_client.py`, combined mode): pulls full analysis, manifest, components, threat indicators; if present, Knox manifest overrides the local manifest.
- **Artifacts**: `artifacts/{analysis_id}/runs/{run_id}/static/manifest.json`, `strings.json`, `cert.json`, `knox_full.json`, `components.json`, `permissions.json`.

Stage A2: APK-only decompile (opt-in)
- **JADX** (`src/apk_analyzer/analyzers/jadx_extractors.py`): decompiles APK to a temp directory for local search. The temp directory is deleted after analysis.
- **Local search helper** (`src/apk_analyzer/analyzers/local_query.py`): scans JADX output (`.java`, `.kt`, `.xml`, `.smali`) for method-name hits; used only as a fallback for seeding.
- If JADX is missing or fails, the pipeline continues with DEX-only seeding (lower recall).

Stage B: Graph extraction
- **Soot extractor (Java)** (`java/soot-extractor`): builds call graph + per-method CFGs using Android platform jars.
- Entry points are derived from Android component lifecycles (Activity/Service/Receiver/Provider/Application/AccessibilityService) across application classes.
- Android jar selection uses the APK target SDK when available:
  - exact match if present,
  - otherwise nearest higher available,
  - otherwise highest available as fallback.
- Callgraph edges combine Soot callgraph edges with direct Jimple invoke edges to avoid missing framework calls.
- **Outputs**: `artifacts/{analysis_id}/runs/{run_id}/graphs/callgraph.json`, `graphs/cfg/*.json`, `graphs/method_index.json`, `graphs/class_hierarchy.json`, `graphs/entrypoints.json`.

Stage C: Sensitive API matching (catalog-driven)
- **Sensitive API catalog** (`config/android_sensitive_api_catalog.json`): maps Soot signatures to categories, priorities, and tags.
- **Matcher** (`src/apk_analyzer/phase0/sensitive_api_matcher.py`): walks callgraph edges, matches callees to catalog signatures, maps callers to manifest components, and computes reachability from entrypoints.
- If the callgraph resolves an interface/superclass instead of the catalog class, the matcher uses `class_hierarchy.json` to accept compatible classes with the same method signature.
- Caller filtering: by default, only app-owned callers (manifest package or components) are kept to avoid AndroidX/Kotlin library noise.
- **Artifacts**: `artifacts/{analysis_id}/runs/{run_id}/seeds/sensitive_api_hits.json`.

Stage D: Recon + case creation (LLM)
- **Recon agent** (`src/apk_analyzer/agents/recon.py`): consumes manifest summary + callgraph summary + sensitive hits and returns `cases` for investigation.
- **Recon tools** (`src/apk_analyzer/agents/recon_tools.py`): LLM may call `get_hit`, `list_hits`, `get_summary`, `get_entrypoints` to refine cases.
- **Artifacts**: `artifacts/{analysis_id}/runs/{run_id}/llm/recon.json`.

Stage E: Seeding (SuspiciousApiIndex)
- If recon cases exist, they are converted into a `SuspiciousApiIndex` (high-confidence callsites).
- Otherwise, **DEX invocation indexing** (`src/apk_analyzer/analyzers/dex_invocation_indexer.py`) scans DEX with Androguard (4.x tested) and matches `config/suspicious_api_catalog.json`.
- If DEX parsing fails or yields no hits, fallback seeding uses Knox source search (combined mode) or JADX local search (apk-only mode), with lower confidence.
- **Artifacts**: `artifacts/{analysis_id}/runs/{run_id}/seeds/suspicious_api_index.json`.

Stage F: Context bundles + CFG slices
- **Context bundle builder** (`src/apk_analyzer/analyzers/context_bundle_builder.py`): builds per-seed backward slices from Soot CFGs, extracts branch conditions, and computes k-hop callgraph neighborhoods.
- Bundles include static context (permissions, receiver triggers, string hints) and case context (priority, reachability).
- **Control-flow paths**: derives entrypoint -> sink method chains using callgraph reachability + callsite statements, and attaches branch conditions from slices.
- **Artifacts**: `artifacts/{analysis_id}/runs/{run_id}/graphs/slices/<seed_id>.json`, `graphs/context_bundles/<seed_id>.json`, `graphs/entrypoint_paths/<seed_id>.json`, `graphs/entrypoint_paths.json`.

Stage G: Tier1 + Verifier (LLM grounding)
- **Tier1**: summarizes behavior and extracts execution constraints (branch predicates, required inputs, triggers).
- **Verifier**: enforces evidence grounding against slice units and context bundles; only verified seeds advance.
- LLM JSON is parsed with a tolerant parser (`src/apk_analyzer/utils/llm_json.py`) and falls back to safe defaults on invalid output.
- **Artifacts**: `artifacts/{analysis_id}/runs/{run_id}/llm/tier1/*.json`, `llm/verifier/*.json`, plus `llm_inputs/` and `llm_outputs/` for raw prompts/returns.

Stage H: Targeted taint analysis (optional)
- **FlowDroid CLI jar** (`src/apk_analyzer/tools/flowdroid_tools.py`): runs taint analysis using a generated sources/sinks subset based on categories present in verified seeds.
- **Usage**: summary is fed into Tier2 as data-flow evidence (not required for driver paths).
- **Artifacts**: `artifacts/{analysis_id}/runs/{run_id}/taint/flowdroid_summary.json`.

Stage I: Tier2 intent + driver guidance
- **Tier2**: produces driver guidance (ADB/UI Automator/Frida-friendly) using Tier1 + control-flow paths + static context + case context + FlowDroid summary (if present).
- **Artifacts**: `artifacts/{analysis_id}/runs/{run_id}/llm/tier2/*.json`.

Stage J: Reporting + MITRE mapping
- **MITRE mapping** (`config/mitre/` + `src/apk_analyzer/analyzers/mitre_mapper.py`): maps extracted evidence to ATT&CK techniques.
- **Report**: includes `driver_guidance` synthesized from Tier-2 outputs for dynamic analysis.
  - `artifacts/{analysis_id}/runs/{run_id}/report/threat_report.json` and `.md`.

## Repo Layout

- `src/apk_analyzer/`: Python pipeline and agent logic
- `java/soot-extractor/`: Java Soot extractor (Gradle)
- `config/`: settings, schemas, suspicious API catalogs, SourcesAndSinks, MITRE mapping
- `config/android_sensitive_api_catalog.json`: catalog-driven sensitive API definitions for recon
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

2) Build the Soot extractor:

```bash
gradle -p java/soot-extractor jar
```

3) Build FlowDroid CLI jar:

```bash
mvn -f FlowDroid/pom.xml -pl soot-infoflow-cmd -am package -DskipTests
```

4) Configure `config/settings.yaml`:

- `analysis.android_platforms_dir` should point to your Android SDK `platforms/` directory.
- `analysis.flowdroid_jar_path` should point to `FlowDroid/soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar`.
- `analysis.soot_extractor_jar_path` should point to `java/soot-extractor/build/libs/soot-extractor.jar`.

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

3) Bootstrap toolchain inside the container (Python deps + Soot extractor + FlowDroid jar):

```bash
docker compose run --rm aag ./scripts/docker_bootstrap.sh
```

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

### Start the UI server

```bash
docker compose up -d obs-ui
```

### Run an analysis (emits run ledger)

```bash
docker compose run --rm aag \
  python -m apk_analyzer.main --mode apk-only --apk /workspace/path/to/app.apk
```

### Open the UI

- Run list: `http://localhost:8000/runs`
- Run details: click an analysis/run ID to view stage timeline, seeding stats, recon output, Soot stats, API/tool events, and LLM I/O.

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
- `analysis.jadx_path`: JADX binary or jar (used in apk-only mode).
- `analysis.jadx_timeout_sec`: JADX decompile timeout.
- `analysis.callgraph_algo`: `SPARK` (default) or `CHA`.
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
- APK-only mode runs JADX in a temp directory that is deleted after analysis; if JADX is missing or fails, the pipeline falls back to DEX-only seeding with reduced recall.
- LLM integration uses Vertex API keys for public Gemini models; service-account auth requires a custom client.

# Configuration Reference

This document provides a complete reference for all configuration options.

## Configuration File

Settings are defined in `config/settings.yaml`. CLI arguments can override most settings.

---

## Knox Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `knox.base_url` | `http://105.145.72.82:8081/api/v1` | Knox Vision API base URL |
| `knox.headers` | `{}` | Custom headers for Knox API requests |

**Environment Override**: `KNOX_BASE_URL`

---

## Analysis Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `analysis.artifacts_dir` | `artifacts` | Output directory for analysis results |
| `analysis.android_platforms_dir` | (auto) | Android SDK platforms directory |
| `analysis.flowdroid_jar_path` | `FlowDroid/.../soot-infoflow-cmd-jar-with-dependencies.jar` | FlowDroid CLI jar path |
| `analysis.soot_extractor_jar_path` | `java/soot-extractor/build/libs/soot-extractor.jar` | Soot extractor jar path |
| `analysis.jadx_path` | `jadx` | Path to JADX binary or jar |
| `analysis.jadx_enabled` | `true` | Enable JADX decompilation |
| `analysis.jadx_timeout_sec` | `600` | JADX decompilation timeout (10 min) |
| `analysis.callgraph_algo` | `SPARK` | Call graph algorithm: `SPARK` or `CHA` |
| `analysis.allow_third_party_callers` | `true` | Include third-party SDK callers in API hits |
| `analysis.filter_common_libraries` | `true` | Filter library callers (androidx, kotlin, etc.) |
| `analysis.k_hop` | `2` | Call graph neighborhood distance |
| `analysis.max_seed_count` | `20` | Maximum suspicious APIs to analyze |
| `analysis.flowdroid_timeout_sec` | `900` | FlowDroid taint analysis timeout (15 min) |
| `analysis.flowdroid_callbacks_enabled` | `true` | Enable FlowDroid callback analysis |
| `analysis.flowdroid_callbacks_timeout_sec` | `300` | Callback analysis timeout (5 min) |
| `analysis.flowdroid_callbacks_max_per_component` | `500` | Max callbacks per component |
| `analysis.flowdroid_callbacks_mode` | `fast` | Callback mode: `fast` or `default` |

**Environment Override**: `ANDROID_SDK_ROOT` → sets `analysis.android_platforms_dir` to `$ANDROID_SDK_ROOT/platforms`

---

## LLM Settings

### General

| Setting | Default | Description |
|---------|---------|-------------|
| `llm.enabled` | `true` | Enable/disable LLM functionality |
| `llm.provider` | `vertex` | Legacy provider field (auto-detected from model names) |
| `llm.timeout_sec` | `1500` | HTTP timeout for LLM calls (25 min) |
| `llm.verify_ssl` | `false` | SSL certificate verification (disable for corporate proxies) |

### Gemini Authentication

| Setting | Default | Description |
|---------|---------|-------------|
| `llm.gemini_auth_method` | `service_account` | Auth method: `api_key` or `service_account` |
| `llm.api_key` | - | API key (for `api_key` method) |
| `llm.base_url` | `https://aiplatform.googleapis.com/v1` | Vertex AI base URL (for `api_key` method) |
| `llm.gcp_project_id` | - | GCP project ID |
| `llm.gcp_location` | `global` | GCP location for Gemini |
| `llm.gcp_service_account_file` | - | Path to GCP service account JSON |

### Claude Authentication

Claude uses service account authentication via `anthropic.AnthropicVertex`:

| Setting | Default | Description |
|---------|---------|-------------|
| `llm.gcp_project_id` | - | GCP project ID (required) |
| `llm.gcp_region` | `us-central1` | GCP region for Claude (different from `gcp_location`) |
| `llm.gcp_service_account_file` | - | Path to GCP service account JSON |

### Per-Stage Model Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `llm.model_orchestrator` | `gemini-3-pro-preview` | Default model if stage-specific not set |
| `llm.model_recon` | `claude-opus-4-5@20251101` | Recon agent model |
| `llm.model_tier1` | `gemini-3-flash-preview` | Tier1 summarizer model |
| `llm.model_verifier` | `gemini-3-pro-preview` | Verifier model |
| `llm.model_tier2` | `gemini-3-flash-preview` | Tier2 intent/commands model |
| `llm.model_report` | `gemini-3-flash-preview` | Report generation model |
| `llm.recon_max_tool_rounds` | `3` | Max tool use rounds for recon |

### Feature Flags

| Setting | Default | Description |
|---------|---------|-------------|
| `llm.tier2_split_enabled` | `true` | Two-phase Tier2 (Phase 2A reasoning + Phase 2B commands) |

---

## Telemetry Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `telemetry.enabled` | `false` | Enable OpenTelemetry export |
| `telemetry.service_name` | `apk-analysis-agent` | Service name for traces |
| `telemetry.otlp_endpoint` | `http://localhost:4317` | OTLP endpoint URL |
| `telemetry.otlp_insecure` | `true` | Use insecure connection |

---

## Observability Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `observability.enabled` | `true` | Enable run ledger for UI |

The run ledger is written to `artifacts/{analysis_id}/observability/runs/{run_id}.jsonl`.

---

## Environment Variables

| Variable | Purpose | Overrides |
|----------|---------|-----------|
| `KNOX_BASE_URL` | Knox API endpoint | `knox.base_url` |
| `ANDROID_SDK_ROOT` | Android SDK path | `analysis.android_platforms_dir` |
| `GCP_PROJECT_ID` | GCP project ID (fallback) | `llm.gcp_project_id` |
| `VERTEX_API_KEY` | Vertex/Gemini API key | `llm.api_key` |
| `GOOGLE_API_KEY` | Google API key (fallback) | `llm.api_key` |
| `GOOGLE_APPLICATION_CREDENTIALS` | Service account path | (set by code from `gcp_service_account_file`) |

### SSL Verification Variables

When `llm.verify_ssl: false`, the following are set automatically:

| Variable | Value |
|----------|-------|
| `PYTHONHTTPSVERIFY` | `0` |
| `CURL_CA_BUNDLE` | `` (empty) |
| `REQUESTS_CA_BUNDLE` | `` (empty) |

---

## CLI Arguments

| Argument | Overrides | Description |
|----------|-----------|-------------|
| `--apk` | - | Path to APK file (required) |
| `--knox-id` | - | Knox APK ID (required for combined mode) |
| `--mode` | - | Analysis mode: `combined` or `apk-only` |
| `--settings` | - | Path to settings YAML file |
| `--android-platforms` | `analysis.android_platforms_dir` | Android SDK platforms directory |
| `--flowdroid-jar` | `analysis.flowdroid_jar_path` | FlowDroid CLI jar path |
| `--soot-jar` | `analysis.soot_extractor_jar_path` | Soot extractor jar path |
| `--jadx-path` | `analysis.jadx_path` | JADX binary/jar path |
| `--jadx-timeout` | `analysis.jadx_timeout_sec` | JADX timeout in seconds |

---

## LLM Setup Guide

### Service Account Setup (Recommended)

1. Create a GCP service account with `Vertex AI User` role
2. Download the JSON key file
3. Place it in `config/gcp-sa-key.json`
4. Update `config/settings.yaml`:

```yaml
llm:
  enabled: true
  gemini_auth_method: "service_account"
  gcp_project_id: "your-project-id"
  gcp_location: "global"
  gcp_service_account_file: "config/gcp-sa-key.json"
```

### API Key Setup (Alternative)

1. Enable Vertex AI API in GCP Console
2. Create an API key
3. Update `config/settings.yaml`:

```yaml
llm:
  enabled: true
  gemini_auth_method: "api_key"
  api_key: "your-api-key"  # or set VERTEX_API_KEY env
```

### Provider Auto-Detection

Model names are parsed to determine the provider:
- **Claude**: Models containing `claude`, `opus`, `sonnet`, or `haiku` → routes to `ClaudeLLMClient`
- **Gemini**: All other models → routes to `GeminiLLMClient` or `VertexLLMClient`

You can mix providers in a single analysis:

```yaml
llm:
  model_recon: "claude-opus-4-5@20251101"  # Uses Claude
  model_tier1: "gemini-3-flash-preview"     # Uses Gemini
  model_tier2: "gemini-3-pro-preview"       # Uses Gemini
```

### Docker Credentials

Service account in Docker:

```bash
docker compose run --rm \
  -e GOOGLE_APPLICATION_CREDENTIALS=/workspace/config/gcp-sa-key.json \
  -e GCP_PROJECT_ID=your-project-id \
  aag python -m apk_analyzer.main --mode apk-only --apk /workspace/data/app.apk
```

API key in Docker:

```bash
docker compose run --rm \
  -e VERTEX_API_KEY=your-api-key \
  aag python -m apk_analyzer.main --mode apk-only --apk /workspace/data/app.apk
```

---

## Example Configuration

```yaml
knox:
  base_url: "http://105.145.72.82:8081/api/v1"
  headers: {}

analysis:
  artifacts_dir: "artifacts"
  android_platforms_dir: ""  # Auto-detected in Docker
  jadx_enabled: true
  jadx_timeout_sec: 600
  callgraph_algo: "SPARK"
  allow_third_party_callers: true
  filter_common_libraries: true
  k_hop: 2
  max_seed_count: 20
  flowdroid_callbacks_enabled: true
  flowdroid_callbacks_mode: "fast"

llm:
  enabled: true
  gemini_auth_method: "service_account"
  gcp_project_id: "your-project-id"
  gcp_location: "global"
  gcp_service_account_file: "config/gcp-sa-key.json"
  verify_ssl: false
  timeout_sec: 1500
  model_orchestrator: "gemini-3-pro-preview"
  model_recon: "claude-opus-4-5@20251101"
  model_tier1: "gemini-3-flash-preview"
  model_verifier: "gemini-3-pro-preview"
  model_tier2: "gemini-3-flash-preview"
  model_report: "gemini-3-flash-preview"
  tier2_split_enabled: true

telemetry:
  enabled: false
  service_name: "apk-analysis-agent"
  otlp_endpoint: "http://localhost:4317"

observability:
  enabled: true
```

# APK Malware Analysis Agent

LLM-assisted Android APK malware analysis pipeline. Uses tiered LLM reasoning with evidence gating to detect threats like banking trojans, spyware, and stalkerware.

## Quick Start

### Prerequisites

- Docker and Docker Compose
- GCP service account with Vertex AI access (for LLM)

### Setup

1. Clone with submodules:
   ```bash
   git clone --recursive <repo-url>
   cd aagv3
   ```

2. Build and bootstrap:
   ```bash
   docker compose build
   docker compose run --rm aag ./scripts/docker_bootstrap.sh
   ```
   Bootstrap builds FlowDroid and Soot extractor (takes ~5 minutes first time).

3. Configure LLM credentials:
   ```bash
   # Add your GCP service account key
   cp /path/to/your-service-account.json config/gcp-sa-key.json
   ```

4. Update `config/settings.yaml`:
   ```yaml
   llm:
     enabled: true
     gcp_project_id: "your-project-id"
     gcp_service_account_file: "config/gcp-sa-key.json"
   ```

### Run Your First Analysis

```bash
# Copy APK to data directory
cp /path/to/sample.apk data/

# Run analysis
docker compose run --rm aag \
  python -m apk_analyzer.main --mode apk-only --apk /workspace/data/sample.apk
```

Artifacts are written to `artifacts/{sha256}/runs/{run_id}/`.

---

## Usage

### Analysis Modes

| Mode | Command | Use Case |
|------|---------|----------|
| APK-only | `--mode apk-only --apk <path>` | Local APK, no Knox dependency |
| Combined | `--apk <path> --knox-id <id>` | Knox metadata + local APK |

**APK-only** (recommended for most cases):
```bash
docker compose run --rm aag \
  python -m apk_analyzer.main --mode apk-only --apk /workspace/data/app.apk
```

**Combined** (with Knox Vision API):
```bash
docker compose run --rm aag \
  python -m apk_analyzer.main --apk /workspace/data/app.apk --knox-id <apk_id>
```

### Observability UI

Real-time pipeline monitoring:

```bash
docker compose up -d obs-ui
```

Open http://localhost:8000/runs to view:
- Stage timeline with live progress
- LLM prompts and responses
- Artifact links

---

## Configuration

### LLM Providers

The pipeline supports Gemini and Claude via GCP Vertex AI:

```yaml
llm:
  enabled: true
  gcp_project_id: "your-project-id"
  gcp_service_account_file: "config/gcp-sa-key.json"
  model_recon: "claude-opus-4-5@20251101"       # Claude for recon
  model_tier1: "gemini-3-flash-preview"          # Gemini for tier1
  model_tier2: "gemini-3-flash-preview"          # Gemini for tier2
```

Model routing is automatic based on model name (claude/gemini patterns).

See [docs/configuration.md](docs/configuration.md) for full settings reference.

### Key Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `analysis.jadx_enabled` | `true` | Enable JADX decompilation |
| `analysis.max_seed_count` | `20` | Max suspicious APIs to analyze |
| `analysis.filter_common_libraries` | `true` | Filter library noise |
| `llm.tier2_split_enabled` | `true` | Two-phase Tier2 (recommended) |
| `llm.verify_ssl` | `false` | Disable for corporate proxies |

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `GCP_PROJECT_ID` | GCP project ID (fallback) |
| `GOOGLE_APPLICATION_CREDENTIALS` | Service account path |
| `KNOX_BASE_URL` | Knox API endpoint override |
| `VERTEX_API_KEY` | API key auth (alternative to service account) |

---

## Repo Layout

```
src/apk_analyzer/          # Python pipeline
  agents/                  # LLM agents (recon, tier1, tier2, verifier)
  analyzers/               # Static analyzers
  prompts/                 # LLM prompt templates
java/soot-extractor/       # Soot callgraph extractor
config/                    # Settings, API catalogs, MITRE mapping
server/                    # FastAPI observability UI
docs/                      # Detailed documentation
```

---

## Architecture

The pipeline runs 9 stages:

1. **Static preprocessing** - Manifest, strings, certificates
2. **JADX decompilation** - Source code for analysis
3. **Soot callgraph extraction** - Call graph + CFGs
4. **Sensitive API matching** - Catalog-driven hit detection
5. **Recon** (LLM) - Threat categorization
6. **Seeding** - API index for investigation
7. **Context bundle building** - Slices, paths, constraints
8. **Tier1 analysis** (LLM) - Behavior summarization + verification
9. **Tier2 driver guidance** (LLM) - Execution commands + reporting

See [docs/architecture.md](docs/architecture.md) for detailed workflow and artifact structure.

---

## Development

For local development without Docker:

- Python 3.10+, JDK 17, Gradle, Maven
- Android SDK platforms (25-36)

See [docs/development.md](docs/development.md) for full setup instructions.

### Tests

```bash
# In Docker
docker compose run --rm aag pytest

# Locally
pytest
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Soot classpath errors | Check `analysis.android_platforms_dir` |
| JADX exit code 1 | Normal for obfuscated code; check output exists |
| LLM timeout | Increase `llm.timeout_sec` |
| SSL errors | Set `llm.verify_ssl: false` |

See [docs/troubleshooting.md](docs/troubleshooting.md) for more.

---

## Docker Reference

### Rebuild After Changes

```bash
# After FlowDroid changes
docker compose run --rm aag \
  mvn -f FlowDroid/pom.xml -pl soot-infoflow-cmd -am package -DskipTests

# After Soot extractor changes
docker compose run --rm aag gradle -p java/soot-extractor jar
```

### Interactive Shell

```bash
docker compose run --rm aag
```

### Docker Environment

- Repo mounted at `/workspace`
- Android SDK at `/opt/android-sdk`
- JADX at `/opt/jadx/bin/jadx`
- Artifacts persist to host via volume mount

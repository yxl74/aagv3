# Development Guide

This document covers local development setup without Docker.

> **Note**: Docker is the recommended deployment method. Use local setup only for development and debugging.

---

## Prerequisites

- Python >= 3.10
- JDK 17 (for Soot extractor and FlowDroid)
- Maven (for FlowDroid build)
- Gradle (for Soot extractor build)
- Android SDK with platform JARs (API levels 25-36 recommended)
- JADX decompiler (optional, for source decompilation)

---

## Setup

### 1. Clone Repository

```bash
git clone --recursive <repo-url>
cd aagv3
```

The `--recursive` flag ensures FlowDroid submodule is initialized.

### 2. Install Python Dependencies

```bash
python -m pip install -r requirements.txt
export PYTHONPATH="$(pwd)/src"
```

Alternatively, install as a package:

```bash
python -m pip install .
```

### 3. Build FlowDroid CLI JAR

FlowDroid is required for callback analysis during Soot extraction.

```bash
mvn -f FlowDroid/pom.xml -pl soot-infoflow-cmd -am package -DskipTests
```

This produces:
```
FlowDroid/soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar
```

### 4. Build Soot Extractor

```bash
gradle -p java/soot-extractor jar
```

This produces:
```
java/soot-extractor/build/libs/soot-extractor.jar
```

### 5. Install JADX (Optional)

Download from [JADX releases](https://github.com/skylot/jadx/releases) or install via package manager:

```bash
# macOS
brew install jadx

# Linux (manual)
wget https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip
unzip jadx-1.5.1.zip -d /opt/jadx
export PATH="/opt/jadx/bin:$PATH"
```

### 6. Configure Settings

Update `config/settings.yaml`:

```yaml
analysis:
  android_platforms_dir: "/path/to/android-sdk/platforms"
  flowdroid_jar_path: "FlowDroid/soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar"
  soot_extractor_jar_path: "java/soot-extractor/build/libs/soot-extractor.jar"
  jadx_path: "jadx"  # or full path
```

---

## Running Locally

### APK-Only Mode

```bash
python -m apk_analyzer.main --mode apk-only --apk /path/to/app.apk
```

### Combined Mode (Knox + APK)

```bash
python -m apk_analyzer.main --apk /path/to/app.apk --knox-id <apk_id>
```

### With Custom Settings

```bash
python -m apk_analyzer.main \
  --mode apk-only \
  --apk /path/to/app.apk \
  --settings /path/to/custom-settings.yaml \
  --android-platforms /custom/android-sdk/platforms
```

---

## Testing

### Run All Tests

```bash
pytest
```

### Run Specific Tests

```bash
# Run tests in a specific file
pytest tests/test_sensitive_api_matcher.py

# Run tests matching a pattern
pytest -k "test_recon"

# Run with verbose output
pytest -v
```

### Test Coverage

```bash
pytest --cov=src/apk_analyzer --cov-report=html
open htmlcov/index.html
```

---

## Known Limitations

- Reflection filtering: when `analysis.reflection_high_signal_only` is enabled, `obfuscated_chain` and `crypto_chain` signals are only kept for app callers (`caller_is_app`); malicious code living in third-party SDK namespaces may be filtered unless it resolves to a sensitive target.
- Reflection + JADX: if JADX is unavailable or fails, reflection hits that require target resolution may be dropped; disable `analysis.reflection_high_signal_only` to inspect raw reflection hits.
- Reachability: `reachable_from_entrypoint` is callgraph-derived and can be false for async/callback/UI-thread flows or inner classes of components (e.g., runnables posted from an Activity); treat “unreachable” as “no static path found,” not proof of dead code.

---

## Rebuilding Components

### After FlowDroid Changes

```bash
mvn -f FlowDroid/pom.xml -pl soot-infoflow-cmd -am package -DskipTests
```

### After Soot Extractor Changes

```bash
gradle -p java/soot-extractor jar
```

### After Python Changes

No rebuild needed. Changes are reflected immediately due to `PYTHONPATH` setup.

---

## Observability UI (Local)

Start the FastAPI server:

```bash
uvicorn server.app:app --host 0.0.0.0 --port 8000 --reload
```

Access at `http://localhost:8000/runs`.

---

## Project Structure

```
aagv3/
├── src/apk_analyzer/          # Python pipeline
│   ├── agents/                # LLM agents
│   │   ├── orchestrator.py    # Main pipeline coordinator
│   │   ├── recon.py           # Recon agent
│   │   ├── tier1_summarizer.py
│   │   ├── tier2a_reasoning.py
│   │   ├── tier2b_commands.py
│   │   ├── verifier.py
│   │   └── report.py
│   ├── analyzers/             # Static analyzers
│   │   ├── static_extractors.py
│   │   ├── jadx_extractors.py
│   │   ├── context_bundle_builder.py
│   │   └── dex_invocation_indexer.py
│   ├── clients/               # API clients
│   │   ├── llm_factory.py
│   │   ├── gemini_client.py
│   │   ├── claude_client.py
│   │   ├── vertex_client.py
│   │   └── knox_client.py
│   ├── phase0/                # API matching
│   │   └── sensitive_api_matcher.py
│   ├── prompts/               # LLM prompts (Markdown)
│   └── utils/                 # Utilities
├── java/soot-extractor/       # Java Soot extractor
│   ├── src/main/java/         # Java source
│   └── build.gradle           # Gradle build file
├── config/                    # Configuration
│   ├── settings.yaml          # Main config file
│   ├── android_sensitive_api_catalog.json
│   ├── suspicious_api_catalog.json
│   └── mitre/                 # MITRE ATT&CK mapping
├── server/                    # FastAPI observability UI
├── tests/                     # Unit tests
├── FlowDroid/                 # FlowDroid submodule
└── scripts/                   # Helper scripts
```

---

## Common Development Tasks

### Adding a New LLM Agent

1. Create agent file in `src/apk_analyzer/agents/`
2. Create prompt template in `src/apk_analyzer/prompts/`
3. Add model config in `config/settings.yaml`
4. Wire up in `orchestrator.py`

### Adding a New Sensitive API

1. Edit `config/android_sensitive_api_catalog.json`
2. Add signature, category, priority, and tags
3. Run tests to verify matching

### Adding a New Static Analyzer

1. Create analyzer in `src/apk_analyzer/analyzers/`
2. Call from `orchestrator.py` at appropriate stage
3. Define artifact output path

---

## Debugging Tips

### Enable Debug Logging

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### View LLM Prompts/Responses

Artifacts are written to:
- `artifacts/{id}/runs/{run_id}/llm_inputs/` - Raw prompts sent to LLM
- `artifacts/{id}/runs/{run_id}/llm_outputs/` - Raw LLM responses

### Inspect Callgraph

```python
import json
with open("artifacts/.../graphs/callgraph.json") as f:
    cg = json.load(f)
print(f"Nodes: {cg['node_count']}, Edges: {cg['edge_count']}")
```

### Test API Matching

```python
from apk_analyzer.phase0.sensitive_api_matcher import match_sensitive_apis
hits = match_sensitive_apis(callgraph_path, catalog_path, ...)
```

---

## IDE Setup

### VS Code

Recommended extensions:
- Python
- Pylance
- Java Extension Pack

`.vscode/settings.json`:
```json
{
  "python.analysis.extraPaths": ["src"],
  "python.defaultInterpreterPath": ".venv/bin/python"
}
```

### PyCharm

1. Mark `src/` as Sources Root
2. Set Python interpreter to venv
3. Configure Java SDK for `java/soot-extractor`

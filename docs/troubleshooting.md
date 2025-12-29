# Troubleshooting

Common issues and their solutions.

---

## Soot / Callgraph Issues

### Error: "Could not find android.jar"

**Cause**: Android SDK platforms directory not configured or missing target SDK.

**Solution**:
```yaml
# config/settings.yaml
analysis:
  android_platforms_dir: "/opt/android-sdk/platforms"  # Local
  # or in Docker, this is auto-detected
```

Ensure the directory contains `android-<SDK>/android.jar` files for the APK's target SDK.

### Error: "No entrypoints found"

**Cause**: Soot couldn't find Android component lifecycle methods.

**Solution**:
1. Verify the APK has a valid `AndroidManifest.xml`
2. Check if components are declared correctly in manifest
3. Try with `analysis.callgraph_algo: CHA` for broader coverage

### Callgraph is too large / takes too long

**Cause**: Large APKs with many classes can produce massive callgraphs.

**Solution**:
```yaml
analysis:
  callgraph_algo: "SPARK"  # More precise than CHA
  flowdroid_callbacks_max_per_component: 100  # Reduce callbacks
```

---

## JADX Issues

### Warning: "JADX exit code 1"

**Cause**: JADX often exits with code 1 due to decompilation errors (obfuscated code, etc.).

**This is usually not a problem**. The pipeline checks for actual `.java` file output rather than exit code.

### No JADX output / No .java files

**Cause**: JADX failed to decompile any classes.

**Solution**:
1. Check if APK is heavily obfuscated or packed
2. Try increasing timeout: `analysis.jadx_timeout_sec: 1200`
3. Pipeline will continue with DEX-only seeding (lower recall)

### JADX not found

**Cause**: JADX binary not in PATH or wrong path configured.

**Solution**:
```yaml
analysis:
  jadx_path: "/opt/jadx/bin/jadx"  # Full path
```

In Docker, JADX is pre-installed at `/opt/jadx/bin/jadx`.

---

## LLM Issues

### Error: "LLM timeout" / Request timed out

**Cause**: LLM request took longer than configured timeout.

**Solution**:
```yaml
llm:
  timeout_sec: 2400  # Increase from default 1500
```

### SSL certificate errors

**Cause**: Corporate proxy intercepting SSL traffic.

**Solution**:
```yaml
llm:
  verify_ssl: false
```

This disables SSL verification for all LLM requests.

### Error: "No LLM client configured"

**Cause**: Neither Gemini nor Claude credentials are valid.

**Solution**: Verify your setup:

For service account:
```yaml
llm:
  gemini_auth_method: "service_account"
  gcp_project_id: "your-project-id"
  gcp_service_account_file: "config/gcp-sa-key.json"
```

Ensure the service account has `Vertex AI User` role.

For API key:
```yaml
llm:
  gemini_auth_method: "api_key"
  api_key: "your-api-key"
```

Or set `VERTEX_API_KEY` environment variable.

### Claude model not working

**Cause**: Claude requires service account auth (not API key).

**Solution**: Claude on Vertex AI only works with service account:
```yaml
llm:
  gcp_project_id: "your-project-id"
  gcp_region: "us-central1"  # Note: different from gcp_location
  gcp_service_account_file: "config/gcp-sa-key.json"
  model_recon: "claude-opus-4-5@20251101"
```

---

## Docker Issues

### Error: "Cannot connect to Docker daemon"

**Cause**: Docker is not running or user doesn't have permissions.

**Solution**:
```bash
# Start Docker
sudo systemctl start docker

# Add user to docker group (requires logout/login)
sudo usermod -aG docker $USER
```

### Container runs out of memory

**Cause**: Large APKs can require significant memory for analysis.

**Solution**: Increase Docker memory limit in Docker Desktop settings or use:
```bash
docker compose run --rm -m 8g aag ...
```

### Bootstrap step fails

**Cause**: FlowDroid or Soot extractor build failed.

**Solution**:
1. Check Maven/Gradle output for errors
2. Ensure JDK 17 is installed in container
3. Try clean rebuild:
```bash
docker compose run --rm aag rm -rf FlowDroid/soot-infoflow-cmd/target
docker compose run --rm aag ./scripts/docker_bootstrap.sh
```

---

## Analysis Issues

### No sensitive API hits found

**Cause**:
1. APK may be benign (no suspicious APIs)
2. Catalog doesn't cover the APIs used
3. Library filtering may be too aggressive

**Solution**:
1. Check `seeds/sensitive_api_hits.json` for raw hits
2. Try disabling library filter: `analysis.filter_common_libraries: false`
3. Check if APK uses reflection (harder to analyze statically)

### Too many false positives (library noise)

**Cause**: Library callers are included in results.

**Solution**:
```yaml
analysis:
  filter_common_libraries: true
  allow_third_party_callers: false  # Restrict to app package only
```

### Seeds marked as unreachable

**Cause**: No path from entrypoints to the suspicious API call.

**This may be accurate** - the code might be dead. But if you expect it to be reachable:
1. Check `graphs/entrypoints.json` for component entrypoints
2. Verify component is declared in manifest
3. Enable callback analysis: `analysis.flowdroid_callbacks_enabled: true`

---

## Observability UI Issues

### UI shows "Disconnected" / No events

**Cause**: SSE connection dropped or analysis not running.

**Solution**:
1. Verify `obs-ui` service is running: `docker compose ps`
2. Check browser console for connection errors
3. Restart UI: `docker compose restart obs-ui`

### Old runs not appearing

**Cause**: UI reads from `observability/runs/<run_id>.jsonl`.

**Solution**: Ensure `observability.enabled: true` in settings.

---

## Getting Help

If you encounter an issue not listed here:

1. Check the run artifacts for detailed logs:
   - `llm_inputs/` - Prompts sent to LLM
   - `llm_outputs/` - Raw LLM responses
   - `graphs/callgraph_summary.json` - Callgraph stats

2. Enable debug logging:
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```

3. File an issue with:
   - Error message
   - Settings file (redact credentials)
   - APK info (size, obfuscation level)
   - Docker/Python version

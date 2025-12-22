from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from apk_analyzer.analyzers.static_extractors import extract_cert_info, extract_manifest, extract_strings
from apk_analyzer.telemetry import span
from apk_analyzer.utils.artifact_store import ArtifactStore


def run_static_extractors(apk_path: str | Path, store: ArtifactStore) -> Dict[str, Any]:
    with span("tool.static_extractors", tool_name="static_extractors"):
        manifest = extract_manifest(apk_path)
        strings = extract_strings(apk_path)
        cert = extract_cert_info(apk_path)

    store.write_json("static/manifest.json", manifest)
    store.write_json("static/strings.json", strings)
    store.write_json("static/cert.json", cert)

    return {"manifest": manifest, "strings": strings, "cert": cert}

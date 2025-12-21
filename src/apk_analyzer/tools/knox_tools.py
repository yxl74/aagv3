from __future__ import annotations

from typing import Any, Dict

from apk_analyzer.clients.knox_client import KnoxClient
from apk_analyzer.utils.artifact_store import ArtifactStore


def fetch_knox_full(knox: KnoxClient, apk_id: str, store: ArtifactStore) -> Dict[str, Any]:
    data = knox.get_full_analysis(apk_id)
    store.write_json("input/knox_full.json", data)
    return data


def fetch_knox_manifest(knox: KnoxClient, apk_id: str, store: ArtifactStore) -> Dict[str, Any]:
    data = knox.get_manifest(apk_id)
    store.write_json("static/manifest.json", data)
    return data

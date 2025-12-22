from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from apk_analyzer.utils.artifact_store import ArtifactStore
from apk_analyzer.telemetry import span


class KnoxClient:
    def __init__(
        self,
        base_url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 30.0,
        artifact_store: Optional[ArtifactStore] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}
        self.timeout = timeout
        self.artifact_store = artifact_store
        self._client = httpx.Client(timeout=timeout, headers=self.headers)

    def _get_json(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        with span("api.knox", tool_name="knox", http_method="GET", http_url=url) as sp:
            response = self._client.get(url, params=params)
            sp.set_attribute("http.status_code", response.status_code)
            response.raise_for_status()
            return response.json()

    def _get_bytes(self, path: str, params: Optional[Dict[str, Any]] = None) -> bytes:
        url = f"{self.base_url}{path}"
        with span("api.knox", tool_name="knox", http_method="GET", http_url=url) as sp:
            response = self._client.get(url, params=params)
            sp.set_attribute("http.status_code", response.status_code)
            response.raise_for_status()
            return response.content

    def get_full_analysis(self, apk_id: str) -> Dict[str, Any]:
        data = self._get_json(f"/apk/{apk_id}/full")
        if self.artifact_store:
            self.artifact_store.write_json("input/knox_full.json", data)
        return data

    def get_manifest(self, apk_id: str) -> Dict[str, Any]:
        data = self._get_json(f"/apk/{apk_id}/manifest")
        if self.artifact_store:
            self.artifact_store.write_json("input/knox_manifest.json", data)
        return data

    def get_permissions(self, apk_id: str, full_data: Optional[Dict[str, Any]] = None) -> List[str]:
        data = full_data or self.get_full_analysis(apk_id)
        manifest = data.get("manifest_data") or data.get("manifest") or {}
        return manifest.get("permissions") or manifest.get("all_permissions") or []

    def get_components(self, apk_id: str, full_data: Optional[Dict[str, Any]] = None) -> Dict[str, List[str]]:
        data = full_data or self.get_full_analysis(apk_id)
        manifest = data.get("manifest_data") or data.get("manifest") or {}
        return {
            "activities": manifest.get("activities", []),
            "services": manifest.get("services", []),
            "receivers": manifest.get("receivers", []),
            "providers": manifest.get("providers", []),
        }

    def get_apkid_detections(self, apk_id: str, full_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        data = full_data or self.get_full_analysis(apk_id)
        return {
            "apkid_detections": data.get("apkid_detections", []),
            "apkid_all_detections": data.get("apkid_all_detections", {}),
        }

    def get_threat_indicators(self, apk_id: str, full_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if full_data and "threat_indicators" in full_data:
            return full_data.get("threat_indicators", {})
        return self._get_json(f"/threat-indicators/{apk_id}")

    def get_file_types(self, apk_id: str) -> Dict[str, Any]:
        return self._get_json(f"/apk/{apk_id}/file-types")

    def get_native_libraries(self, apk_id: str, full_data: Optional[Dict[str, Any]] = None) -> Any:
        try:
            return self._get_json(f"/apk/{apk_id}/native-full")
        except httpx.HTTPError:
            if full_data:
                return full_data.get("native_libraries", [])
            return []

    def search_source_code(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        params = {"q": query, "type": "content", "doc_type": "source_code", "limit": limit}
        data = self._get_json("/search", params=params)
        hits = data.get("hits") or data.get("results") or []
        return hits

    def get_source_file(self, apk_id: str, file_path: str) -> Dict[str, Any]:
        return self._get_json(f"/apk/{apk_id}/source/{file_path}")

    def get_source_tree(self, apk_id: str) -> Dict[str, Any]:
        return self._get_json(f"/apk/{apk_id}/source")

    def get_bytecode_methods(self, apk_id: str, class_descriptor: str, limit: int = 100) -> Dict[str, Any]:
        params = {"apk_id": apk_id, "class": class_descriptor, "limit": limit}
        return self._get_json("/bytecode/methods", params=params)

    def download_apk(self, apk_id: str) -> bytes:
        data = self._get_bytes(f"/apk/{apk_id}/download")
        if self.artifact_store:
            self.artifact_store.write_bytes("input/app.apk", data)
        return data

    def close(self) -> None:
        self._client.close()

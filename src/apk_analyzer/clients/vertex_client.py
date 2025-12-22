from __future__ import annotations

import json
from typing import Any, Dict, Optional

import httpx

from apk_analyzer.telemetry import span

class VertexLLMClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://aiplatform.googleapis.com/v1",
        default_model: str = "gemini-2.5-flash-lite",
        verify_ssl: bool = False,
        timeout_sec: float = 60.0,
    ) -> None:
        if not api_key:
            raise ValueError("Vertex API key is required")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self.client = httpx.Client(timeout=timeout_sec, verify=verify_ssl)

    def complete(self, prompt: str, payload: dict, model: Optional[str] = None) -> str:
        model_name = model or self.default_model
        url = f"{self.base_url}/publishers/google/models/{model_name}:generateContent"
        text = f"{prompt}\n\nPayload JSON:\n{json.dumps(payload, indent=2, ensure_ascii=True)}"
        body = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {"text": text},
                    ],
                }
            ]
        }
        with span("api.vertex", tool_name="vertex", http_method="POST", http_url=url, model=model_name) as sp:
            response = self.client.post(url, params={"key": self.api_key}, json=body)
            sp.set_attribute("http.status_code", response.status_code)
            response.raise_for_status()
            data = response.json()
            content = _extract_text(data)
            return content


def _extract_text(payload: Dict[str, Any]) -> str:
    candidates = payload.get("candidates") or []
    for cand in candidates:
        parts = (cand.get("content") or {}).get("parts") or []
        for part in parts:
            text = part.get("text")
            if text:
                return text
    raise ValueError("Vertex response contained no text")

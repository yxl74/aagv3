from __future__ import annotations

import json
from typing import Any, Dict, Optional

import httpx


class VertexLLMClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://aiplatform.googleapis.com/v1",
        default_model: str = "gemini-2.5-flash-lite",
        timeout_sec: float = 60.0,
    ) -> None:
        if not api_key:
            raise ValueError("Vertex API key is required")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self.client = httpx.Client(timeout=timeout_sec)

    def complete(self, prompt: str, payload: dict, model: Optional[str] = None) -> Dict[str, Any]:
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
        response = self.client.post(url, params={"key": self.api_key}, json=body)
        response.raise_for_status()
        data = response.json()
        content = _extract_text(data)
        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:  # pragma: no cover - depends on LLM output
            raise ValueError("Vertex response was not valid JSON") from exc


def _extract_text(payload: Dict[str, Any]) -> str:
    candidates = payload.get("candidates") or []
    for cand in candidates:
        parts = (cand.get("content") or {}).get("parts") or []
        for part in parts:
            text = part.get("text")
            if text:
                return text
    raise ValueError("Vertex response contained no text")

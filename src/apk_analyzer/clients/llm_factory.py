from __future__ import annotations

import os
from typing import Any, Dict, Optional

from apk_analyzer.agents.base import LLMClient
from apk_analyzer.clients.vertex_client import VertexLLMClient


def build_llm_client(settings: Dict[str, Any]) -> Optional[LLMClient]:
    llm_conf = settings.get("llm", {}) or {}
    if not llm_conf.get("enabled"):
        return None
    provider = llm_conf.get("provider")
    if provider != "vertex":
        raise ValueError(f"Unsupported LLM provider: {provider}")

    api_key = llm_conf.get("api_key") or os.environ.get("VERTEX_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise ValueError("Set llm.api_key or VERTEX_API_KEY/GOOGLE_API_KEY for Vertex API key auth")

    base_url = llm_conf.get("base_url", "https://aiplatform.googleapis.com/v1")
    timeout_sec = llm_conf.get("timeout_sec", 60)
    verify_ssl = llm_conf.get("verify_ssl", False)
    default_model = llm_conf.get("model_orchestrator") or "gemini-2.5-flash-lite"

    return VertexLLMClient(
        api_key=api_key,
        base_url=base_url,
        default_model=default_model,
        verify_ssl=verify_ssl,
        timeout_sec=timeout_sec,
    )

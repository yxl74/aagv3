from __future__ import annotations

import os
from typing import Any, Dict, Optional

from apk_analyzer.agents.base import LLMClient
from apk_analyzer.clients.vertex_client import VertexLLMClient


def _detect_provider(model_name: str) -> str:
    """
    Auto-detect LLM provider from model name.

    Returns:
        "claude" for Claude models, "gemini" for Gemini models
    """
    if not model_name:
        return "gemini"

    model_lower = model_name.lower()

    # Claude model patterns (Anthropic naming convention)
    if any(pattern in model_lower for pattern in ["claude", "opus", "sonnet", "haiku"]):
        return "claude"

    return "gemini"


class MultiProviderLLMClient:
    """
    LLM client that routes requests to appropriate provider based on model name.

    Implements the LLMClient protocol while supporting multiple backends.
    """

    def __init__(
        self,
        gemini_client: Optional[LLMClient] = None,
        claude_client: Optional[LLMClient] = None,
        default_provider: str = "gemini",
    ) -> None:
        self.gemini_client = gemini_client
        self.claude_client = claude_client
        self.default_provider = default_provider

    def complete(self, prompt: str, payload: dict, model: Optional[str] = None) -> str:
        """Route to appropriate provider based on model name."""
        provider = _detect_provider(model) if model else self.default_provider

        if provider == "claude":
            if not self.claude_client:
                raise ValueError(
                    f"Claude model requested ({model}) but Claude client not configured. "
                    "Set gcp_project_id and gcp_service_account_file in settings."
                )
            return self.claude_client.complete(prompt, payload, model)
        else:
            if not self.gemini_client:
                raise ValueError(
                    f"Gemini model requested ({model}) but Gemini client not configured. "
                    "Set api_key or use service_account auth in settings."
                )
            return self.gemini_client.complete(prompt, payload, model)


def _build_gemini_client(llm_conf: Dict[str, Any]) -> Optional[LLMClient]:
    """
    Build Gemini client based on auth_method setting.

    Auth methods:
        - "api_key": Use VertexLLMClient with API key (default, existing behavior)
        - "service_account": Use GeminiLLMClient with google-genai SDK and service account
    """
    auth_method = llm_conf.get("gemini_auth_method", "api_key")
    timeout_sec = llm_conf.get("timeout_sec", 600)
    default_model = llm_conf.get("model_orchestrator") or "gemini-2.0-flash"

    if auth_method == "service_account":
        # Use google-genai SDK with service account
        gcp_project_id = llm_conf.get("gcp_project_id") or os.environ.get("GCP_PROJECT_ID")
        if not gcp_project_id:
            raise ValueError(
                "gemini_auth_method is 'service_account' but gcp_project_id not set. "
                "Set llm.gcp_project_id or GCP_PROJECT_ID env var."
            )

        from apk_analyzer.clients.gemini_client import GeminiLLMClient

        gcp_location = llm_conf.get("gcp_location", "global")
        service_account_file = llm_conf.get("gcp_service_account_file")
        verify_ssl = llm_conf.get("verify_ssl", True)

        return GeminiLLMClient(
            project_id=gcp_project_id,
            location=gcp_location,
            default_model=default_model,
            service_account_file=service_account_file,
            timeout_sec=timeout_sec,
            verify_ssl=verify_ssl,
        )
    else:
        # Use existing VertexLLMClient with API key (default)
        api_key = llm_conf.get("api_key") or os.environ.get("VERTEX_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            return None  # No API key available

        base_url = llm_conf.get("base_url", "https://aiplatform.googleapis.com/v1")
        verify_ssl = llm_conf.get("verify_ssl", False)

        return VertexLLMClient(
            api_key=api_key,
            base_url=base_url,
            default_model=default_model,
            verify_ssl=verify_ssl,
            timeout_sec=timeout_sec,
        )


def _build_claude_client(llm_conf: Dict[str, Any]) -> Optional[LLMClient]:
    """Build Claude client if GCP project configured."""
    gcp_project_id = llm_conf.get("gcp_project_id") or os.environ.get("GCP_PROJECT_ID")
    if not gcp_project_id:
        return None

    from apk_analyzer.clients.claude_client import ClaudeLLMClient

    gcp_region = llm_conf.get("gcp_region", "us-central1")
    service_account_file = llm_conf.get("gcp_service_account_file")
    timeout_sec = llm_conf.get("timeout_sec", 600)
    verify_ssl = llm_conf.get("verify_ssl", True)

    # Find a Claude model for default, or use standard default
    default_claude_model = "claude-sonnet-4@20250514"
    for key in ["model_recon", "model_tier1", "model_tier2", "model_report", "model_orchestrator"]:
        candidate = llm_conf.get(key)
        if candidate and _detect_provider(candidate) == "claude":
            default_claude_model = candidate
            break

    return ClaudeLLMClient(
        project_id=gcp_project_id,
        region=gcp_region,
        default_model=default_claude_model,
        service_account_file=service_account_file,
        timeout_sec=timeout_sec,
        verify_ssl=verify_ssl,
    )


def build_llm_client(settings: Dict[str, Any]) -> Optional[LLMClient]:
    """
    Build LLM client(s) from settings.

    Supports:
        - Gemini with API key auth (gemini_auth_method: "api_key", default)
        - Gemini with service account auth (gemini_auth_method: "service_account")
        - Claude with service account auth (requires gcp_project_id)

    Returns a MultiProviderLLMClient that routes requests based on model name.
    """
    llm_conf = settings.get("llm", {}) or {}
    if not llm_conf.get("enabled"):
        return None

    gemini_client = _build_gemini_client(llm_conf)
    claude_client = _build_claude_client(llm_conf)

    # Validate at least one client is configured
    if not gemini_client and not claude_client:
        raise ValueError(
            "No LLM client configured. Provide either:\n"
            "  - llm.api_key (or VERTEX_API_KEY env var) for Gemini with API key\n"
            "  - llm.gemini_auth_method: 'service_account' with gcp_project_id for Gemini with service account\n"
            "  - llm.gcp_project_id for Claude (requires service account)"
        )

    # Return multi-provider client
    default_provider = "gemini" if gemini_client else "claude"
    return MultiProviderLLMClient(
        gemini_client=gemini_client,
        claude_client=claude_client,
        default_provider=default_provider,
    )

from __future__ import annotations

import json
import os
from typing import Any, Optional

from apk_analyzer.telemetry import span


class ClaudeLLMClient:
    """
    LLM client for Anthropic Claude via Google Cloud Vertex AI.

    Uses the anthropic.AnthropicVertex SDK which authenticates via
    Google Application Default Credentials (ADC).
    """

    def __init__(
        self,
        project_id: str,
        region: str = "us-central1",
        default_model: str = "claude-sonnet-4@20250514",
        service_account_file: Optional[str] = None,
        timeout_sec: float = 600.0,
        max_tokens: int = 8192,
        verify_ssl: bool = True,
    ) -> None:
        """
        Initialize Claude Vertex client.

        Args:
            project_id: GCP project ID
            region: GCP region (e.g., "us-central1", "europe-west4")
            default_model: Default Claude model to use
            service_account_file: Path to GCP service account JSON file.
                                  If provided, sets GOOGLE_APPLICATION_CREDENTIALS.
            timeout_sec: Request timeout in seconds
            max_tokens: Maximum tokens in response
            verify_ssl: Whether to verify SSL certificates (set False for corporate proxies)
        """
        if not project_id:
            raise ValueError("GCP project_id is required for AnthropicVertex")

        self.project_id = project_id
        self.region = region
        self.default_model = default_model
        self.timeout_sec = timeout_sec
        self.max_tokens = max_tokens
        self.verify_ssl = verify_ssl

        # Disable SSL verification for Google Auth (token exchange)
        if not verify_ssl:
            from apk_analyzer.clients.gemini_client import _disable_ssl_verification
            _disable_ssl_verification()

        # Set up service account credentials if provided
        if service_account_file:
            if not os.path.isabs(service_account_file):
                service_account_file = os.path.abspath(service_account_file)
            if not os.path.exists(service_account_file):
                raise FileNotFoundError(
                    f"Service account file not found: {service_account_file}"
                )
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = service_account_file

        # Lazy import to avoid import errors if anthropic not installed
        try:
            from anthropic import AnthropicVertex
            import httpx
        except ImportError as e:
            raise ImportError(
                "anthropic package required for Claude support. "
                "Install with: pip install anthropic"
            ) from e

        # Create custom httpx client with SSL verification disabled if requested
        http_client = httpx.Client(verify=False) if not verify_ssl else None

        self.client = AnthropicVertex(
            region=region,
            project_id=project_id,
            http_client=http_client,
        )

    def complete(self, prompt: str, payload: dict, model: Optional[str] = None) -> str:
        """
        Generate completion using Claude via Vertex AI.

        Implements the LLMClient protocol.

        Args:
            prompt: System/instruction prompt
            payload: JSON payload to include in the message
            model: Model name override (e.g., "claude-opus-4-5@20251101")

        Returns:
            Text response from Claude
        """
        model_name = model or self.default_model
        text = f"{prompt}\n\nPayload JSON:\n{json.dumps(payload, separators=(',', ':'), ensure_ascii=True)}"
        url = f"vertex.anthropic/{model_name}"

        with span("api.claude", tool_name="claude", http_method="POST", http_url=url, model=model_name) as sp:
            message = self.client.messages.create(
                max_tokens=self.max_tokens,
                messages=[{"role": "user", "content": text}],
                model=model_name,
            )

            sp.set_attribute("usage.input_tokens", message.usage.input_tokens)
            sp.set_attribute("usage.output_tokens", message.usage.output_tokens)

            content = _extract_text(message)
            return content


def _extract_text(message: Any) -> str:
    """
    Extract text content from Claude message response.

    Args:
        message: Anthropic Message object

    Returns:
        Extracted text content or error JSON
    """
    if not message.content:
        return json.dumps({
            "error": "claude_no_content",
            "stop_reason": message.stop_reason,
        }, ensure_ascii=True)

    for block in message.content:
        if hasattr(block, "text") and block.text:
            return block.text

    return json.dumps({
        "error": "claude_no_text",
        "content_types": [type(b).__name__ for b in message.content],
    }, ensure_ascii=True)

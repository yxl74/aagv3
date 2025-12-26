from __future__ import annotations

import json
import os
import ssl
from typing import Any, Optional

from apk_analyzer.telemetry import span


class GeminiLLMClient:
    """
    LLM client for Google Gemini via Vertex AI using google-genai SDK.

    Uses GCP service account authentication via Application Default Credentials.
    """

    def __init__(
        self,
        project_id: str,
        location: str = "global",
        default_model: str = "gemini-2.0-flash",
        service_account_file: Optional[str] = None,
        timeout_sec: float = 600.0,
        verify_ssl: bool = True,
    ) -> None:
        """
        Initialize Gemini client with Vertex AI.

        Args:
            project_id: GCP project ID
            location: GCP location (e.g., "global", "us-central1")
            default_model: Default Gemini model to use
            service_account_file: Path to GCP service account JSON file.
                                  If provided, sets GOOGLE_APPLICATION_CREDENTIALS.
            timeout_sec: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates (set False for corp proxies)
        """
        if not project_id:
            raise ValueError("GCP project_id is required for Gemini Vertex AI")

        self.project_id = project_id
        self.location = location
        self.default_model = default_model
        self.timeout_sec = timeout_sec
        self.verify_ssl = verify_ssl

        # Set up service account credentials if provided
        if service_account_file:
            if not os.path.isabs(service_account_file):
                service_account_file = os.path.abspath(service_account_file)
            if not os.path.exists(service_account_file):
                raise FileNotFoundError(
                    f"Service account file not found: {service_account_file}"
                )
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = service_account_file

        # Disable SSL verification globally for google-auth if needed
        if not verify_ssl:
            # This affects the OAuth token fetch
            import httplib2
            httplib2.RETRIES = 1
            os.environ["PYTHONHTTPSVERIFY"] = "0"

            # For urllib3/requests used by google-auth
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Import and initialize google-genai client
        try:
            from google import genai
            import httpx
        except ImportError as e:
            raise ImportError(
                "google-genai package required for Gemini support. "
                "Install with: pip install google-genai"
            ) from e

        # Create custom httpx client if SSL verification is disabled
        http_options = {}
        if not verify_ssl:
            http_options["api_base"] = None  # Use default
            # The genai client uses httpx internally, we need to patch it
            self._patch_ssl_verification()

        self.client = genai.Client(
            vertexai=True,
            project=project_id,
            location=location,
        )

    def _patch_ssl_verification(self):
        """Patch SSL verification for google-auth and httpx."""
        import ssl

        # Create unverified SSL context
        ssl._create_default_https_context = ssl._create_unverified_context

        # Patch google.auth.transport.requests to disable SSL
        try:
            import google.auth.transport.requests as google_requests
            import requests

            # Create a session with SSL verification disabled
            original_request = google_requests.Request

            class InsecureRequest(original_request):
                def __init__(self, session=None):
                    if session is None:
                        session = requests.Session()
                        session.verify = False
                    super().__init__(session)

            google_requests.Request = InsecureRequest
        except ImportError:
            pass

        # Also patch httpx for the genai client
        try:
            import httpx
            original_client = httpx.Client
            original_async_client = httpx.AsyncClient

            class InsecureClient(original_client):
                def __init__(self, *args, **kwargs):
                    kwargs['verify'] = False
                    super().__init__(*args, **kwargs)

            class InsecureAsyncClient(original_async_client):
                def __init__(self, *args, **kwargs):
                    kwargs['verify'] = False
                    super().__init__(*args, **kwargs)

            httpx.Client = InsecureClient
            httpx.AsyncClient = InsecureAsyncClient
        except ImportError:
            pass

    def complete(self, prompt: str, payload: dict, model: Optional[str] = None) -> str:
        """
        Generate completion using Gemini via Vertex AI.

        Implements the LLMClient protocol.

        Args:
            prompt: System/instruction prompt
            payload: JSON payload to include in the message
            model: Model name override (e.g., "gemini-2.0-flash")

        Returns:
            Text response from Gemini
        """
        model_name = model or self.default_model
        text = f"{prompt}\n\nPayload JSON:\n{json.dumps(payload, separators=(',', ':'), ensure_ascii=True)}"
        url = f"vertex.google/{model_name}"

        with span("api.gemini", tool_name="gemini", http_method="POST", http_url=url, model=model_name) as sp:
            response = self.client.models.generate_content(
                model=model_name,
                contents=[text],
            )

            # Extract usage info if available
            if hasattr(response, 'usage_metadata') and response.usage_metadata:
                sp.set_attribute("usage.input_tokens", response.usage_metadata.prompt_token_count)
                sp.set_attribute("usage.output_tokens", response.usage_metadata.candidates_token_count)

            content = _extract_text(response)
            return content


def _extract_text(response: Any) -> str:
    """
    Extract text content from Gemini response.

    Args:
        response: google-genai GenerateContentResponse object

    Returns:
        Extracted text content or error JSON
    """
    try:
        if hasattr(response, 'text') and response.text:
            return response.text
    except Exception:
        pass

    # Fallback: try to extract from candidates
    try:
        if hasattr(response, 'candidates') and response.candidates:
            for candidate in response.candidates:
                if hasattr(candidate, 'content') and candidate.content:
                    if hasattr(candidate.content, 'parts') and candidate.content.parts:
                        for part in candidate.content.parts:
                            if hasattr(part, 'text') and part.text:
                                return part.text
    except Exception:
        pass

    return json.dumps({
        "error": "gemini_no_text",
        "response_type": type(response).__name__,
    }, ensure_ascii=True)

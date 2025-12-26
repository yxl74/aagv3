from __future__ import annotations

import json
import os
import ssl
from typing import Any, Optional


def _disable_ssl_verification():
    """Disable SSL verification globally. Must be called before other imports."""
    # Disable SSL verification at the lowest level
    ssl._create_default_https_context = ssl._create_unverified_context

    # Environment variables that some libraries check
    os.environ["PYTHONHTTPSVERIFY"] = "0"
    os.environ["CURL_CA_BUNDLE"] = ""
    os.environ["REQUESTS_CA_BUNDLE"] = ""

    # Disable urllib3 warnings
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        pass

    # Patch requests library
    try:
        import requests
        from requests.adapters import HTTPAdapter

        old_init = HTTPAdapter.__init__
        def new_init(self, *args, **kwargs):
            old_init(self, *args, **kwargs)
        HTTPAdapter.__init__ = new_init

        # Patch Session to default verify=False
        old_request = requests.Session.request
        def new_request(self, method, url, **kwargs):
            kwargs.setdefault('verify', False)
            return old_request(self, method, url, **kwargs)
        requests.Session.request = new_request
    except ImportError:
        pass

    # Patch httpx
    try:
        import httpx

        _original_client_init = httpx.Client.__init__
        _original_async_client_init = httpx.AsyncClient.__init__

        def _patched_client_init(self, *args, **kwargs):
            kwargs['verify'] = False
            return _original_client_init(self, *args, **kwargs)

        def _patched_async_client_init(self, *args, **kwargs):
            kwargs['verify'] = False
            return _original_async_client_init(self, *args, **kwargs)

        httpx.Client.__init__ = _patched_client_init
        httpx.AsyncClient.__init__ = _patched_async_client_init
    except ImportError:
        pass

    # Patch google-auth transport
    try:
        import google.auth.transport.requests as google_requests
        import requests as req_lib

        _original_request_init = google_requests.Request.__init__

        def _patched_request_init(self, session=None):
            if session is None:
                session = req_lib.Session()
            session.verify = False
            _original_request_init(self, session)

        google_requests.Request.__init__ = _patched_request_init
    except ImportError:
        pass

    # Patch google-auth _mtls_helper if present
    try:
        import google.auth.transport._mtls_helper as mtls
        mtls._GOOGLE_API_USE_CLIENT_CERTIFICATE = False
    except (ImportError, AttributeError):
        pass


# Import telemetry after potential SSL patching
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

        # Disable SSL verification BEFORE setting up credentials
        if not verify_ssl:
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

        # Import and initialize google-genai client
        try:
            from google import genai
        except ImportError as e:
            raise ImportError(
                "google-genai package required for Gemini support. "
                "Install with: pip install google-genai"
            ) from e

        self.client = genai.Client(
            vertexai=True,
            project=project_id,
            location=location,
        )

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

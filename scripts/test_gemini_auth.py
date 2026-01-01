#!/usr/bin/env python3
"""Test script for Gemini/Vertex AI authentication using google-genai SDK.

Usage:
    1. Place your GCP service account JSON file at config/gcp-sa-key.json
    2. Edit PROJECT_ID below to match your GCP project
    3. Run: python scripts/test_gemini_auth.py
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# =============================================================================
# CONFIGURATION - Edit these values
# =============================================================================
PROJECT_ID = "knox-dev-2"  # Your GCP project ID
LOCATION = "global"  # GCP location
SERVICE_ACCOUNT_FILE = "config/gcp-sa-key.json"  # Path to your credentials
MODEL = "gemini-2.0-flash"  # Gemini model to test
VERIFY_SSL = False  # Set False for corporate proxies with SSL inspection
# =============================================================================


def run_gemini_client_smoke_test() -> None:
    """Run a GeminiLLMClient smoke test (manual script, not a pytest test)."""
    from apk_analyzer.clients.gemini_client import GeminiLLMClient

    print("=" * 60)
    print("Gemini/Vertex AI Authentication Test (Service Account)")
    print("=" * 60)
    print(f"  Project ID:       {PROJECT_ID}")
    print(f"  Location:         {LOCATION}")
    print(f"  Service Account:  {SERVICE_ACCOUNT_FILE}")
    print(f"  Model:            {MODEL}")
    print(f"  Verify SSL:       {VERIFY_SSL}")
    print("=" * 60)

    # Check if service account file exists
    sa_path = Path(SERVICE_ACCOUNT_FILE)
    if not sa_path.exists():
        sa_path = Path(__file__).parent.parent / SERVICE_ACCOUNT_FILE
    if not sa_path.exists():
        print(f"\nERROR: Service account file not found: {SERVICE_ACCOUNT_FILE}")
        print("       Place your GCP credentials JSON file at this location.")
        sys.exit(1)

    print("\n[1/3] Initializing GeminiLLMClient...")
    try:
        client = GeminiLLMClient(
            project_id=PROJECT_ID,
            location=LOCATION,
            service_account_file=str(sa_path),
            default_model=MODEL,
            verify_ssl=VERIFY_SSL,
        )
        print("      OK - Client initialized")
    except Exception as e:
        print(f"      FAILED - {e}")
        sys.exit(1)

    print("\n[2/3] Testing authentication (calling Gemini API)...")
    try:
        response = client.complete(
            prompt="Say 'Authentication successful!' and nothing else.",
            payload={"test": True},
            model=MODEL,
        )
        print("      OK - API call succeeded")
    except Exception as e:
        print(f"      FAILED - {e}")
        print("\n       Possible causes:")
        print("       - Invalid service account credentials")
        print("       - Service account lacks Vertex AI permissions")
        print("       - Vertex AI API not enabled in your GCP project")
        sys.exit(1)

    print("\n[3/3] Validating response...")
    if response and len(response) > 0:
        print("      OK - Got response from Gemini")
    else:
        print("      WARNING - Response was empty")

    print("\n" + "=" * 60)
    print("RESULT: All tests passed!")
    print("=" * 60)
    print(f"\nGemini response: {response}")


def run_minimal_quickstart() -> None:
    """Minimal test matching the quickstart exactly (manual)."""
    import os
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "config/gcp-sa-key.json"

    from google import genai

    print("Running minimal quickstart test...")
    client = genai.Client(
        vertexai=True,
        project=PROJECT_ID,
        location=LOCATION,
    )

    response = client.models.generate_content(
        model=MODEL,
        contents=["Say hello in one sentence."],
    )
    print(f"Response: {response.text}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--minimal":
        run_minimal_quickstart()
    else:
        run_gemini_client_smoke_test()

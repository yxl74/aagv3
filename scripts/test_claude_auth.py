#!/usr/bin/env python3
"""Test script for Claude/Vertex AI authentication and completion.

Usage:
    1. Place your GCP service account JSON file at config/gcp-sa-key.json
    2. Edit PROJECT_ID below to match your GCP project
    3. Run: python scripts/test_claude_auth.py
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# =============================================================================
# CONFIGURATION - Edit these values
# =============================================================================
PROJECT_ID = "knox-dev-2"  # Replace with your actual GCP project ID
REGION = "global"  # GCP region (us-central1, europe-west4, etc.)
SERVICE_ACCOUNT_FILE = "config/gcp-sa-key.json"  # Path to your credentials
MODEL = "claude-sonnet-4-5@20250929"  # Claude model to test
# =============================================================================


def test_claude_client():
    """Test ClaudeLLMClient directly."""
    from apk_analyzer.clients.claude_client import ClaudeLLMClient

    print("=" * 60)
    print("Claude/Vertex AI Authentication Test")
    print("=" * 60)
    print(f"  Project ID:       {PROJECT_ID}")
    print(f"  Region:           {REGION}")
    print(f"  Service Account:  {SERVICE_ACCOUNT_FILE}")
    print(f"  Model:            {MODEL}")
    print("=" * 60)

    if PROJECT_ID == "your-project-id":
        print("\nERROR: Please edit this script and set PROJECT_ID to your actual GCP project ID.")
        sys.exit(1)

    # Check if service account file exists
    sa_path = Path(SERVICE_ACCOUNT_FILE)
    if not sa_path.exists():
        # Try relative to project root
        sa_path = Path(__file__).parent.parent / SERVICE_ACCOUNT_FILE
    if not sa_path.exists():
        print(f"\nERROR: Service account file not found: {SERVICE_ACCOUNT_FILE}")
        print("       Place your GCP credentials JSON file at this location.")
        sys.exit(1)

    print("\n[1/3] Initializing ClaudeLLMClient...")
    try:
        client = ClaudeLLMClient(
            project_id=PROJECT_ID,
            region=REGION,
            service_account_file=str(sa_path),
            default_model=MODEL,
        )
        print("      OK - Client initialized")
    except Exception as e:
        print(f"      FAILED - {e}")
        sys.exit(1)

    print("\n[2/3] Testing authentication (calling Claude API)...")
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
        print("       - Claude API not enabled in your GCP project")
        print("       - Incorrect region for your project")
        sys.exit(1)

    print("\n[3/3] Validating response...")
    if response and len(response) > 0:
        print("      OK - Got response from Claude")
    else:
        print("      WARNING - Response was empty")

    print("\n" + "=" * 60)
    print("RESULT: All tests passed!")
    print("=" * 60)
    print(f"\nClaude response: {response}")


if __name__ == "__main__":
    test_claude_client()

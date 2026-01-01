#!/usr/bin/env python3
"""Minimal Claude (Vertex) smoke test.

This file lives under `scripts/` and is intended to be run manually, not as part
of the automated pytest suite. Keep module import side-effect free so `pytest`
can safely discover it.
"""

from __future__ import annotations

import os


def main() -> None:
    # Set credentials before importing client libraries.
    os.environ.setdefault("GOOGLE_APPLICATION_CREDENTIALS", "config/gcp-sa-key.json")

    from anthropic import AnthropicVertex

    client = AnthropicVertex(region="global", project_id="knox-dev-2")
    message = client.messages.create(
        max_tokens=1024,
        messages=[{"role": "user", "content": "Hello! Can you help me?"}],
        model="claude-sonnet-4-5@20250929",
    )
    print(message.content[0].text)


if __name__ == "__main__":
    main()

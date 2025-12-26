#!/usr/bin/env python3
"""Minimal test matching Anthropic quickstart exactly."""

import os

# Set credentials before importing
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "config/gcp-sa-key.json"

from anthropic import AnthropicVertex

client = AnthropicVertex(region="global", project_id="knox-dev-2")
message = client.messages.create(
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello! Can you help me?"}],
    model="claude-sonnet-4-5@20250929"
)
print(message.content[0].text)

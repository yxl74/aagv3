from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

import yaml


def load_settings(path: str | Path) -> Dict[str, Any]:
    path = Path(path)
    with path.open("r", encoding="utf-8") as handle:
        settings = yaml.safe_load(handle) or {}
    base_url = os.environ.get("KNOX_BASE_URL")
    if base_url:
        settings.setdefault("knox", {})["base_url"] = base_url
    android_root = os.environ.get("ANDROID_SDK_ROOT")
    if android_root:
        analysis = settings.setdefault("analysis", {})
        if not analysis.get("android_platforms_dir"):
            analysis["android_platforms_dir"] = str(Path(android_root) / "platforms")
    return settings

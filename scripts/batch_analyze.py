from __future__ import annotations

import argparse
from pathlib import Path

from apk_analyzer.agents.orchestrator import Orchestrator
from apk_analyzer.utils.config import load_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Batch APK analysis")
    parser.add_argument("--pairs", help="Path to file with apk_path,knox_id per line", required=True)
    parser.add_argument("--settings", default="config/settings.yaml")
    args = parser.parse_args()

    settings = load_settings(args.settings)
    orchestrator = Orchestrator(settings)

    for line in Path(args.pairs).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split(",", 1)]
        if len(parts) != 2:
            raise ValueError("Expected 'apk_path,knox_id' per line in pairs file")
        apk_path, knox_id = parts
        orchestrator.run(apk_path=apk_path, knox_apk_id=knox_id)


if __name__ == "__main__":
    main()

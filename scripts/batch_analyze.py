from __future__ import annotations

import argparse
from pathlib import Path

from apk_analyzer.agents.orchestrator import Orchestrator
from apk_analyzer.utils.config import load_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Batch APK analysis")
    parser.add_argument("--apk-list", help="Path to file containing APK paths")
    parser.add_argument("--knox-list", help="Path to file containing Knox APK IDs")
    parser.add_argument("--settings", default="config/settings.yaml")
    args = parser.parse_args()

    settings = load_settings(args.settings)
    orchestrator = Orchestrator(settings)

    if args.apk_list:
        for line in Path(args.apk_list).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            orchestrator.run(apk_path=line, knox_apk_id=None)

    if args.knox_list:
        for line in Path(args.knox_list).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            orchestrator.run(apk_path=None, knox_apk_id=line)


if __name__ == "__main__":
    main()

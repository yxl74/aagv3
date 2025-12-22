from __future__ import annotations

import argparse
from pathlib import Path

from apk_analyzer.agents.orchestrator import Orchestrator
from apk_analyzer.utils.config import load_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Batch APK analysis")
    parser.add_argument(
        "--mode",
        choices=["combined", "apk-only"],
        default="combined",
        help="Batch analysis mode (default: combined)",
    )
    parser.add_argument("--pairs", help="Path to file with apk_path,knox_id per line")
    parser.add_argument("--apk-list", help="Path to file with apk_path per line (apk-only)")
    parser.add_argument("--settings", default="config/settings.yaml")
    args = parser.parse_args()

    if args.mode == "combined" and not args.pairs:
        parser.error("--pairs is required when --mode is combined.")
    if args.mode == "apk-only" and not args.apk_list:
        parser.error("--apk-list is required when --mode is apk-only.")

    settings = load_settings(args.settings)
    orchestrator = Orchestrator(settings)

    if args.mode == "combined":
        for line in Path(args.pairs).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [part.strip() for part in line.split(",", 1)]
            if len(parts) != 2:
                raise ValueError("Expected 'apk_path,knox_id' per line in pairs file")
            apk_path, knox_id = parts
            orchestrator.run(apk_path=apk_path, knox_apk_id=knox_id, mode="combined")
    else:
        for line in Path(args.apk_list).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            orchestrator.run(apk_path=line, knox_apk_id=None, mode="apk-only")


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict

from apk_analyzer.agents.orchestrator import Orchestrator
from apk_analyzer.utils.config import load_settings


def _apply_overrides(settings: Dict[str, Any], args: argparse.Namespace) -> None:
    analysis = settings.setdefault("analysis", {})
    if args.android_platforms:
        analysis["android_platforms_dir"] = args.android_platforms
    if args.flowdroid_jar:
        analysis["flowdroid_jar_path"] = args.flowdroid_jar
    if args.soot_jar:
        analysis["soot_extractor_jar_path"] = args.soot_jar


def main() -> None:
    parser = argparse.ArgumentParser(description="APK analysis agent")
    parser.add_argument("--apk", help="Path to APK file")
    parser.add_argument("--knox-id", help="Knox APK ID")
    parser.add_argument("--settings", default="config/settings.yaml", help="Settings YAML path")
    parser.add_argument("--android-platforms", help="Android SDK platforms directory")
    parser.add_argument("--flowdroid-jar", help="Path to FlowDroid CLI jar")
    parser.add_argument("--soot-jar", help="Path to Soot extractor jar")

    args = parser.parse_args()
    if not (args.apk and args.knox_id):
        parser.error("Both --apk and --knox-id are required for analysis.")
    settings = load_settings(args.settings)
    _apply_overrides(settings, args)

    orchestrator = Orchestrator(settings)
    report = orchestrator.run(apk_path=args.apk, knox_apk_id=args.knox_id)
    print(f"Report written for {report.get('analysis_id')}")


if __name__ == "__main__":
    main()

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

from apk_analyzer.telemetry import span

def run_soot_extractor(
    apk_path: str | Path,
    android_platforms_dir: str | Path,
    out_dir: str | Path,
    jar_path: str | Path,
    cg_algo: str = "SPARK",
    k_hop: int = 2,
    target_sdk: int | None = None,
    android_jar: str | Path | None = None,
    timeout_sec: int = 600,
) -> Optional[Path]:
    apk_path = Path(apk_path)
    android_platforms_dir = Path(android_platforms_dir)
    out_dir = Path(out_dir)
    jar_path = Path(jar_path)
    if not jar_path.exists():
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "java",
        "-jar",
        str(jar_path),
        "--apk",
        str(apk_path),
        "--android-platforms",
        str(android_platforms_dir),
        "--out",
        str(out_dir),
        "--cg-algo",
        cg_algo,
        "--k-hop",
        str(k_hop),
    ]
    if target_sdk:
        cmd.extend(["--target-sdk", str(target_sdk)])
    if android_jar:
        cmd.extend(["--android-jar", str(android_jar)])
    with span("tool.soot", tool_name="soot", cg_algo=cg_algo, k_hop=k_hop, timeout_sec=timeout_sec):
        subprocess.run(cmd, check=True, timeout=timeout_sec)
    return out_dir

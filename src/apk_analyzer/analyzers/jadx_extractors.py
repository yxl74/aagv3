from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Optional


def _resolve_jadx(jadx_path: str | Path) -> Optional[Path]:
    path = Path(jadx_path)
    if path.exists():
        return path
    found = shutil.which(str(jadx_path))
    if found:
        return Path(found)
    return None


def run_jadx(
    apk_path: str | Path,
    out_dir: str | Path,
    jadx_path: str | Path = "jadx",
    timeout_sec: int = 600,
) -> Optional[Path]:
    jadx_bin = _resolve_jadx(jadx_path)
    if not jadx_bin:
        return None
    apk_path = Path(apk_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if jadx_bin.suffix == ".jar":
        cmd = ["java", "-jar", str(jadx_bin), "-d", str(out_dir), str(apk_path)]
    else:
        cmd = [str(jadx_bin), "-d", str(out_dir), str(apk_path)]

    try:
        subprocess.run(cmd, check=True, timeout=timeout_sec)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return out_dir


def find_jadx_manifest(jadx_root: str | Path) -> Optional[Path]:
    root = Path(jadx_root)
    candidates = [
        root / "resources" / "AndroidManifest.xml",
        root / "AndroidManifest.xml",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None

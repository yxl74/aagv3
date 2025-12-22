from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Sequence

DEFAULT_EXTENSIONS = {".java", ".kt", ".xml", ".smali"}


def search_source_code(
    root_dir: str | Path,
    query: str,
    limit: int = 20,
    extensions: Optional[Sequence[str]] = None,
    max_bytes: int = 1_000_000,
) -> List[Dict[str, str]]:
    root = Path(root_dir)
    exts = set(extensions) if extensions else DEFAULT_EXTENSIONS
    hits: List[Dict[str, str]] = []
    if not root.exists():
        return hits

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in exts:
            continue
        try:
            if path.stat().st_size > max_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if query not in text:
            continue
        sample = ""
        for line in text.splitlines():
            if query in line:
                sample = line.strip()
                break
        hits.append({
            "file_path": str(path.relative_to(root)),
            "match": query,
            "line": sample,
        })
        if len(hits) >= limit:
            break
    return hits


def get_source_file(root_dir: str | Path, rel_path: str, max_bytes: int = 2_000_000) -> str:
    root = Path(root_dir)
    path = root / rel_path
    if not path.exists():
        raise FileNotFoundError(str(path))
    data = path.read_bytes()
    if len(data) > max_bytes:
        data = data[:max_bytes]
    return data.decode("utf-8", errors="ignore")

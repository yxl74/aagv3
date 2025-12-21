from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


class ArtifactStore:
    def __init__(self, base_dir: str | Path, analysis_id: str) -> None:
        self.base_dir = Path(base_dir)
        self.analysis_id = analysis_id
        self.root = self.base_dir / analysis_id

    @classmethod
    def from_inputs(
        cls,
        base_dir: str | Path,
        apk_path: str | Path | None = None,
        knox_apk_id: str | None = None,
    ) -> "ArtifactStore":
        if apk_path:
            apk_path = Path(apk_path)
            analysis_id = _sha256_file(apk_path)
        elif knox_apk_id:
            analysis_id = knox_apk_id
        else:
            raise ValueError("apk_path or knox_apk_id is required")
        return cls(base_dir, analysis_id)

    def ensure_dir(self, *parts: str) -> Path:
        path = self.root.joinpath(*parts)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def path(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    def write_json(self, rel_path: str, data: Any) -> Path:
        path = self.path(rel_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=True)
        return path

    def write_text(self, rel_path: str, text: str) -> Path:
        path = self.path(rel_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def write_bytes(self, rel_path: str, data: bytes) -> Path:
        path = self.path(rel_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def read_json(self, rel_path: str) -> Any:
        path = self.path(rel_path)
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def list_dirs(self, rel_path: str) -> Iterable[Path]:
        path = self.path(rel_path)
        if not path.exists():
            return []
        return [p for p in path.iterdir() if p.is_dir()]

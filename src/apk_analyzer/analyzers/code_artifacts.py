from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


_STRING_CONST_RE = re.compile(
    r"\b(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?String\s+(\w+)\s*=\s*\"([^\"]+)\""
)
_STRING_LITERAL_RE = re.compile(r"\"([^\"]+)\"")

_FILE_CONTEXT_RE = re.compile(
    r"(FileOutputStream|openFileOutput|setOutputFile|Files\.newOutputStream|new File\()"
)
_LOG_RE = re.compile(r"\bLog\.(\w+)\s*\(\s*([^,]+)\s*,\s*([^)]+)\)")

_FILE_EXTENSIONS = (
    ".zip", ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".mp4", ".mp3", ".wav", ".aac",
    ".txt", ".json", ".db", ".log", ".bin",
)

_DIR_PREFIXES = {
    "cacheDir": "cacheDir/",
    "getCacheDir": "cacheDir/",
    "externalCacheDir": "externalCacheDir/",
    "getExternalCacheDir": "externalCacheDir/",
    "filesDir": "filesDir/",
    "getFilesDir": "filesDir/",
    "externalFilesDir": "externalFilesDir/",
    "getExternalFilesDir": "externalFilesDir/",
}


def extract_file_artifacts(jadx_root: Path) -> Dict[str, Any]:
    """
    Extract file write/read artifacts from decompiled source.
    Returns mapping: component -> list of artifacts.
    """
    source_root = _resolve_sources_root(jadx_root)
    artifacts: Dict[str, List[Dict[str, Any]]] = {}

    for path in _iter_source_files(source_root):
        class_name = _class_name_from_path(source_root, path)
        if not class_name:
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not source:
            continue
        cleaned = _strip_comments(source)
        constants = _extract_string_constants(cleaned)

        for line in cleaned.splitlines():
            if not _FILE_CONTEXT_RE.search(line):
                continue
            expanded = _expand_constants(line, constants)
            path_hints = _extract_path_hints(expanded)
            if not path_hints:
                continue
            for hint in path_hints:
                _add_artifact(artifacts, class_name, hint, line)

    return artifacts


def extract_log_hints(jadx_root: Path) -> Dict[str, Any]:
    """
    Extract Log.* tags/messages from decompiled source.
    Returns mapping: component -> list of log hints.
    """
    source_root = _resolve_sources_root(jadx_root)
    hints: Dict[str, List[Dict[str, Any]]] = {}

    for path in _iter_source_files(source_root):
        class_name = _class_name_from_path(source_root, path)
        if not class_name:
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not source:
            continue
        cleaned = _strip_comments(source)
        constants = _extract_string_constants(cleaned)
        for line in cleaned.splitlines():
            match = _LOG_RE.search(line)
            if not match:
                continue
            level, tag_expr, msg_expr = match.groups()
            tag = _resolve_token(tag_expr, constants)
            message = _resolve_token(msg_expr, constants)
            if not tag or not message:
                continue
            entry = {
                "tag": tag,
                "message": message,
                "level": level.lower(),
            }
            _add_hint(hints, class_name, entry)

    return hints


def _resolve_sources_root(root: Path) -> Path:
    candidates = [
        root / "sources",
        root / "app" / "src" / "main" / "java",
        root / "app" / "src" / "main" / "kotlin",
        root,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return root


def _iter_source_files(root: Path) -> List[Path]:
    files: List[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in (".java", ".kt"):
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
        except OSError:
            continue
        files.append(path)
    return files


def _class_name_from_path(root: Path, path: Path) -> Optional[str]:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return None
    if rel.suffix not in (".java", ".kt"):
        return None
    parts = list(rel.with_suffix("").parts)
    if not parts:
        return None
    return ".".join(parts)


def _strip_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    source = re.sub(r"//.*", "", source)
    return source


def _extract_string_constants(source: str) -> Dict[str, str]:
    constants: Dict[str, str] = {}
    for match in _STRING_CONST_RE.finditer(source):
        name, value = match.groups()
        if name and value:
            constants[name] = value
    return constants


def _expand_constants(line: str, constants: Dict[str, str]) -> str:
    expanded = line
    for name, value in constants.items():
        if name in expanded:
            expanded = re.sub(rf"\\b{name}\\b", f"\"{value}\"", expanded)
    return expanded


def _extract_path_hints(line: str) -> List[str]:
    literals = _STRING_LITERAL_RE.findall(line)
    if not literals:
        return []
    prefix = _dir_prefix_from_line(line)
    hints: List[str] = []
    for literal in literals:
        if _is_extension_literal(literal):
            continue
        if _is_file_literal(literal) or prefix:
            hint = literal
            if prefix and not hint.startswith("/") and "/" not in hint:
                hint = f"{prefix}{hint}"
            hints.append(hint)
    if len(literals) >= 2:
        joined = _join_literals(literals)
        if joined:
            if prefix and not joined.startswith("/") and "/" not in joined:
                joined = f"{prefix}{joined}"
            hints.append(joined)
    return list(dict.fromkeys(hints))


def _join_literals(literals: List[str]) -> Optional[str]:
    if len(literals) < 2:
        return None
    left = literals[0].lstrip("/")
    right = literals[-1]
    if not _is_file_literal(right):
        return None
    return f"{left}*{right}"


def _dir_prefix_from_line(line: str) -> Optional[str]:
    for key, prefix in _DIR_PREFIXES.items():
        if key in line:
            return prefix
    return None


def _is_file_literal(literal: str) -> bool:
    if "/" in literal:
        return True
    return literal.lower().endswith(_FILE_EXTENSIONS)


def _is_extension_literal(literal: str) -> bool:
    if not literal.startswith("."):
        return False
    return literal.lower() in _FILE_EXTENSIONS


def _add_artifact(
    artifacts: Dict[str, List[Dict[str, Any]]],
    class_name: str,
    path_hint: str,
    line: str,
) -> None:
    if not path_hint:
        return
    entry = {
        "path_hint": path_hint,
        "line": line.strip()[:200],
    }
    bucket = artifacts.setdefault(class_name, [])
    if any(item.get("path_hint") == path_hint for item in bucket):
        return
    if len(bucket) >= 20:
        return
    bucket.append(entry)


def _resolve_token(token: str, constants: Dict[str, str]) -> Optional[str]:
    token = token.strip()
    token = token.replace("this.", "")
    if token.startswith("\"") and token.endswith("\"") and len(token) >= 2:
        return token[1:-1]
    if token in constants:
        return constants[token]
    if "." in token:
        tail = token.split(".")[-1]
        if tail in constants:
            return constants[tail]
    literals = _STRING_LITERAL_RE.findall(token)
    if literals:
        return literals[0]
    return None


def _add_hint(hints: Dict[str, List[Dict[str, Any]]], class_name: str, entry: Dict[str, Any]) -> None:
    bucket = hints.setdefault(class_name, [])
    key = (entry.get("tag"), entry.get("message"))
    if any((item.get("tag"), item.get("message")) == key for item in bucket):
        return
    if len(bucket) >= 30:
        return
    bucket.append(entry)

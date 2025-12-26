from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


_STRING_CONST_RE = re.compile(
    r"\b(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?String\s+(\w+)\s*=\s*\"([^\"]+)\""
)

_GETTER_TYPES = {
    "getStringExtra": "string",
    "getCharSequenceExtra": "string",
    "getIntExtra": "int",
    "getBooleanExtra": "boolean",
    "getLongExtra": "long",
    "getFloatExtra": "float",
    "getDoubleExtra": "double",
    "getParcelableExtra": "parcelable",
    "getSerializableExtra": "serializable",
    "getStringArrayExtra": "string_array",
    "getIntArrayExtra": "int_array",
}

_GET_EXTRA_RE = re.compile(r"\.(get\w+Extra)\s*\(\s*([^,\)]+?)\s*(?:,|\))")
_HAS_EXTRA_RE = re.compile(r"\.hasExtra\s*\(\s*([^)]+?)\s*\)")
_PUT_EXTRA_RE = re.compile(r"\.putExtra\s*\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)")
_SET_ACTION_RE = re.compile(r"\.setAction\s*\(\s*([^)]+?)\s*\)")
_STR_EQUALS_RE = re.compile(
    r"Objects\.equals\([^,]*getStringExtra\s*\(\s*([^)]+?)\s*\)\s*,\s*([^)]+?)\s*\)"
)
_STR_EQUALS_METHOD_RE = re.compile(
    r"getStringExtra\s*\(\s*([^)]+?)\s*\)\s*\.\s*equals\s*\(\s*([^)]+?)\s*\)"
)


def extract_intent_contracts(jadx_root: Path, manifest: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract intent extra contracts from decompiled source.

    Returns a mapping of component class name -> contract:
    {
        "com.pkg.MyService": {
            "component_type": "service",
            "extras": [
                {"name": "ACTION", "type": "string", "required": True, "value_hints": ["START"]},
                ...
            ],
            "actions": ["com.pkg.ACTION_START"]
        }
    }
    """
    if not jadx_root or not Path(jadx_root).exists():
        return {}

    source_root = _resolve_sources_root(Path(jadx_root))
    components = _collect_components(manifest)
    contracts: Dict[str, Any] = {}

    for class_name, comp_type in components:
        source_path = _find_source_file(source_root, class_name)
        if not source_path:
            continue
        try:
            source = source_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not source:
            continue

        cleaned = _strip_comments(source)
        constants = _extract_string_constants(cleaned)
        extras = _extract_extras(cleaned, constants)
        actions = _extract_actions(cleaned, constants)

        if extras or actions:
            contracts[class_name] = {
                "component_type": comp_type,
                "extras": extras,
                "actions": actions,
            }

    return contracts


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


def _collect_components(manifest: Dict[str, Any]) -> List[Tuple[str, str]]:
    package_name = manifest.get("package_name") or manifest.get("package") or ""
    components: List[Tuple[str, str]] = []
    for comp_type, key in (
        ("activity", "activities"),
        ("service", "services"),
        ("receiver", "receivers"),
        ("provider", "providers"),
    ):
        for name in manifest.get(key, []) or []:
            if not name:
                continue
            if isinstance(name, dict):
                name = name.get("name")
            if not isinstance(name, str):
                continue
            if name.startswith(".") and package_name:
                full = package_name + name
            else:
                full = name
            components.append((full, comp_type))
    return components


def _find_source_file(source_root: Path, class_name: str) -> Optional[Path]:
    if not class_name:
        return None
    outer_class = class_name.split("$")[0]
    relative = Path(*outer_class.split("."))
    for suffix in (".java", ".kt"):
        candidate = (source_root / relative).with_suffix(suffix)
        if candidate.exists():
            return candidate
    return None


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


def _clean_token(token: str) -> str:
    token = token.strip()
    token = token.strip(");")
    token = re.sub(r"^\(([^)]+)\)", "", token).strip()
    token = token.replace("this.", "")
    return token


def _resolve_token(token: str, constants: Dict[str, str]) -> Optional[str]:
    if not token:
        return None
    token = _clean_token(token)
    if token.startswith("\"") and token.endswith("\"") and len(token) >= 2:
        return token[1:-1]
    if token in constants:
        return constants[token]
    if "." in token:
        tail = token.split(".")[-1]
        if tail in constants:
            return constants[tail]
    return None


def _value_hint_from_token(token: str, constants: Dict[str, str]) -> Optional[str]:
    token = _clean_token(token)
    resolved = _resolve_token(token, constants)
    if resolved is not None:
        return resolved
    if re.fullmatch(r"-?\d+", token):
        return token
    if token in ("true", "false"):
        return token
    return None


def _extract_extras(source: str, constants: Dict[str, str]) -> List[Dict[str, Any]]:
    extras: Dict[str, Dict[str, Any]] = {}

    def ensure_extra(name: str) -> Dict[str, Any]:
        if name not in extras:
            extras[name] = {
                "name": name,
                "required": False,
                "types": set(),
                "value_hints": set(),
            }
        return extras[name]

    for match in _GET_EXTRA_RE.finditer(source):
        method, arg = match.groups()
        extra_type = _GETTER_TYPES.get(method, "unknown")
        key = _resolve_token(arg, constants) or _clean_token(arg)
        if not key:
            continue
        entry = ensure_extra(key)
        entry["types"].add(extra_type)

    for match in _HAS_EXTRA_RE.finditer(source):
        arg = match.group(1)
        key = _resolve_token(arg, constants) or _clean_token(arg)
        if not key:
            continue
        entry = ensure_extra(key)
        entry["required"] = True

    for match in _PUT_EXTRA_RE.finditer(source):
        key_arg, value_arg = match.groups()
        key = _resolve_token(key_arg, constants) or _clean_token(key_arg)
        if not key:
            continue
        entry = ensure_extra(key)
        value_hint = _value_hint_from_token(value_arg, constants)
        if value_hint is not None:
            entry["value_hints"].add(value_hint)
        if value_hint in ("true", "false"):
            entry["types"].add("boolean")
        elif value_hint and re.fullmatch(r"-?\d+", value_hint):
            entry["types"].add("int")

    for match in _STR_EQUALS_RE.finditer(source):
        key_arg, value_arg = match.groups()
        key = _resolve_token(key_arg, constants) or _clean_token(key_arg)
        if not key:
            continue
        entry = ensure_extra(key)
        entry["required"] = True
        value_hint = _value_hint_from_token(value_arg, constants)
        if value_hint is not None:
            entry["value_hints"].add(value_hint)
        entry["types"].add("string")

    for match in _STR_EQUALS_METHOD_RE.finditer(source):
        key_arg, value_arg = match.groups()
        key = _resolve_token(key_arg, constants) or _clean_token(key_arg)
        if not key:
            continue
        entry = ensure_extra(key)
        entry["required"] = True
        value_hint = _value_hint_from_token(value_arg, constants)
        if value_hint is not None:
            entry["value_hints"].add(value_hint)
        entry["types"].add("string")

    results: List[Dict[str, Any]] = []
    for entry in extras.values():
        types = sorted(t for t in entry["types"] if t)
        extra_type = types[0] if len(types) == 1 else "mixed"
        results.append({
            "name": entry["name"],
            "type": extra_type,
            "required": bool(entry["required"]),
            "value_hints": sorted(entry["value_hints"]),
        })
    return sorted(results, key=lambda x: x["name"])


def _extract_actions(source: str, constants: Dict[str, str]) -> List[str]:
    actions: set[str] = set()
    for match in _SET_ACTION_RE.finditer(source):
        arg = match.group(1)
        resolved = _resolve_token(arg, constants)
        if resolved:
            actions.add(resolved)
    return sorted(actions)

from __future__ import annotations

import re
import shlex
from typing import Any, Dict, List, Optional, Tuple


_EXTRA_FLAG_TYPES = {
    "string": "--es",
    "string_array": "--esa",
    "int": "--ei",
    "int_array": "--eia",
    "long": "--el",
    "boolean": "--ez",
    "float": "--ef",
    "double": "--ed",
}

_NON_INJECTABLE_TYPES = {"parcelable", "serializable", "unknown", "mixed"}


def validate_execution_guidance(
    guidance: Dict[str, Any],
    intent_contracts: Dict[str, Any],
    file_artifacts: Optional[Dict[str, Any]] = None,
    log_hints: Optional[Dict[str, Any]] = None,
    package_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Normalize execution guidance and enforce intent contracts when possible.
    """
    if not guidance:
        return guidance
    intent_contracts = intent_contracts or {}

    steps = guidance.get("steps") or []
    if not isinstance(steps, list):
        return guidance

    pkg_name = package_name or guidance.get("package_name") or ""

    for idx, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        if step.get("type") == "adb":
            command = step.get("command") or ""
            if command:
                command = _ensure_adb_prefix(command)
                step["command"] = command
                if _is_am_start_command(command):
                    component = _extract_component(command, pkg_name)
                    contract = _find_contract(intent_contracts, component)
                    if contract:
                        step.update(_apply_contract_to_step(step, contract))
                    if not step.get("verify"):
                        _attach_verification(step, component, file_artifacts or {}, log_hints or {}, pkg_name)
        elif step.get("type") == "frida":
            _ensure_frida_capture(step, idx + 1)
    return guidance


def _ensure_adb_prefix(command: str) -> str:
    if command.startswith("adb "):
        return command
    if command.startswith("shell "):
        return f"adb {command}"
    return f"adb shell {command}"


def _is_am_start_command(command: str) -> bool:
    return (
        "am start" in command
        or "am startservice" in command
        or "am start-foreground-service" in command
        or "am broadcast" in command
    )


def _extract_component(command: str, package_name: str) -> Optional[str]:
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    for idx, tok in enumerate(tokens):
        if tok in ("-n", "--component") and idx + 1 < len(tokens):
            comp = tokens[idx + 1]
            return _normalize_component(comp, package_name)
    return None


def _normalize_component(component: str, package_name: str) -> Optional[str]:
    if not component:
        return None
    if "/" in component:
        pkg, cls = component.split("/", 1)
        if cls.startswith(".") and pkg:
            return f"{pkg}{cls}"
        if cls:
            return cls
        return pkg
    if component.startswith(".") and package_name:
        return f"{package_name}{component}"
    return component


def _find_contract(intent_contracts: Dict[str, Any], component: Optional[str]) -> Optional[Dict[str, Any]]:
    if not component:
        return None
    if component in intent_contracts:
        return intent_contracts[component]
    if "$" in component:
        outer = component.split("$")[0]
        return intent_contracts.get(outer)
    return None


def _apply_contract_to_step(step: Dict[str, Any], contract: Dict[str, Any]) -> Dict[str, Any]:
    command = step.get("command") or ""
    extras_present = _extract_extras_from_command(command)
    required_extras = [e for e in contract.get("extras", []) if e.get("required")]
    missing = [e for e in required_extras if e.get("name") not in extras_present]

    if not missing:
        return step

    updated_command, added_names = _append_extras(command, missing)
    remaining = [e for e in missing if e.get("name") not in added_names]
    if remaining:
        step["type"] = "manual"
        step["command"] = _manualize_command(command, remaining)
        return step

    step["command"] = updated_command
    return step


def _extract_extras_from_command(command: str) -> set[str]:
    extras: set[str] = set()
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if tok in ("--es", "--ei", "--el", "--ez", "--ef", "--ed", "--esa", "--eia", "--eu", "--ecn"):
            if idx + 1 < len(tokens):
                extras.add(tokens[idx + 1])
            idx += 3
            continue
        if tok == "--esn":
            if idx + 1 < len(tokens):
                extras.add(tokens[idx + 1])
            idx += 2
            continue
        idx += 1
    return extras


def _append_extras(command: str, missing: List[Dict[str, Any]]) -> Tuple[str, set[str]]:
    added: set[str] = set()
    updated = command
    for extra in missing:
        name = extra.get("name")
        if not name:
            continue
        extra_type = extra.get("type") or "unknown"
        if extra_type in _NON_INJECTABLE_TYPES:
            continue
        value_hint = _pick_value_hint(extra)
        if value_hint is None:
            continue
        flag = _EXTRA_FLAG_TYPES.get(extra_type, "--es")
        value = value_hint if _is_numeric(value_hint) or flag in ("--ei", "--el") else shlex.quote(value_hint)
        updated = f"{updated} {flag} {name} {value}"
        added.add(name)
    return updated, added


def _pick_value_hint(extra: Dict[str, Any]) -> Optional[str]:
    for hint in extra.get("value_hints") or []:
        if hint is None:
            continue
        if _is_safe_hint(hint):
            return str(hint)
    return None


def _is_safe_hint(value: str) -> bool:
    if _is_numeric(value):
        return True
    return bool(re.fullmatch(r"[A-Za-z0-9_.:-]+", value))


def _is_numeric(value: str) -> bool:
    return bool(re.fullmatch(r"-?\d+", str(value)))


def _manualize_command(command: str, missing: List[Dict[str, Any]]) -> str:
    missing_names = [m.get("name") for m in missing if m.get("name")]
    return f"MANUAL: missing required extras {missing_names}. {command}"


def _ensure_frida_capture(step: Dict[str, Any], step_index: int) -> None:
    command = step.get("command") or ""
    if not command or "frida" not in command:
        return
    log_path = step.get("log_path") or f"evidence/frida_step_{step.get('step_id') or step_index}.log"
    if "tee " not in command and "evidence/" not in command:
        command = f"mkdir -p evidence && {command} 2>&1 | tee {log_path}"
        step["command"] = command

    verify = step.get("verify") or {}
    verify_cmd = verify.get("command") or ""
    expected = verify.get("expect_contains")
    if "logcat" in verify_cmd and expected:
        step["verify"] = {
            "command": f"grep -n {shlex.quote(expected)} {log_path}",
            "expect_contains": expected,
        }


def _attach_verification(
    step: Dict[str, Any],
    component: Optional[str],
    file_artifacts: Dict[str, Any],
    log_hints: Dict[str, Any],
    package_name: str,
) -> None:
    if step.get("verify") or not component:
        return
    logs = log_hints.get(component) or log_hints.get(component.split("$")[0]) if component else None
    if logs:
        entry = logs[0]
        tag = entry.get("tag")
        message = entry.get("message")
        if tag and message:
            step["verify"] = {
                "command": f"adb logcat -d -s {tag} | grep {shlex.quote(message)}",
                "expect_contains": message,
            }
            return

    artifacts = file_artifacts.get(component) or file_artifacts.get(component.split("$")[0]) if component else None
    if not artifacts:
        return
    resolved = None
    for artifact in artifacts:
        hint = artifact.get("path_hint")
        if not _is_stable_path_hint(hint):
            continue
        resolved = _resolve_path_hint(hint, package_name)
        if resolved:
            break
    if resolved:
        base = resolved.split("/")[-1]
        step["verify"] = {
            "command": f"adb shell ls {resolved}",
            "expect_contains": base,
        }


def _resolve_path_hint(path_hint: Optional[str], package_name: str) -> Optional[str]:
    if not path_hint:
        return None
    if path_hint.startswith("/"):
        if _looks_like_absolute_file(path_hint):
            return path_hint
        return None
    if path_hint.startswith("cacheDir/") and package_name:
        return f"/data/data/{package_name}/cache/{path_hint.split('/', 1)[1]}"
    if path_hint.startswith("filesDir/") and package_name:
        return f"/data/data/{package_name}/files/{path_hint.split('/', 1)[1]}"
    if path_hint.startswith("externalCacheDir/") and package_name:
        return f"/sdcard/Android/data/{package_name}/cache/{path_hint.split('/', 1)[1]}"
    if path_hint.startswith("externalFilesDir/") and package_name:
        return f"/sdcard/Android/data/{package_name}/files/{path_hint.split('/', 1)[1]}"
    return None


def _looks_like_absolute_file(path_hint: str) -> bool:
    if path_hint.count("/") >= 2:
        return True
    if "." in path_hint:
        return True
    return False


def _is_stable_path_hint(path_hint: Optional[str]) -> bool:
    if not path_hint:
        return False
    name = path_hint.split("/")[-1]
    if "*" in name or "?" in name:
        return False
    if name.endswith("_"):
        return False
    if "." not in name:
        return False
    return True

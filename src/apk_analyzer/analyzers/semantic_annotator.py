"""
Method-context-aware semantic annotator for Jimple statements.

Annotates numeric constants in Jimple bytecode with their semantic meanings,
but ONLY when the method context is known to avoid false positives.

For example:
- setAudioSource(1) → setAudioSource(1 /* MIC */)
- randomMethod(1)   → randomMethod(1)  (no annotation, unknown context)

This prevents the LLM from seeing raw integers without understanding their
semantic meaning in the Android API context.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple


# =============================================================================
# ENUM DEFINITIONS BY TYPE
# =============================================================================

# These are separated by enum type to avoid collision
# (e.g., "1" means different things in AudioSource vs OutputFormat)

AUDIO_SOURCE_ENUM = {
    "0": "DEFAULT",
    "1": "MIC",
    "4": "CAMCORDER",
    "5": "VOICE_RECOGNITION",
    "6": "VOICE_COMMUNICATION",
    "7": "REMOTE_SUBMIX",
    "9": "UNPROCESSED",
}

OUTPUT_FORMAT_ENUM = {
    "0": "DEFAULT",
    "1": "THREE_GPP",
    "2": "MPEG_4",
    "3": "AMR_NB",
    "4": "AMR_WB",
    "6": "WEBM",
}

AUDIO_ENCODER_ENUM = {
    "0": "DEFAULT",
    "1": "AMR_NB",
    "2": "AMR_WB",
    "3": "AAC",
    "4": "HE_AAC",
    "5": "AAC_ELD",
    "6": "VORBIS",
    "7": "OPUS",
}

VIDEO_SOURCE_ENUM = {
    "0": "DEFAULT",
    "1": "CAMERA",
    "2": "SURFACE",
}

WINDOW_TYPE_ENUM = {
    "1": "TYPE_BASE_APPLICATION",
    "2": "TYPE_APPLICATION",
    "3": "TYPE_APPLICATION_STARTING",
    "1000": "TYPE_STATUS_BAR",
    "2002": "TYPE_SYSTEM_ALERT",
    "2003": "TYPE_TOAST",
    "2010": "TYPE_SYSTEM_OVERLAY",
    "2038": "TYPE_APPLICATION_OVERLAY",
}

WINDOW_FLAG_ENUM = {
    "1": "FLAG_ALLOW_LOCK_WHILE_SCREEN_ON",
    "2": "FLAG_DIM_BEHIND",
    "4": "FLAG_NOT_TOUCH_MODAL",
    "8": "FLAG_NOT_FOCUSABLE",
    "16": "FLAG_NOT_TOUCHABLE",
    "32": "FLAG_WATCH_OUTSIDE_TOUCH",
    "256": "FLAG_FULLSCREEN",
    "16777216": "FLAG_HARDWARE_ACCELERATED",
}

FOREGROUND_SERVICE_TYPE_ENUM = {
    "0": "FOREGROUND_SERVICE_TYPE_MANIFEST",
    "1": "FOREGROUND_SERVICE_TYPE_DATA_SYNC",
    "2": "FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK",
    "4": "FOREGROUND_SERVICE_TYPE_PHONE_CALL",
    "8": "FOREGROUND_SERVICE_TYPE_LOCATION",
    "16": "FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE",
    "64": "FOREGROUND_SERVICE_TYPE_CAMERA",
    "128": "FOREGROUND_SERVICE_TYPE_MICROPHONE",
    "256": "FOREGROUND_SERVICE_TYPE_HEALTH",
    "512": "FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING",
    "1024": "FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED",
    "1073741824": "FOREGROUND_SERVICE_TYPE_SHORT_SERVICE",
}

INTENT_FLAG_ENUM = {
    "268435456": "FLAG_ACTIVITY_NEW_TASK",
    "67108864": "FLAG_ACTIVITY_CLEAR_TASK",
    "536870912": "FLAG_ACTIVITY_SINGLE_TOP",
    "33554432": "FLAG_ACTIVITY_CLEAR_TOP",
    "524288": "FLAG_ACTIVITY_NEW_DOCUMENT",
    "32": "FLAG_GRANT_READ_URI_PERMISSION",
    "64": "FLAG_GRANT_WRITE_URI_PERMISSION",
}

PIXEL_FORMAT_ENUM = {
    "0": "UNKNOWN",
    "1": "RGBA_8888",
    "-1": "OPAQUE",
    "-2": "TRANSPARENT",
    "-3": "TRANSLUCENT",
}

GRAVITY_ENUM = {
    "0": "NO_GRAVITY",
    "1": "LEFT",
    "3": "TOP",
    "5": "RIGHT",
    "16": "CENTER_VERTICAL",
    "17": "CENTER",
    "48": "TOP|CENTER_HORIZONTAL",
    "80": "BOTTOM",
}

SMS_STATUS_ENUM = {
    "-1": "STATUS_NONE",
    "0": "STATUS_COMPLETE",
    "32": "STATUS_PENDING",
    "64": "STATUS_FAILED",
}


# =============================================================================
# METHOD TO ENUM TYPE MAPPING
# =============================================================================

@dataclass
class MethodEnumInfo:
    """Information about which enum a method parameter uses."""
    enum_map: Dict[str, str]
    param_index: int = 0  # 0-based index of the parameter to annotate
    enum_name: str = ""   # Human-readable name for the enum


# Maps method names (case-insensitive) to their enum info
# Only first matching parameter is annotated to avoid over-annotation
METHOD_ENUM_MAP: Dict[str, MethodEnumInfo] = {
    # MediaRecorder
    "setaudiosource": MethodEnumInfo(AUDIO_SOURCE_ENUM, 0, "AudioSource"),
    "setoutputformat": MethodEnumInfo(OUTPUT_FORMAT_ENUM, 0, "OutputFormat"),
    "setaudioencoder": MethodEnumInfo(AUDIO_ENCODER_ENUM, 0, "AudioEncoder"),
    "setvideosource": MethodEnumInfo(VIDEO_SOURCE_ENUM, 0, "VideoSource"),

    # WindowManager.LayoutParams
    "settype": MethodEnumInfo(WINDOW_TYPE_ENUM, 0, "WindowType"),
    "setflags": MethodEnumInfo(WINDOW_FLAG_ENUM, 0, "WindowFlags"),

    # Service.startForeground
    "startforeground": MethodEnumInfo(FOREGROUND_SERVICE_TYPE_ENUM, 1, "ForegroundServiceType"),

    # Intent.setFlags / addFlags
    "setflags": MethodEnumInfo(INTENT_FLAG_ENUM, 0, "IntentFlags"),
    "addflags": MethodEnumInfo(INTENT_FLAG_ENUM, 0, "IntentFlags"),

    # LayoutParams construction (common patterns)
    # WindowManager.LayoutParams constructor often uses type as param
    "layoutparams": MethodEnumInfo(WINDOW_TYPE_ENUM, 0, "WindowType"),
}

# Additional method signatures for disambiguation (for overloaded methods)
# Format: "classname.methodname" or just methodname for common patterns
QUALIFIED_METHOD_ENUM_MAP: Dict[str, MethodEnumInfo] = {
    "android.media.MediaRecorder.setAudioSource": MethodEnumInfo(AUDIO_SOURCE_ENUM, 0, "AudioSource"),
    "android.media.MediaRecorder.setOutputFormat": MethodEnumInfo(OUTPUT_FORMAT_ENUM, 0, "OutputFormat"),
    "android.media.MediaRecorder.setAudioEncoder": MethodEnumInfo(AUDIO_ENCODER_ENUM, 0, "AudioEncoder"),
    "android.media.MediaRecorder.setVideoSource": MethodEnumInfo(VIDEO_SOURCE_ENUM, 0, "VideoSource"),
    "android.view.WindowManager.LayoutParams.<init>": MethodEnumInfo(WINDOW_TYPE_ENUM, 2, "WindowType"),
    "android.app.Service.startForeground": MethodEnumInfo(FOREGROUND_SERVICE_TYPE_ENUM, 1, "ForegroundServiceType"),
}


# =============================================================================
# ANNOTATOR IMPLEMENTATION
# =============================================================================

# Regex to match method invocations in Jimple
# Examples:
#   virtualinvoke $r1.<android.media.MediaRecorder: void setAudioSource(int)>(1)
#   specialinvoke $r2.<init>(...)
_JIMPLE_INVOKE_RE = re.compile(
    r'(invoke\w*)\s*'                           # invoke type
    r'(\$?\w+)\.'                               # receiver
    r'<([^:]+):\s*([^>]+)>\s*'                  # class: return_type method(params)
    r'\(([^)]*)\)'                              # arguments
)

# Regex to extract method name from Jimple signature
_METHOD_SIG_RE = re.compile(r'(\w+)\s*\([^)]*\)')

# Regex to match numeric constants in arguments
_ARG_CONST_RE = re.compile(r'\b(\d+)\b')


def _extract_method_name(signature: str) -> Optional[str]:
    """Extract method name from Jimple method signature."""
    match = _METHOD_SIG_RE.search(signature)
    if match:
        return match.group(1)
    return None


def _get_enum_info(class_name: str, method_name: str) -> Optional[MethodEnumInfo]:
    """Get enum info for a method, checking both qualified and simple names."""
    # Try qualified name first
    qualified = f"{class_name}.{method_name}"
    if qualified in QUALIFIED_METHOD_ENUM_MAP:
        return QUALIFIED_METHOD_ENUM_MAP[qualified]

    # Fall back to simple method name (case-insensitive)
    method_lower = method_name.lower()
    if method_lower in METHOD_ENUM_MAP:
        return METHOD_ENUM_MAP[method_lower]

    return None


def annotate_statement(stmt: str) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Annotate a single Jimple statement with semantic meanings.

    Returns:
        Tuple of (annotated_statement, list_of_annotations)
    """
    annotations: List[Dict[str, Any]] = []

    # Find invoke patterns
    match = _JIMPLE_INVOKE_RE.search(stmt)
    if not match:
        return stmt, []

    invoke_type = match.group(1)
    class_name = match.group(3)
    method_sig = match.group(4)
    args = match.group(5)

    method_name = _extract_method_name(method_sig)
    if not method_name:
        return stmt, []

    enum_info = _get_enum_info(class_name, method_name)
    if not enum_info:
        return stmt, []

    # Parse arguments to find the target constant
    arg_parts = [a.strip() for a in args.split(",")] if args.strip() else []
    if not arg_parts:
        return stmt, []

    target_idx = min(enum_info.param_index, len(arg_parts) - 1)
    target_arg = arg_parts[target_idx]

    # Check if this argument is a numeric constant
    const_match = _ARG_CONST_RE.search(target_arg)
    if not const_match:
        return stmt, []

    const_val = const_match.group(1)
    if const_val not in enum_info.enum_map:
        return stmt, []

    semantic_name = enum_info.enum_map[const_val]

    # Create annotation record
    annotations.append({
        "method": method_name,
        "class": class_name,
        "constant": const_val,
        "semantic": semantic_name,
        "enum_type": enum_info.enum_name,
    })

    # Annotate the statement
    # Replace the argument with annotated version
    annotated_arg = f"{target_arg} /* {semantic_name} */"
    new_args = [annotated_arg if i == target_idx else a for i, a in enumerate(arg_parts)]
    new_args_str = ", ".join(new_args)

    # Replace in original statement
    annotated_stmt = stmt.replace(f"({args})", f"({new_args_str})")

    return annotated_stmt, annotations


def annotate_slice_units(units: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Annotate all units in a slice with semantic meanings.

    Args:
        units: List of slice units with 'stmt' field

    Returns:
        Tuple of (annotated_units, all_annotations)
    """
    annotated_units = []
    all_annotations = []

    for unit in units:
        stmt = unit.get("stmt", "")
        if not stmt:
            annotated_units.append(unit)
            continue

        annotated_stmt, annotations = annotate_statement(stmt)

        # Create new unit with annotated statement
        new_unit = {**unit}
        new_unit["stmt"] = annotated_stmt
        if annotations:
            new_unit["_semantic_annotations"] = annotations
            all_annotations.extend(annotations)

        annotated_units.append(new_unit)

    return annotated_units, all_annotations


def annotate_sliced_cfg(sliced_cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Annotate a complete sliced CFG with semantic meanings.

    Args:
        sliced_cfg: Dict with 'units' key containing slice units

    Returns:
        New sliced_cfg dict with annotated statements
    """
    if not sliced_cfg:
        return sliced_cfg

    units = sliced_cfg.get("units", [])
    if not units:
        return sliced_cfg

    annotated_units, all_annotations = annotate_slice_units(units)

    result = {**sliced_cfg}
    result["units"] = annotated_units
    if all_annotations:
        result["_annotations_summary"] = {
            "count": len(all_annotations),
            "annotations": all_annotations,
        }

    return result


def get_semantic_summary(annotations: List[Dict[str, Any]]) -> str:
    """
    Generate a human-readable summary of annotations.

    Useful for including in prompts to help LLM understand the code semantics.
    """
    if not annotations:
        return ""

    lines = ["Semantic Context:"]
    for ann in annotations:
        lines.append(f"  - {ann['method']}({ann['constant']}) uses {ann['enum_type']}.{ann['semantic']}")

    return "\n".join(lines)

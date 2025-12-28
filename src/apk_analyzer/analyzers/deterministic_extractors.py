"""Deterministic extractors for Phase 1A.

This module provides deterministic extraction functions that don't require
LLM interpretation. These form the foundation for Phase 1A output.

Fix 3: Default to PARTIAL coverage with heuristics for COMPLETE.
Fix 7: Proper trigger surface extraction from explicit sources.
Fix 23: extract_permissions() is separate from trigger surface.
Fix 25: Drift guard with tolerance window.
Fix 34: extract_trigger_surface() returns NO permissions.
Improvement B: Pre-parse Jimple into structured ParsedUnit.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from apk_analyzer.models.analysis_context import ComponentHints
from apk_analyzer.models.tier1_phases import (
    ApiCallExtraction,
    ControlGuard,
    ExtractionCoverage,
    ParsedUnit,
    RequiredPermission,
)

if TYPE_CHECKING:
    from apk_analyzer.utils.artifact_store import ArtifactStore


# =============================================================================
# Permission Inference from API Signatures
# =============================================================================

# Mapping of API patterns to required permissions
API_PERMISSION_MAP: Dict[str, List[str]] = {
    "android.media.MediaRecorder": ["android.permission.RECORD_AUDIO"],
    "android.media.AudioRecord": ["android.permission.RECORD_AUDIO"],
    "android.hardware.Camera": ["android.permission.CAMERA"],
    "android.hardware.camera2": ["android.permission.CAMERA"],
    "android.location.LocationManager": [
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
    ],
    "android.telephony.TelephonyManager.getDeviceId": ["android.permission.READ_PHONE_STATE"],
    "android.telephony.TelephonyManager.getSubscriberId": ["android.permission.READ_PHONE_STATE"],
    "android.telephony.TelephonyManager.getLine1Number": ["android.permission.READ_PHONE_STATE"],
    "android.telephony.SmsManager": ["android.permission.SEND_SMS"],
    "android.content.ContentResolver.query": ["android.permission.READ_CONTACTS"],
    "android.net.wifi.WifiManager": ["android.permission.ACCESS_WIFI_STATE"],
    "android.bluetooth.BluetoothAdapter": ["android.permission.BLUETOOTH"],
}


def infer_permissions_from_api(signature: str) -> List[str]:
    """Infer required permissions from an API signature.

    Args:
        signature: The API method signature.

    Returns:
        List of inferred permission strings.
    """
    permissions = []
    for pattern, perms in API_PERMISSION_MAP.items():
        if pattern in signature:
            permissions.extend(perms)
    return list(set(permissions))


# =============================================================================
# Trigger Surface Extraction (Fix 7, 34)
# =============================================================================


def extract_trigger_surface(
    seed_id: str,
    caller_method: str,
    store: "ArtifactStore",
) -> ComponentHints:
    """Extract trigger surface info from explicit sources.

    Fix 7: Explicit data sources with fallback chain.
    Fix 34: Does NOT extract permissions - call extract_permissions() separately.

    Sources (in order):
    1. Entrypoint paths file (preferred)
    2. Manifest component lists (fallback)
    3. Inferred from method signature (last resort)

    Args:
        seed_id: The seed ID for this sensitive callsite.
        caller_method: The method signature containing the callsite.
        store: ArtifactStore for file access (Fix 26).

    Returns:
        ComponentHints with source tracking (NO permissions).
    """
    # SOURCE 1: Entrypoint paths file (preferred)
    try:
        entrypoint_data = store.read_json(f"graphs/entrypoint_paths/{seed_id}.json")
        component_name = entrypoint_data.get("component_name")
        component_type = entrypoint_data.get("component_type")
        if component_name and component_type:
            return ComponentHints(
                component_name=component_name,
                component_type=component_type,
                entrypoint_method=caller_method,
                source="entrypoint_paths",
                source_confidence=0.95,
            )
    except (FileNotFoundError, KeyError):
        pass

    # SOURCE 2: Manifest component lists (fallback)
    try:
        manifest = store.read_json("static/manifest.json")
        class_name = _extract_class_name(caller_method)

        for comp_type, list_key in [
            ("Activity", "activities"),
            ("Service", "services"),
            ("BroadcastReceiver", "receivers"),
            ("ContentProvider", "providers"),
        ]:
            components = manifest.get(list_key, [])
            for comp in components:
                comp_name = comp.get("name", "")
                if comp_name.endswith(class_name) or class_name in comp_name:
                    return ComponentHints(
                        component_name=comp_name,
                        component_type=comp_type,
                        entrypoint_method=caller_method,
                        source="manifest",
                        source_confidence=0.8,
                    )
    except (FileNotFoundError, KeyError):
        pass

    # SOURCE 3: Inferred (last resort)
    class_name = _extract_class_name(caller_method)
    return ComponentHints(
        component_name=class_name.split(".")[-1] if class_name else "Unknown",
        component_type="Unknown",
        entrypoint_method=caller_method,
        source="inferred",
        source_confidence=0.3,
    )


def _extract_class_name(method_signature: str) -> str:
    """Extract class name from a method signature."""
    # Handle signatures like "<com.example.MyClass: void onCreate()>"
    if ":" in method_signature:
        class_part = method_signature.split(":")[0]
        return class_part.strip("<>").strip()
    return method_signature


# =============================================================================
# Permission Extraction (Fix 23)
# =============================================================================


def extract_permissions(
    manifest: Dict[str, Any],
    api_calls: List[ApiCallExtraction],
) -> List[RequiredPermission]:
    """Extract permissions from manifest and API inference.

    Fix 23: This is the SINGLE canonical source for permissions.
    Called separately from extract_trigger_surface().

    Args:
        manifest: Parsed manifest data.
        api_calls: List of extracted API calls.

    Returns:
        Deduplicated list of RequiredPermission.
    """
    permissions: List[RequiredPermission] = []

    # Global manifest permissions
    for perm in manifest.get("permissions", []):
        permissions.append(
            RequiredPermission(
                permission=perm,
                scope="global_manifest",
                evidence_unit_ids=[],
                confidence=0.5,
            )
        )

    # API-inferred permissions (higher confidence for this path)
    for api_call in api_calls:
        inferred = infer_permissions_from_api(api_call.signature)
        for perm in inferred:
            permissions.append(
                RequiredPermission(
                    permission=perm,
                    scope="inferred_from_api",
                    evidence_unit_ids=[api_call.unit_id],
                    confidence=0.9,
                )
            )

    return dedupe_permissions(permissions)


def dedupe_permissions(permissions: List[RequiredPermission]) -> List[RequiredPermission]:
    """Deduplicate permissions, keeping highest confidence for each."""
    perm_map: Dict[str, RequiredPermission] = {}
    for p in permissions:
        if p.permission not in perm_map or p.confidence > perm_map[p.permission].confidence:
            # Merge evidence unit IDs
            if p.permission in perm_map:
                existing_ids = perm_map[p.permission].evidence_unit_ids
                p.evidence_unit_ids = list(set(existing_ids + p.evidence_unit_ids))
            perm_map[p.permission] = p
    return list(perm_map.values())


# =============================================================================
# Extraction Coverage (Fix 3, 25)
# =============================================================================


def compute_extraction_coverage(
    api_calls: List[ApiCallExtraction],
    branch_conditions: List[ControlGuard],
    entrypoint_method: Optional[str],
    ambiguous_units: List[str],
) -> ExtractionCoverage:
    """Compute extraction coverage level.

    Fix 3: Default to PARTIAL. Only mark COMPLETE if all heuristics pass.

    Args:
        api_calls: Extracted API calls.
        branch_conditions: Extracted branch conditions.
        entrypoint_method: The entrypoint method if found.
        ambiguous_units: Units that need interpretation.

    Returns:
        ExtractionCoverage enum value.
    """
    # All three conditions must be true for COMPLETE
    has_callsites = len(api_calls) > 0
    has_guards = len(branch_conditions) > 0
    has_entrypoint = entrypoint_method is not None

    if has_callsites and has_guards and has_entrypoint:
        # Additional check: no ambiguous units
        if len(ambiguous_units) == 0:
            return ExtractionCoverage.COMPLETE
        return ExtractionCoverage.PARTIAL

    # Missing critical structure
    if not has_callsites and not has_guards:
        return ExtractionCoverage.MINIMAL

    # Default: PARTIAL (triggers 1B even without explicit ambiguity)
    return ExtractionCoverage.PARTIAL


def validate_with_sanity_check(
    extracted_callsite_count: int,
    cfg_callsite_count: int,
    drift_tolerance: float = 0.3,
) -> tuple[bool, str]:
    """Validate extraction against CFG counts with tolerance.

    Fix 25: Drift guard with 30% tolerance window.

    Args:
        extracted_callsite_count: Number of callsites from extraction.
        cfg_callsite_count: Number of callsites from CFG.
        drift_tolerance: Allowed percentage difference (default 30%).

    Returns:
        Tuple of (passed, message).
    """
    if cfg_callsite_count == 0:
        if extracted_callsite_count == 0:
            return True, "No callsites in CFG or extraction"
        return False, f"Extractor drift: CFG has 0 callsites, extracted {extracted_callsite_count}"

    drift_ratio = abs(cfg_callsite_count - extracted_callsite_count) / cfg_callsite_count

    if drift_ratio > drift_tolerance:
        return (
            False,
            f"Extractor drift detected: CFG has ~{cfg_callsite_count} callsites, "
            f"extracted {extracted_callsite_count} ({drift_ratio:.0%} difference)",
        )

    return True, "Extraction within tolerance"


# =============================================================================
# Unit Parsing (Improvement B)
# =============================================================================


def parse_unit(unit: Dict[str, Any]) -> ParsedUnit:
    """Parse a CFG unit into structured ParsedUnit.

    Improvement B: Pre-parse Jimple so 1B doesn't parse text.

    Args:
        unit: Raw unit dict from CFG.

    Returns:
        ParsedUnit with structured fields.
    """
    unit_id = unit.get("unit_id", "")
    raw_stmt = unit.get("stmt", "")

    # Detect operation type
    op = _detect_op(raw_stmt)

    result = ParsedUnit(
        unit_id=unit_id,
        raw_stmt=raw_stmt,
        op=op,
    )

    if op == "invoke":
        result.call_sig, result.args = _parse_invoke(raw_stmt)
    elif op == "assign":
        result.lhs, rhs = _parse_assign(raw_stmt)
        # Check if RHS is an invoke
        if "invoke" in rhs.lower():
            result.call_sig, result.args = _parse_invoke(rhs)
    elif op == "if":
        result.condition = _parse_condition(raw_stmt)

    return result


def _detect_op(stmt: str) -> str:
    """Detect the operation type from a Jimple statement."""
    stmt_lower = stmt.lower()
    if "invoke" in stmt_lower:
        return "invoke"
    if " = " in stmt:
        return "assign"
    if stmt_lower.startswith("if "):
        return "if"
    if stmt_lower.startswith("goto "):
        return "goto"
    if stmt_lower.startswith("return"):
        return "return"
    return "other"


def _parse_invoke(stmt: str) -> tuple[Optional[str], List[str]]:
    """Parse an invoke statement to extract signature and arguments."""
    # Pattern: invoke... <ClassName: ReturnType methodName(ArgTypes)>(args)
    sig_match = re.search(r"<([^>]+)>", stmt)
    sig = sig_match.group(1) if sig_match else None

    # Extract arguments from the last parentheses
    args_match = re.search(r"\(([^)]*)\)\s*$", stmt)
    if args_match:
        args_str = args_match.group(1)
        args = [a.strip() for a in args_str.split(",") if a.strip()]
    else:
        args = []

    return sig, args


def _parse_assign(stmt: str) -> tuple[str, str]:
    """Parse an assignment statement."""
    parts = stmt.split(" = ", 1)
    if len(parts) == 2:
        return parts[0].strip(), parts[1].strip()
    return stmt, ""


def _parse_condition(stmt: str) -> Optional[str]:
    """Parse a condition from an if statement."""
    # Pattern: if <condition> goto label
    match = re.search(r"if\s+(.+?)\s+goto", stmt, re.IGNORECASE)
    return match.group(1).strip() if match else None

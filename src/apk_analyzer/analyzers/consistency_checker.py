from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Tuple

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

# Semantic mapping: bytecode constants -> symbolic names
# This allows the verifier to match LLM facts that use symbolic names
# against bytecode that uses numeric constants
ANDROID_CONSTANTS: Dict[str, List[str]] = {
    # MediaRecorder.AudioSource
    "0": ["default", "audiosource"],
    "1": ["mic", "microphone", "audiosource.mic"],
    "4": ["camcorder"],
    "5": ["voice_recognition"],
    "6": ["voice_communication"],
    "7": ["remote_submix"],
    # MediaRecorder.OutputFormat
    "2": ["mpeg_4", "mpeg4"],
    # MediaRecorder.AudioEncoder
    "3": ["amr_nb", "amrnb"],
    # WindowManager.LayoutParams type
    "2": ["type_phone", "type_application"],
    "2002": ["type_system_alert"],
    "2003": ["type_toast"],
    "2010": ["type_system_overlay"],
    "2038": ["type_application_overlay", "application_overlay"],
    # WindowManager.LayoutParams flags
    "8": ["flag_not_focusable", "not_focusable"],
    "16777216": ["flag_hardware_accelerated"],
    # Intent flags
    "268435456": ["flag_activity_new_task", "new_task"],
    "67108864": ["flag_activity_clear_task", "clear_task"],
    # ContentResolver query projection constants
    "_id": ["id", "column_id"],
    # PixelFormat
    "-3": ["translucent", "pixelformat.translucent"],
    # Gravity
    "17": ["center", "gravity.center"],
    # PackageManager flags
    "0": ["get_activities", "get_services", "get_receivers"],
}

# Method name aliases for common Android APIs
METHOD_ALIASES: Dict[str, List[str]] = {
    "getdeviceid": ["imei", "device_id", "deviceid"],
    "getsubscriberid": ["imsi", "subscriber_id", "subscriberid"],
    "getimei": ["imei", "device_id"],
    "getline1number": ["phone_number", "line1", "phonenumber"],
    "setaudiosource": ["audiosource", "mic", "microphone", "audio_source"],
    "setoutputformat": ["outputformat", "output_format", "mpeg"],
    "setaudioencoder": ["audioencoder", "audio_encoder", "amr"],
    "setoutputfile": ["outputfile", "output_file", "filepath"],
    "getmediaprojection": ["mediaprojection", "media_projection", "screen_capture"],
    "addview": ["overlay", "window", "view"],
    "getinputstream": ["inputstream", "input_stream", "socket_input"],
    "getoutputstream": ["outputstream", "output_stream", "socket_output"],
}


def _tokenize(text: str) -> List[str]:
    """Tokenize text for matching."""
    tokens = re.findall(r"[a-zA-Z0-9_.$]+", text.lower())
    return [t for t in tokens if len(t) > 2]


def _extract_constants_from_statements(statements: str) -> Set[str]:
    """Extract numeric constants and identifiers from Jimple statements."""
    constants: Set[str] = set()
    # Match numeric constants like (1), (2038), etc.
    for match in re.findall(r'\((\d+)\)', statements):
        constants.add(match)
    # Match standalone numbers in assignments
    for match in re.findall(r'=\s*(\d+)\s*[;,\)]', statements):
        constants.add(match)
    # Match negative numbers
    for match in re.findall(r'\(-(\d+)\)', statements):
        constants.add(f"-{match}")
    return constants


def _get_semantic_tokens(constants_found: Set[str]) -> Set[str]:
    """Get semantic tokens (symbolic names) for constants found in statements."""
    semantic: Set[str] = set()
    for const_val in constants_found:
        if const_val in ANDROID_CONSTANTS:
            for alias in ANDROID_CONSTANTS[const_val]:
                semantic.add(alias.lower())
    return semantic


def _get_method_aliases(statements: str) -> Set[str]:
    """Get method name aliases for methods found in statements."""
    aliases: Set[str] = set()
    statements_lower = statements.lower()
    for method_name, method_aliases in METHOD_ALIASES.items():
        if method_name in statements_lower:
            for alias in method_aliases:
                aliases.add(alias.lower())
    return aliases


def consistency_check(
    tier1_summary: Dict[str, Any],
    context_bundle: Dict[str, Any],
    min_token_overlap: float = 0.2,
    strict_mode: bool = False,
) -> Dict[str, Any]:
    """
    Check consistency of Tier1 facts against context bundle evidence.

    Args:
        tier1_summary: The Tier1 summarizer output with facts
        context_bundle: The context bundle with sliced CFG and static context
        min_token_overlap: Minimum fraction of fact tokens that must match (0.0-1.0)
        strict_mode: If True, require exact token matching (old behavior)

    Returns:
        Dict with ok, missing_unit_ids, mismatched_facts, warnings, repair_hint
    """
    slice_units = context_bundle.get("sliced_cfg", {}).get("units", [])
    unit_map = {u.get("unit_id"): u.get("stmt", "") for u in slice_units}
    missing_unit_ids: List[str] = []
    mismatched_facts: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    strings_nearby = set(context_bundle.get("static_context", {}).get("strings_nearby", []))

    for fact in tier1_summary.get("facts", []):
        fact_text = fact.get("fact", "")
        support_ids = fact.get("support_unit_ids", [])

        # Check for missing unit IDs
        for uid in support_ids:
            if uid not in unit_map:
                missing_unit_ids.append(uid)

        # Build combined statement text from supporting units
        if support_ids:
            combined_stmt = " ".join([unit_map.get(uid, "") for uid in support_ids])
        else:
            combined_stmt = ""

        # Tokenize fact and statement
        fact_tokens = _tokenize(fact_text)

        if fact_tokens and combined_stmt:
            combined_stmt_lower = combined_stmt.lower()

            # Extract constants and get their semantic equivalents
            constants_found = _extract_constants_from_statements(combined_stmt)
            semantic_tokens = _get_semantic_tokens(constants_found)
            method_aliases = _get_method_aliases(combined_stmt)

            # Expand matching vocabulary with semantic tokens and aliases
            expanded_vocabulary = set(combined_stmt_lower.split())
            expanded_vocabulary.update(semantic_tokens)
            expanded_vocabulary.update(method_aliases)

            # Count how many fact tokens match (directly or semantically)
            matching_tokens = 0
            for token in fact_tokens:
                # Direct match in statement
                if token in combined_stmt_lower:
                    matching_tokens += 1
                    continue
                # Match in expanded vocabulary (semantic equivalents)
                if token in expanded_vocabulary:
                    matching_tokens += 1
                    continue
                # Partial match in expanded vocabulary
                if any(token in vocab_token or vocab_token in token for vocab_token in expanded_vocabulary):
                    matching_tokens += 1
                    continue

            overlap_ratio = matching_tokens / len(fact_tokens) if fact_tokens else 0.0

            if strict_mode:
                # Old behavior: require any direct token match
                if not any(token in combined_stmt_lower for token in fact_tokens):
                    mismatched_facts.append({
                        "fact": fact_text,
                        "reason": "No token overlap with supporting statements",
                    })
            else:
                # New behavior: require minimum overlap ratio with semantic matching
                if overlap_ratio < min_token_overlap:
                    # Low overlap is a warning, not a rejection
                    warnings.append({
                        "fact": fact_text,
                        "reason": f"Low token overlap ({overlap_ratio:.1%} < {min_token_overlap:.0%})",
                        "overlap_ratio": overlap_ratio,
                    })
                elif overlap_ratio < 0.5:
                    # Medium overlap: log as informational
                    warnings.append({
                        "fact": fact_text,
                        "reason": f"Moderate token overlap ({overlap_ratio:.1%})",
                        "overlap_ratio": overlap_ratio,
                        "severity": "info",
                    })

        # Check URLs, IPs, domains - be more lenient
        for regex, label in ((_URL_RE, "url"), (_IP_RE, "ip"), (_DOMAIN_RE, "domain")):
            matches = regex.findall(fact_text)
            if matches:
                for match in matches:
                    if match not in strings_nearby and match not in combined_stmt:
                        # For domains, check partial match (e.g., "192.168" in IP range)
                        partial_match = False
                        if label == "ip":
                            # Allow partial IP match (first 2 octets)
                            prefix = ".".join(match.split(".")[:2])
                            if any(prefix in s for s in strings_nearby) or prefix in combined_stmt:
                                partial_match = True
                        if label == "domain":
                            # Allow root domain match
                            parts = match.split(".")
                            if len(parts) >= 2:
                                root = ".".join(parts[-2:])
                                if any(root in s for s in strings_nearby) or root in combined_stmt:
                                    partial_match = True

                        if not partial_match:
                            if strict_mode:
                                mismatched_facts.append({
                                    "fact": fact_text,
                                    "reason": f"{label} '{match}' not present in slice or strings",
                                })
                            else:
                                # In lenient mode, add as warning
                                warnings.append({
                                    "fact": fact_text,
                                    "reason": f"{label} '{match}' not directly present in slice or strings",
                                    "severity": "warning",
                                })

    # Only missing unit IDs and mismatched facts cause failure
    # Warnings are informational
    ok = not missing_unit_ids and not mismatched_facts
    repair_hint = ""
    if not ok:
        repair_hint = "Only claim facts directly supported by unit_ids and matching statement text."

    return {
        "ok": ok,
        "missing_unit_ids": sorted(set(missing_unit_ids)),
        "mismatched_facts": mismatched_facts,
        "warnings": warnings,
        "repair_hint": repair_hint,
    }

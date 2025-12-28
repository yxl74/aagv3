"""SDK-versioned Android constant mappings.

This module provides semantic mappings for Android SDK constants with
version tracking and resolution confidence.

Fix 6: SDK-versioned SemanticMapping with resolution_source.
Improvement A: resolution_confidence per mapping.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass
class SemanticMapping:
    """SDK-versioned semantic mapping for Android constants.

    Attributes:
        constant_value: The numeric constant value.
        semantic_name: Human-readable name (e.g., "MIC", "CAMCORDER").
        sdk_version_added: Android SDK version when this was added.
        sdk_version_deprecated: SDK version when deprecated (if applicable).
        resolution_source: How this mapping was determined.
    """

    constant_value: int
    semantic_name: str
    sdk_version_added: int
    sdk_version_deprecated: Optional[int] = None
    resolution_source: str = "sdk_official"  # "sdk_official" | "aosp_source" | "empirical"


# =============================================================================
# Audio Source Constants (MediaRecorder.AudioSource)
# =============================================================================

AUDIO_SOURCE_MAPPINGS: Dict[int, SemanticMapping] = {
    0: SemanticMapping(0, "DEFAULT", sdk_version_added=1, resolution_source="sdk_official"),
    1: SemanticMapping(1, "MIC", sdk_version_added=1, resolution_source="sdk_official"),
    2: SemanticMapping(2, "VOICE_UPLINK", sdk_version_added=4, resolution_source="sdk_official"),
    3: SemanticMapping(3, "VOICE_DOWNLINK", sdk_version_added=4, resolution_source="sdk_official"),
    4: SemanticMapping(4, "VOICE_CALL", sdk_version_added=4, resolution_source="sdk_official"),
    5: SemanticMapping(5, "CAMCORDER", sdk_version_added=7, resolution_source="sdk_official"),
    6: SemanticMapping(6, "VOICE_RECOGNITION", sdk_version_added=7, resolution_source="sdk_official"),
    7: SemanticMapping(7, "VOICE_COMMUNICATION", sdk_version_added=11, resolution_source="sdk_official"),
    9: SemanticMapping(9, "UNPROCESSED", sdk_version_added=24, resolution_source="sdk_official"),
    10: SemanticMapping(10, "VOICE_PERFORMANCE", sdk_version_added=29, resolution_source="sdk_official"),
}

# =============================================================================
# Camera Facing Constants (CameraCharacteristics.LENS_FACING)
# =============================================================================

CAMERA_FACING_MAPPINGS: Dict[int, SemanticMapping] = {
    0: SemanticMapping(0, "LENS_FACING_FRONT", sdk_version_added=21, resolution_source="sdk_official"),
    1: SemanticMapping(1, "LENS_FACING_BACK", sdk_version_added=21, resolution_source="sdk_official"),
    2: SemanticMapping(2, "LENS_FACING_EXTERNAL", sdk_version_added=23, resolution_source="sdk_official"),
}

# =============================================================================
# Location Request Priority (LocationRequest)
# =============================================================================

LOCATION_PRIORITY_MAPPINGS: Dict[int, SemanticMapping] = {
    100: SemanticMapping(100, "PRIORITY_HIGH_ACCURACY", sdk_version_added=9, resolution_source="sdk_official"),
    102: SemanticMapping(102, "PRIORITY_BALANCED_POWER_ACCURACY", sdk_version_added=9, resolution_source="sdk_official"),
    104: SemanticMapping(104, "PRIORITY_LOW_POWER", sdk_version_added=9, resolution_source="sdk_official"),
    105: SemanticMapping(105, "PRIORITY_NO_POWER", sdk_version_added=9, resolution_source="sdk_official"),
}

# =============================================================================
# Network Type Constants (ConnectivityManager)
# =============================================================================

NETWORK_TYPE_MAPPINGS: Dict[int, SemanticMapping] = {
    0: SemanticMapping(0, "TYPE_MOBILE", sdk_version_added=1, sdk_version_deprecated=28, resolution_source="sdk_official"),
    1: SemanticMapping(1, "TYPE_WIFI", sdk_version_added=1, sdk_version_deprecated=28, resolution_source="sdk_official"),
    6: SemanticMapping(6, "TYPE_WIMAX", sdk_version_added=8, sdk_version_deprecated=28, resolution_source="sdk_official"),
    7: SemanticMapping(7, "TYPE_BLUETOOTH", sdk_version_added=13, sdk_version_deprecated=28, resolution_source="sdk_official"),
    9: SemanticMapping(9, "TYPE_ETHERNET", sdk_version_added=13, sdk_version_deprecated=28, resolution_source="sdk_official"),
}

# =============================================================================
# Telephony Manager Constants
# =============================================================================

PHONE_TYPE_MAPPINGS: Dict[int, SemanticMapping] = {
    0: SemanticMapping(0, "PHONE_TYPE_NONE", sdk_version_added=1, resolution_source="sdk_official"),
    1: SemanticMapping(1, "PHONE_TYPE_GSM", sdk_version_added=1, resolution_source="sdk_official"),
    2: SemanticMapping(2, "PHONE_TYPE_CDMA", sdk_version_added=4, resolution_source="sdk_official"),
    3: SemanticMapping(3, "PHONE_TYPE_SIP", sdk_version_added=11, resolution_source="sdk_official"),
}

# =============================================================================
# Master Constant Map
# =============================================================================

ANDROID_CONSTANTS_MAP: Dict[str, Dict[int, SemanticMapping]] = {
    "android.media.MediaRecorder$AudioSource": AUDIO_SOURCE_MAPPINGS,
    "android.hardware.camera2.CameraCharacteristics": CAMERA_FACING_MAPPINGS,
    "android.location.LocationRequest": LOCATION_PRIORITY_MAPPINGS,
    "android.net.ConnectivityManager": NETWORK_TYPE_MAPPINGS,
    "android.telephony.TelephonyManager": PHONE_TYPE_MAPPINGS,
}


def annotate_with_confidence(
    constant: int,
    enum_class: str,
    target_sdk: int = 33,
) -> Optional[Tuple[str, float]]:
    """Return semantic annotation with confidence based on SDK version match.

    Args:
        constant: The integer constant value.
        enum_class: The Android class containing this constant.
        target_sdk: The target SDK version of the APK being analyzed.

    Returns:
        Tuple of (semantic_name, confidence) or None if not found.
    """
    class_mappings = ANDROID_CONSTANTS_MAP.get(enum_class, {})
    mapping = class_mappings.get(constant)

    if not mapping:
        return None

    # Higher confidence if SDK version matches
    if mapping.sdk_version_added <= target_sdk:
        if mapping.sdk_version_deprecated and mapping.sdk_version_deprecated <= target_sdk:
            return (mapping.semantic_name, 0.5)  # Deprecated, lower confidence
        return (mapping.semantic_name, 0.95)  # High confidence

    return (mapping.semantic_name, 0.7)  # SDK mismatch, medium confidence


def get_resolution_source(constant: int, enum_class: str) -> Optional[str]:
    """Get the resolution source for a constant mapping."""
    class_mappings = ANDROID_CONSTANTS_MAP.get(enum_class, {})
    mapping = class_mappings.get(constant)
    return mapping.resolution_source if mapping else None

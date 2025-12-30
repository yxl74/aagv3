"""
Co-occurrence pattern detection for Android malware analysis.

This module implements research-backed co-occurrence patterns (2020-2025) to
reduce false positives by detecting threat pattern combinations that indicate
malicious behavior.

Key principle: FAIL-OPEN (additive only)
- Base score = max(weights) - always preserved
- Patterns can only ADD boost, never subtract
- Priority can only be PROMOTED, never demoted

References:
- ThreatFabric banking trojan research
- Cleafy TrickMo analysis
- NCC Group SharkBot writeup
- Microsoft toll-fraud research
- Cisco Talos Firestarter (FCM C2)
- arXiv 2025 stalkerware corpus study
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from apk_analyzer.knowledge.api_catalog import ApiCatalog

PRIORITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass(frozen=True)
class CooccurrencePattern:
    """
    Pattern definition for co-occurrence detection.

    Matching logic (all specified conditions must be met):
    - all_of: Block must contain ALL of these categories
    - any_of: Block must contain AT LEAST ONE of these categories
    - any_of_2: Second any-of group (for "A + (B or C) + (D or E)" patterns)
    - min_count + from_set: Block must contain at least min_count from the set

    Scoring (per-level to avoid double-counting at group+block):
    - boost: Legacy field for backward compatibility (used as boost_group if set)
    - boost_group: Added at method-group level (tight coupling, stronger signal)
    - boost_block: Added at class-block level (distributed co-occurrence, weaker signal)
    - priority_override: Promotes priority upward (never demotes)
    """

    pattern_id: str
    description: str
    boost: float  # Legacy: used as boost_group, boost_block derived as 40%
    all_of: FrozenSet[str] = field(default_factory=frozenset)
    any_of: FrozenSet[str] = field(default_factory=frozenset)
    any_of_2: FrozenSet[str] = field(default_factory=frozenset)
    min_count: int = 0
    from_set: FrozenSet[str] = field(default_factory=frozenset)
    priority_override: Optional[str] = None

    @property
    def boost_group(self) -> float:
        """Boost when pattern matched at group level (same caller method)."""
        return self.boost

    @property
    def boost_block(self) -> float:
        """Boost when pattern matched at block level (same class).

        40% of group boost since distributed co-occurrence is weaker signal.
        """
        return round(self.boost * 0.4, 3)


# =============================================================================
# Pattern Definitions (Research-Backed, 2020-2025)
# =============================================================================

COOCCURRENCE_PATTERNS: List[CooccurrencePattern] = [
    # =========================================================================
    # Group 1: Dropper / Staged Install Chain
    # Sources: ThreatFabric, Cleafy TrickMo, NCC Group SharkBot
    # =========================================================================
    CooccurrencePattern(
        pattern_id="P_DROP_INSTALL_VIA_DM",
        description="Dropper: package install + DownloadManager payload fetch",
        all_of=frozenset({"SYSTEM_MANIPULATION_PACKAGE", "DELIVERY_PAYLOAD_DOWNLOAD_DOWNLOADMANAGER"}),
        boost=0.20,
        priority_override="HIGH",
    ),
    CooccurrencePattern(
        pattern_id="P_DROP_INSTALL_VIA_NET",
        description="Dropper: package install + network C2 for payload",
        all_of=frozenset({"SYSTEM_MANIPULATION_PACKAGE", "C2_NETWORKING"}),
        boost=0.15,
        priority_override="HIGH",
    ),
    CooccurrencePattern(
        pattern_id="P_DROP_INSTALL_SETTINGS_LURE",
        description="Dropper: package install + settings lure (social engineering)",
        all_of=frozenset({"SYSTEM_MANIPULATION_PACKAGE", "SOCIAL_ENGINEERING_PERMISSION_LURE_SETTINGS"}),
        boost=0.20,
        priority_override="HIGH",
    ),
    CooccurrencePattern(
        pattern_id="P_DROP_TO_ACCESSIBILITY",
        description="Dropper chain: package install -> Accessibility request",
        all_of=frozenset({"SYSTEM_MANIPULATION_PACKAGE", "ABUSE_ACCESSIBILITY"}),
        boost=0.25,
        priority_override="CRITICAL",
    ),

    # =========================================================================
    # Group 2: Dynamic Loader + Evasion (Packer/Unpacker Pattern)
    # =========================================================================
    CooccurrencePattern(
        pattern_id="P_DYNLOAD_EVASION",
        description="Dynamic code loading + obfuscation/reflection/anti-debug",
        all_of=frozenset({"DYNAMIC_CODE_LOADING"}),
        any_of=frozenset({"EVASION_CRYPTO_OBFUSCATION", "EVASION_REFLECTION", "ANTI_ANALYSIS_ANTI_DEBUG"}),
        boost=0.15,
    ),
    CooccurrencePattern(
        pattern_id="P_NATIVELOAD_EVASION",
        description="Native code loading + obfuscation/anti-debug",
        all_of=frozenset({"NATIVE_CODE_LOADING"}),
        any_of=frozenset({"EVASION_CRYPTO_OBFUSCATION", "ANTI_ANALYSIS_ANTI_DEBUG"}),
        boost=0.12,
    ),

    # =========================================================================
    # Group 3: ODF / ATS / Full Device Takeover
    # Sources: ThreatFabric, TeaBot, TrickMo, Hook v3 (Zimperium)
    # =========================================================================
    CooccurrencePattern(
        pattern_id="P_ODF_REMOTE_STREAM",
        description="ODF: Accessibility + screen capture + C2 (remote streaming)",
        all_of=frozenset({"ABUSE_ACCESSIBILITY", "SURVEILLANCE_SCREEN_CAPTURE"}),
        any_of=frozenset({"C2_NETWORKING", "C2_PUSH_FCM"}),
        boost=0.25,
        priority_override="CRITICAL",
    ),
    CooccurrencePattern(
        pattern_id="P_ODF_INPUT_AUTOMATION",
        description="ODF: Accessibility + input injection + C2 (ATS)",
        all_of=frozenset({"ABUSE_ACCESSIBILITY", "INPUT_INJECTION"}),
        any_of=frozenset({"C2_NETWORKING", "C2_PUSH_FCM"}),
        boost=0.20,
        priority_override="CRITICAL",
    ),
    CooccurrencePattern(
        pattern_id="P_ODF_OVERLAY_OR_WEBINJECT",
        description="Banking trojan: Accessibility + overlay/WebView phishing",
        all_of=frozenset({"ABUSE_ACCESSIBILITY"}),
        any_of=frozenset({"INPUT_PROMPT_OVERLAY", "WEBVIEW_PHISHING"}),
        boost=0.20,
        priority_override="CRITICAL",
    ),

    # =========================================================================
    # Group 4: OTP Theft (SMS + Notifications)
    # Sources: Microsoft toll-fraud research, EventBot, TrickMo
    # =========================================================================
    CooccurrencePattern(
        pattern_id="P_OTP_SMS_INTERCEPT_EXFIL",
        description="OTP theft: SMS interception + exfiltration",
        all_of=frozenset({"INTERCEPT_SMS_MESSAGES"}),
        any_of=frozenset({"C2_NETWORKING", "EXFIL_ALTERNATIVE_PROTOCOL"}),
        boost=0.15,
    ),
    CooccurrencePattern(
        pattern_id="P_OTP_NOTIFICATION_CAPTURE_AND_HIDE",
        description="OTP theft: notification capture + suppression (NLS abuse)",
        all_of=frozenset({"COLLECTION_NOTIFICATIONS", "DEFENSE_EVASION_NOTIFICATION_SUPPRESSION"}),
        boost=0.20,
    ),
    CooccurrencePattern(
        pattern_id="P_OTP_SMS_AND_NOTIFICATION_HIDE",
        description="OTP theft: SMS interception + notification suppression",
        all_of=frozenset({"INTERCEPT_SMS_MESSAGES", "DEFENSE_EVASION_NOTIFICATION_SUPPRESSION"}),
        boost=0.25,
        priority_override="CRITICAL",
    ),

    # =========================================================================
    # Group 5: Smishing Propagation (FluBot-style)
    # =========================================================================
    CooccurrencePattern(
        pattern_id="P_SMISHING_SPREAD",
        description="Smishing: send SMS + contacts/SMS collection + C2",
        all_of=frozenset({"SMS_CONTROL_SEND", "C2_NETWORKING"}),
        any_of=frozenset({"COLLECTION_CONTACTS", "COLLECTION_SMS_MESSAGES"}),
        boost=0.20,
        priority_override="HIGH",
    ),

    # =========================================================================
    # Group 6: Stalkerware / Spyware Bundle
    # Source: arXiv 2025 stalkerware corpus study
    # =========================================================================
    CooccurrencePattern(
        pattern_id="P_STALKERWARE_PERSIST_LOCATION",
        description="Stalkerware: location tracking + battery optimization + persistence",
        all_of=frozenset({"SURVEILLANCE_LOCATION", "PERSISTENCE_BATTERY_OPTIMIZATION_ALLOWLIST"}),
        any_of=frozenset({
            "PERSISTENCE_BROADCAST_RECEIVERS",
            "PERSISTENCE_SCHEDULED_TASKS",
            "PERSISTENCE_FOREGROUND_SERVICE",
        }),
        boost=0.20,
    ),
    CooccurrencePattern(
        pattern_id="P_STALKERWARE_COLLECTION_BUNDLE",
        description="Stalkerware: 3+ surveillance/collection capabilities bundled",
        min_count=3,
        from_set=frozenset({
            "SURVEILLANCE_LOCATION",
            "SURVEILLANCE_AUDIO",
            "SURVEILLANCE_CAMERA",
            "COLLECTION_SMS_MESSAGES",
            "COLLECTION_CONTACTS",
            "COLLECTION_CALL_LOG",
            "COLLECTION_FILES_MEDIA",
        }),
        boost=0.25,
        priority_override="HIGH",
    ),
    CooccurrencePattern(
        pattern_id="P_STALKERWARE_SMS_COMMAND_CONTROL",
        description="Stalkerware: SMS-based C2 + persistence",
        all_of=frozenset({"C2_NETWORKING"}),
        any_of=frozenset({"COLLECTION_SMS_MESSAGES", "INTERCEPT_SMS_MESSAGES"}),
        any_of_2=frozenset({"PERSISTENCE_BROADCAST_RECEIVERS", "PERSISTENCE_SCHEDULED_TASKS"}),
        boost=0.15,
    ),

    # =========================================================================
    # Group 7: Push Wake-up C2 (FCM)
    # Source: Cisco Talos Firestarter
    # =========================================================================
    CooccurrencePattern(
        pattern_id="P_PUSH_WAKEUP_THEN_FETCH",
        description="C2: FCM push wake-up followed by fetch/loader",
        all_of=frozenset({"C2_PUSH_FCM"}),
        any_of=frozenset({"C2_NETWORKING", "DYNAMIC_CODE_LOADING"}),
        boost=0.10,
    ),

    # =========================================================================
    # Group 8: Toll Fraud Chain
    # Source: Microsoft toll-fraud research
    # =========================================================================
    CooccurrencePattern(
        pattern_id="P_TOLL_FRAUD_CHAIN",
        description="Toll fraud: dynamic loading + notification suppression + operator/cellular forcing",
        all_of=frozenset({"DYNAMIC_CODE_LOADING", "DEFENSE_EVASION_NOTIFICATION_SUPPRESSION"}),
        any_of=frozenset({"TOLL_FRAUD_OPERATOR_GATING", "TOLL_FRAUD_FORCE_CELLULAR"}),
        boost=0.20,
        priority_override="CRITICAL",
    ),
]


def pattern_matches(pattern: CooccurrencePattern, categories: Set[str]) -> bool:
    """
    Check if a code block's categories match a co-occurrence pattern.

    All specified conditions must be satisfied for a match.

    Args:
        pattern: The pattern to check against.
        categories: Set of category IDs present in the block/group.

    Returns:
        True if all pattern conditions are met, False otherwise.
    """
    # all_of: categories must contain all specified
    if pattern.all_of and not pattern.all_of.issubset(categories):
        return False

    # any_of: categories must contain at least one
    if pattern.any_of and not (pattern.any_of & categories):
        return False

    # any_of_2: second any-of group must also have at least one
    if pattern.any_of_2 and not (pattern.any_of_2 & categories):
        return False

    # min_count from set: must have at least N categories from the specified set
    if pattern.min_count > 0 and pattern.from_set:
        count = len(pattern.from_set & categories)
        if count < pattern.min_count:
            return False

    return True


def compute_threat_score(
    categories: Set[str],
    catalog: ApiCatalog,
    patterns: Optional[List[CooccurrencePattern]] = None,
    level: str = "group",
) -> Tuple[float, float, str, Dict[str, Any]]:
    """
    Compute threat score for a code block/group with co-occurrence boosting.

    Key principle: FAIL-OPEN (additive only)
    - Base score = max(weights) - always preserved
    - Patterns can only ADD boost, never subtract
    - Priority can only be PROMOTED, never demoted

    Args:
        categories: Set of category IDs present in the block/group.
        catalog: The API catalog for looking up category weights.
        patterns: List of patterns to check (defaults to COOCCURRENCE_PATTERNS).
        level: Scoring level - "group" (method-level, stronger signal) or
               "block" (class-level, weaker signal). Affects boost magnitude
               to avoid double-counting when same pattern matches at both levels.

    Returns:
        Tuple of (threat_score, threat_score_raw, effective_priority, metadata)
        - threat_score: Capped at 1.0 (for display/thresholds)
        - threat_score_raw: Uncapped (for sorting - provides separation among CRITICALs)
        - effective_priority: May be promoted by patterns
        - metadata: Dict with scoring details
    """
    if patterns is None:
        patterns = COOCCURRENCE_PATTERNS

    if not categories:
        return 0.0, 0.0, "LOW", {"reason": "no_categories"}

    # Collect weights and priorities from catalog
    # Unknown categories are treated as weight 0 (don't error)
    weights: Dict[str, float] = {}
    priorities: List[str] = []
    for cat in categories:
        if cat in catalog.categories:
            weights[cat] = catalog.categories[cat].weight
            priorities.append(catalog.categories[cat].priority)

    # Base score: max of individual weights (preserves existing behavior)
    base_score = max(weights.values()) if weights else 0.0

    # Base priority: highest severity among categories
    if priorities:
        base_priority = min(priorities, key=lambda p: PRIORITY_RANK.get(p, 99))
    else:
        base_priority = "LOW"

    # Match patterns and accumulate boosts (using per-level boost)
    matched_patterns: List[str] = []
    total_boost = 0.0
    best_priority = base_priority

    for pattern in patterns:
        if pattern_matches(pattern, categories):
            matched_patterns.append(pattern.pattern_id)
            # Use per-level boost to avoid double-counting
            if level == "group":
                total_boost += pattern.boost_group
            else:
                total_boost += pattern.boost_block

            # Priority promotion (never demotion)
            if pattern.priority_override:
                override_rank = PRIORITY_RANK.get(pattern.priority_override, 99)
                current_rank = PRIORITY_RANK.get(best_priority, 99)
                if override_rank < current_rank:
                    best_priority = pattern.priority_override

    # Raw score (uncapped, for sorting)
    threat_score_raw = base_score + total_boost

    # Capped score (for display/thresholds)
    threat_score = min(threat_score_raw, 1.0)

    return threat_score, threat_score_raw, best_priority, {
        "base_score": round(base_score, 3),
        "synergy_boost": round(total_boost, 3),
        "patterns_matched": matched_patterns,
        "pattern_count": len(matched_patterns),
        "base_priority": base_priority,
        "priority_promoted": best_priority != base_priority,
        "category_count": len(categories),
    }

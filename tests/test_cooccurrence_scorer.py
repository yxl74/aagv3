"""Unit tests for co-occurrence scoring module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from apk_analyzer.knowledge.api_catalog import ApiCatalog
from apk_analyzer.phase0.cooccurrence_scorer import (
    COOCCURRENCE_PATTERNS,
    CooccurrencePattern,
    compute_threat_score,
    pattern_matches,
)


def _make_catalog(tmp_path: Path) -> ApiCatalog:
    """Create a test catalog with various categories."""
    payload = {
        "version": "test",
        "categories": {
            "SYSTEM_MANIPULATION_PACKAGE": {
                "priority": "HIGH",
                "description": "Package installation",
                "weight": 0.70,
                "mitre": {"primary": "T1398", "aliases": []},
                "requires_slice": True,
                "pha_tags": ["DROPPER"],
                "permission_hints": [],
                "signatures": {"methods": [], "fields": [], "strings": []},
            },
            "ABUSE_ACCESSIBILITY": {
                "priority": "CRITICAL",
                "description": "Accessibility abuse",
                "weight": 1.0,
                "mitre": {"primary": "T1517", "aliases": []},
                "requires_slice": True,
                "pha_tags": ["BANKING"],
                "permission_hints": [],
                "signatures": {"methods": [], "fields": [], "strings": []},
            },
            "C2_NETWORKING": {
                "priority": "HIGH",
                "description": "C2 networking",
                "weight": 0.65,
                "mitre": {"primary": "T1071", "aliases": []},
                "requires_slice": False,
                "pha_tags": ["RAT"],
                "permission_hints": [],
                "signatures": {"methods": [], "fields": [], "strings": []},
            },
            "SURVEILLANCE_SCREEN_CAPTURE": {
                "priority": "CRITICAL",
                "description": "Screen capture",
                "weight": 0.90,
                "mitre": {"primary": "T1513", "aliases": []},
                "requires_slice": True,
                "pha_tags": ["SPYWARE"],
                "permission_hints": [],
                "signatures": {"methods": [], "fields": [], "strings": []},
            },
            "INTERCEPT_SMS_MESSAGES": {
                "priority": "HIGH",
                "description": "SMS interception",
                "weight": 0.75,
                "mitre": {"primary": "T1412", "aliases": []},
                "requires_slice": True,
                "pha_tags": ["BANKING"],
                "permission_hints": ["RECEIVE_SMS"],
                "signatures": {"methods": [], "fields": [], "strings": []},
            },
            "DEFENSE_EVASION_NOTIFICATION_SUPPRESSION": {
                "priority": "HIGH",
                "description": "Notification suppression",
                "weight": 0.60,
                "mitre": {"primary": "T1406", "aliases": []},
                "requires_slice": False,
                "pha_tags": ["BANKING"],
                "permission_hints": [],
                "signatures": {"methods": [], "fields": [], "strings": []},
            },
            "DYNAMIC_CODE_LOADING": {
                "priority": "CRITICAL",
                "description": "Dynamic code loading",
                "weight": 1.0,
                "mitre": {"primary": "T1406", "aliases": []},
                "requires_slice": True,
                "pha_tags": ["BACKDOOR"],
                "permission_hints": [],
                "signatures": {"methods": [], "fields": [], "strings": []},
            },
            "EVASION_CRYPTO_OBFUSCATION": {
                "priority": "MEDIUM",
                "description": "Crypto obfuscation",
                "weight": 0.45,
                "mitre": {"primary": "T1406", "aliases": []},
                "requires_slice": False,
                "pha_tags": ["TROJAN"],
                "permission_hints": [],
                "signatures": {"methods": [], "fields": [], "strings": []},
            },
            "INPUT_PROMPT_OVERLAY": {
                "priority": "CRITICAL",
                "description": "Overlay prompt",
                "weight": 0.95,
                "mitre": {"primary": "T1411", "aliases": []},
                "requires_slice": True,
                "pha_tags": ["BANKING"],
                "permission_hints": [],
                "signatures": {"methods": [], "fields": [], "strings": []},
            },
            "SURVEILLANCE_LOCATION": {
                "priority": "HIGH",
                "description": "Location tracking",
                "weight": 0.60,
                "mitre": {"primary": "T1430", "aliases": []},
                "requires_slice": False,
                "pha_tags": ["SPYWARE"],
                "permission_hints": ["ACCESS_FINE_LOCATION"],
                "signatures": {"methods": [], "fields": [], "strings": []},
            },
            "SURVEILLANCE_AUDIO": {
                "priority": "CRITICAL",
                "description": "Audio recording",
                "weight": 0.85,
                "mitre": {"primary": "T1429", "aliases": []},
                "requires_slice": True,
                "pha_tags": ["SPYWARE"],
                "permission_hints": ["RECORD_AUDIO"],
                "signatures": {"methods": [], "fields": [], "strings": []},
            },
            "COLLECTION_SMS_MESSAGES": {
                "priority": "HIGH",
                "description": "SMS collection",
                "weight": 0.70,
                "mitre": {"primary": "T1412", "aliases": []},
                "requires_slice": True,
                "pha_tags": ["SPYWARE"],
                "permission_hints": ["READ_SMS"],
                "signatures": {"methods": [], "fields": [], "strings": []},
            },
        },
    }
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_text(json.dumps(payload), encoding="utf-8")
    return ApiCatalog.load(catalog_path)


class TestPatternMatches:
    """Tests for pattern_matches function."""

    def test_all_of_match(self) -> None:
        """Pattern with all_of should match when all categories present."""
        pattern = CooccurrencePattern(
            pattern_id="test",
            description="test",
            boost=0.1,
            all_of=frozenset({"A", "B"}),
        )
        assert pattern_matches(pattern, {"A", "B", "C"}) is True
        assert pattern_matches(pattern, {"A", "C"}) is False
        assert pattern_matches(pattern, {"B", "C"}) is False
        assert pattern_matches(pattern, set()) is False

    def test_any_of_match(self) -> None:
        """Pattern with any_of should match when at least one category present."""
        pattern = CooccurrencePattern(
            pattern_id="test",
            description="test",
            boost=0.1,
            any_of=frozenset({"A", "B"}),
        )
        assert pattern_matches(pattern, {"A"}) is True
        assert pattern_matches(pattern, {"B"}) is True
        assert pattern_matches(pattern, {"A", "B"}) is True
        assert pattern_matches(pattern, {"C"}) is False

    def test_all_of_and_any_of_combined(self) -> None:
        """Pattern with both all_of and any_of requires both conditions."""
        pattern = CooccurrencePattern(
            pattern_id="test",
            description="test",
            boost=0.1,
            all_of=frozenset({"A"}),
            any_of=frozenset({"B", "C"}),
        )
        assert pattern_matches(pattern, {"A", "B"}) is True
        assert pattern_matches(pattern, {"A", "C"}) is True
        assert pattern_matches(pattern, {"A", "B", "C"}) is True
        assert pattern_matches(pattern, {"A"}) is False  # Missing any_of
        assert pattern_matches(pattern, {"B"}) is False  # Missing all_of

    def test_any_of_2(self) -> None:
        """Pattern with any_of_2 requires match from second group too."""
        pattern = CooccurrencePattern(
            pattern_id="test",
            description="test",
            boost=0.1,
            all_of=frozenset({"A"}),
            any_of=frozenset({"B", "C"}),
            any_of_2=frozenset({"D", "E"}),
        )
        assert pattern_matches(pattern, {"A", "B", "D"}) is True
        assert pattern_matches(pattern, {"A", "C", "E"}) is True
        assert pattern_matches(pattern, {"A", "B", "C", "D", "E"}) is True
        assert pattern_matches(pattern, {"A", "B"}) is False  # Missing any_of_2
        assert pattern_matches(pattern, {"A", "D"}) is False  # Missing any_of

    def test_min_count_from_set(self) -> None:
        """Pattern with min_count requires N categories from set."""
        pattern = CooccurrencePattern(
            pattern_id="test",
            description="test",
            boost=0.1,
            min_count=3,
            from_set=frozenset({"A", "B", "C", "D", "E"}),
        )
        assert pattern_matches(pattern, {"A", "B", "C"}) is True
        assert pattern_matches(pattern, {"A", "B", "C", "D", "E"}) is True
        assert pattern_matches(pattern, {"A", "B"}) is False  # Only 2
        assert pattern_matches(pattern, {"A", "B", "X", "Y"}) is False  # Only 2 from set

    def test_empty_conditions_always_match(self) -> None:
        """Pattern with no conditions should match any categories."""
        pattern = CooccurrencePattern(
            pattern_id="test",
            description="test",
            boost=0.1,
        )
        assert pattern_matches(pattern, {"A", "B"}) is True
        assert pattern_matches(pattern, set()) is True


class TestComputeThreatScore:
    """Tests for compute_threat_score function."""

    def test_no_categories_returns_zero(self, tmp_path: Path) -> None:
        """Empty categories should return zero score."""
        catalog = _make_catalog(tmp_path)
        score, raw_score, priority, meta = compute_threat_score(set(), catalog)
        assert score == 0.0
        assert raw_score == 0.0
        assert priority == "LOW"
        assert meta.get("reason") == "no_categories"

    def test_base_score_is_max_weight(self, tmp_path: Path) -> None:
        """Base score should be max of category weights."""
        catalog = _make_catalog(tmp_path)
        # ABUSE_ACCESSIBILITY has weight 1.0, C2_NETWORKING has weight 0.65
        categories = {"ABUSE_ACCESSIBILITY", "C2_NETWORKING"}
        score, raw_score, priority, meta = compute_threat_score(categories, catalog)
        assert meta["base_score"] == 1.0
        assert priority == "CRITICAL"  # ABUSE_ACCESSIBILITY is CRITICAL

    def test_pattern_boost_applied(self, tmp_path: Path) -> None:
        """Matching patterns should add boost to score."""
        catalog = _make_catalog(tmp_path)
        # P_DROP_TO_ACCESSIBILITY pattern: SYSTEM_MANIPULATION_PACKAGE + ABUSE_ACCESSIBILITY
        categories = {"SYSTEM_MANIPULATION_PACKAGE", "ABUSE_ACCESSIBILITY"}
        score, raw_score, priority, meta = compute_threat_score(categories, catalog)

        # Should have base + boost
        assert meta["base_score"] == 1.0  # ABUSE_ACCESSIBILITY weight
        assert meta["synergy_boost"] > 0.0  # Pattern matched
        assert "P_DROP_TO_ACCESSIBILITY" in meta["patterns_matched"]
        assert raw_score > meta["base_score"]

    def test_priority_promotion(self, tmp_path: Path) -> None:
        """Pattern with priority_override should promote priority."""
        catalog = _make_catalog(tmp_path)
        # P_DROP_INSTALL_VIA_NET: SYSTEM_MANIPULATION_PACKAGE + C2_NETWORKING
        # Both are HIGH, but pattern has priority_override="HIGH" (confirms it)
        categories = {"SYSTEM_MANIPULATION_PACKAGE", "C2_NETWORKING"}
        score, raw_score, priority, meta = compute_threat_score(categories, catalog)

        assert "P_DROP_INSTALL_VIA_NET" in meta["patterns_matched"]
        assert priority == "HIGH"

    def test_priority_never_demoted(self, tmp_path: Path) -> None:
        """Priority should never be demoted, only promoted."""
        catalog = _make_catalog(tmp_path)
        # ABUSE_ACCESSIBILITY alone is CRITICAL
        categories = {"ABUSE_ACCESSIBILITY"}
        score, raw_score, priority, meta = compute_threat_score(categories, catalog)

        # Even with no pattern match, priority stays CRITICAL
        assert priority == "CRITICAL"
        assert meta["base_priority"] == "CRITICAL"

    def test_score_capped_at_one(self, tmp_path: Path) -> None:
        """Capped score should not exceed 1.0."""
        catalog = _make_catalog(tmp_path)
        # ABUSE_ACCESSIBILITY (1.0) + multiple patterns that would push it over
        categories = {
            "ABUSE_ACCESSIBILITY",
            "SURVEILLANCE_SCREEN_CAPTURE",
            "C2_NETWORKING",
            "INPUT_PROMPT_OVERLAY",
        }
        score, raw_score, priority, meta = compute_threat_score(categories, catalog)

        assert score <= 1.0
        assert raw_score >= score  # Raw can exceed 1.0

    def test_raw_score_provides_separation(self, tmp_path: Path) -> None:
        """Raw score should provide ranking separation for high-scoring blocks."""
        catalog = _make_catalog(tmp_path)

        # Block 1: ABUSE_ACCESSIBILITY only
        categories1 = {"ABUSE_ACCESSIBILITY"}
        score1, raw1, _, _ = compute_threat_score(categories1, catalog)

        # Block 2: ABUSE_ACCESSIBILITY + pattern match
        categories2 = {"ABUSE_ACCESSIBILITY", "SURVEILLANCE_SCREEN_CAPTURE", "C2_NETWORKING"}
        score2, raw2, _, _ = compute_threat_score(categories2, catalog)

        # Both should cap at 1.0 but raw scores should differ
        # Note: Block 2 raw score should be higher due to pattern boost
        assert raw2 > raw1 or (raw2 == raw1 and score2 >= score1)

    def test_odf_pattern_match(self, tmp_path: Path) -> None:
        """ODF/ATS pattern should match and boost."""
        catalog = _make_catalog(tmp_path)
        # P_ODF_REMOTE_STREAM: ABUSE_ACCESSIBILITY + SURVEILLANCE_SCREEN_CAPTURE + (C2_NETWORKING or C2_PUSH_FCM)
        categories = {"ABUSE_ACCESSIBILITY", "SURVEILLANCE_SCREEN_CAPTURE", "C2_NETWORKING"}
        score, raw_score, priority, meta = compute_threat_score(categories, catalog)

        assert "P_ODF_REMOTE_STREAM" in meta["patterns_matched"]
        assert priority == "CRITICAL"

    def test_otp_theft_pattern(self, tmp_path: Path) -> None:
        """OTP theft pattern should match."""
        catalog = _make_catalog(tmp_path)
        # P_OTP_SMS_AND_NOTIFICATION_HIDE: INTERCEPT_SMS_MESSAGES + DEFENSE_EVASION_NOTIFICATION_SUPPRESSION
        categories = {"INTERCEPT_SMS_MESSAGES", "DEFENSE_EVASION_NOTIFICATION_SUPPRESSION"}
        score, raw_score, priority, meta = compute_threat_score(categories, catalog)

        assert "P_OTP_SMS_AND_NOTIFICATION_HIDE" in meta["patterns_matched"]
        assert priority == "CRITICAL"

    def test_stalkerware_bundle_pattern(self, tmp_path: Path) -> None:
        """Stalkerware bundle pattern should match with 3+ surveillance categories."""
        catalog = _make_catalog(tmp_path)
        # P_STALKERWARE_COLLECTION_BUNDLE: 3+ from surveillance set
        categories = {
            "SURVEILLANCE_LOCATION",
            "SURVEILLANCE_AUDIO",
            "COLLECTION_SMS_MESSAGES",
        }
        score, raw_score, priority, meta = compute_threat_score(categories, catalog)

        assert "P_STALKERWARE_COLLECTION_BUNDLE" in meta["patterns_matched"]
        # Priority is CRITICAL because SURVEILLANCE_AUDIO has CRITICAL base priority
        # (pattern's HIGH override cannot demote, only promote)
        assert priority == "CRITICAL"

    def test_multiple_patterns_accumulate_boost(self, tmp_path: Path) -> None:
        """Multiple matching patterns should accumulate their boosts."""
        catalog = _make_catalog(tmp_path)
        # Categories that match multiple patterns
        categories = {
            "ABUSE_ACCESSIBILITY",
            "SURVEILLANCE_SCREEN_CAPTURE",
            "C2_NETWORKING",
            "INPUT_PROMPT_OVERLAY",
        }
        score, raw_score, priority, meta = compute_threat_score(categories, catalog)

        # Should match multiple patterns
        assert meta["pattern_count"] >= 2
        assert meta["synergy_boost"] > 0.2  # Multiple boosts accumulated


class TestPerLevelBoosts:
    """Tests for per-level boost functionality (Fix 8.8 regression)."""

    def test_boost_group_returns_boost_value(self) -> None:
        """boost_group property should return the original boost value."""
        pattern = CooccurrencePattern(
            pattern_id="test",
            description="test",
            boost=0.25,
            all_of=frozenset({"A", "B"}),
        )
        assert pattern.boost_group == 0.25

    def test_boost_block_returns_forty_percent(self) -> None:
        """boost_block property should return 40% of boost value."""
        pattern = CooccurrencePattern(
            pattern_id="test",
            description="test",
            boost=0.25,
            all_of=frozenset({"A", "B"}),
        )
        assert pattern.boost_block == 0.1  # 0.25 * 0.4 = 0.1

    def test_boost_block_rounding(self) -> None:
        """boost_block should round to 3 decimal places."""
        pattern = CooccurrencePattern(
            pattern_id="test",
            description="test",
            boost=0.33,  # 0.33 * 0.4 = 0.132
            all_of=frozenset({"A"}),
        )
        assert pattern.boost_block == 0.132

    def test_compute_score_uses_group_boost_by_default(self, tmp_path: Path) -> None:
        """compute_threat_score should use boost_group by default."""
        catalog = _make_catalog(tmp_path)
        # P_DROP_TO_ACCESSIBILITY pattern with boost 0.20
        categories = {"SYSTEM_MANIPULATION_PACKAGE", "ABUSE_ACCESSIBILITY"}

        # Default level is "group"
        score, raw, priority, meta = compute_threat_score(categories, catalog)
        group_boost = meta["synergy_boost"]
        assert group_boost > 0.0

    def test_compute_score_block_level_has_lower_boost(self, tmp_path: Path) -> None:
        """Block level should produce lower synergy boost than group level."""
        catalog = _make_catalog(tmp_path)
        # P_DROP_TO_ACCESSIBILITY pattern
        categories = {"SYSTEM_MANIPULATION_PACKAGE", "ABUSE_ACCESSIBILITY"}

        _, _, _, meta_group = compute_threat_score(categories, catalog, level="group")
        _, _, _, meta_block = compute_threat_score(categories, catalog, level="block")

        # Block level should have ~40% of group boost
        group_boost = meta_group["synergy_boost"]
        block_boost = meta_block["synergy_boost"]
        assert block_boost < group_boost
        assert abs(block_boost - group_boost * 0.4) < 0.01  # Within rounding


class TestCooccurrencePatterns:
    """Tests for the defined patterns."""

    def test_all_patterns_have_required_fields(self) -> None:
        """All patterns should have required fields."""
        for pattern in COOCCURRENCE_PATTERNS:
            assert pattern.pattern_id
            assert pattern.description
            assert isinstance(pattern.boost, float)
            assert pattern.boost >= 0.0
            assert pattern.boost <= 0.5

    def test_pattern_ids_unique(self) -> None:
        """All pattern IDs should be unique."""
        ids = [p.pattern_id for p in COOCCURRENCE_PATTERNS]
        assert len(ids) == len(set(ids))

    def test_pattern_count(self) -> None:
        """Should have expected number of patterns."""
        # 17 research patterns + 1 toll fraud = 18
        assert len(COOCCURRENCE_PATTERNS) == 18

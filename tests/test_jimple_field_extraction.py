"""Tests for Jimple field reference extraction (Fix 8.2 regression)."""

from __future__ import annotations

import re

# Import the regex and mapping from orchestrator
from apk_analyzer.agents.orchestrator import (
    _FIELD_PATTERN,
    KNOWN_FIELD_VALUES,
)


class TestJimpleFieldPattern:
    """Tests for Jimple field reference regex pattern."""

    def test_matches_accessibility_settings_field(self) -> None:
        """Should match real Jimple staticget format for Settings.ACTION_ACCESSIBILITY_SETTINGS."""
        jimple = 'staticget <android.provider.Settings: java.lang.String ACTION_ACCESSIBILITY_SETTINGS>'
        match = _FIELD_PATTERN.search(jimple)
        assert match is not None
        class_name, field_name = match.groups()
        assert class_name == "android.provider.Settings"
        assert field_name == "ACTION_ACCESSIBILITY_SETTINGS"

    def test_matches_notification_listener_settings(self) -> None:
        """Should match Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS field."""
        jimple = '<android.provider.Settings: java.lang.String ACTION_NOTIFICATION_LISTENER_SETTINGS>'
        match = _FIELD_PATTERN.search(jimple)
        assert match is not None
        class_name, field_name = match.groups()
        assert class_name == "android.provider.Settings"
        assert field_name == "ACTION_NOTIFICATION_LISTENER_SETTINGS"

    def test_matches_usage_access_settings(self) -> None:
        """Should match Settings.ACTION_USAGE_ACCESS_SETTINGS field."""
        jimple = 'r0 = <android.provider.Settings: java.lang.String ACTION_USAGE_ACCESS_SETTINGS>'
        match = _FIELD_PATTERN.search(jimple)
        assert match is not None
        _, field_name = match.groups()
        assert field_name == "ACTION_USAGE_ACCESS_SETTINGS"

    def test_matches_overlay_permission(self) -> None:
        """Should match Settings.ACTION_MANAGE_OVERLAY_PERMISSION field."""
        jimple = '<android.provider.Settings: java.lang.String ACTION_MANAGE_OVERLAY_PERMISSION>'
        match = _FIELD_PATTERN.search(jimple)
        assert match is not None

    def test_does_not_match_non_string_fields(self) -> None:
        """Should not match non-String field types."""
        jimple = '<android.provider.Settings: int SOME_INT_FIELD>'
        match = _FIELD_PATTERN.search(jimple)
        assert match is None

    def test_does_not_match_malformed_input(self) -> None:
        """Should not match malformed Jimple."""
        bad_inputs = [
            "android.provider.Settings.ACTION_ACCESSIBILITY_SETTINGS",  # Not angle bracket format
            "<android.provider.Settings ACTION_ACCESSIBILITY_SETTINGS>",  # Missing colon
            "<: java.lang.String ACTION_ACCESSIBILITY_SETTINGS>",  # Missing class
        ]
        for inp in bad_inputs:
            match = _FIELD_PATTERN.search(inp)
            assert match is None, f"Should not match: {inp}"


class TestKnownFieldValues:
    """Tests for known field value mappings."""

    def test_accessibility_settings_mapped(self) -> None:
        """ACTION_ACCESSIBILITY_SETTINGS should map to correct intent string."""
        key = "android.provider.Settings.ACTION_ACCESSIBILITY_SETTINGS"
        assert key in KNOWN_FIELD_VALUES
        assert KNOWN_FIELD_VALUES[key] == "android.settings.ACCESSIBILITY_SETTINGS"

    def test_notification_listener_mapped(self) -> None:
        """ACTION_NOTIFICATION_LISTENER_SETTINGS should map correctly."""
        key = "android.provider.Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS"
        assert key in KNOWN_FIELD_VALUES
        assert "NOTIFICATION_LISTENER" in KNOWN_FIELD_VALUES[key]

    def test_all_values_are_intent_actions(self) -> None:
        """All mapped values should look like Android intent actions."""
        for key, value in KNOWN_FIELD_VALUES.items():
            assert "android.settings" in value or "android.provider" in value, (
                f"Value {value} doesn't look like an intent action"
            )

    def test_field_extraction_integration(self) -> None:
        """Integration test: regex match → lookup → resolved value."""
        jimple = 'staticget <android.provider.Settings: java.lang.String ACTION_ACCESSIBILITY_SETTINGS>'
        match = _FIELD_PATTERN.search(jimple)
        assert match is not None

        class_name, field_name = match.groups()
        field_key = f"{class_name}.{field_name}"
        resolved = KNOWN_FIELD_VALUES.get(field_key)

        assert resolved == "android.settings.ACCESSIBILITY_SETTINGS"

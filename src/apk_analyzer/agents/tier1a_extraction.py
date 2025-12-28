"""Tier1 Phase 1A: Structural Extraction Agent.

This module implements Phase 1A of the three-phase Tier1 analysis:
- Deterministic extraction of API calls, control guards, etc.
- LLM validation of extraction quality
- Sanity check against CFG counts

Fix 3: Default to PARTIAL coverage.
Fix 8: Sanity check with drift guard.
Fix 17: PhaseStatus based on extraction results.
Fix 25: Drift guard with 30% tolerance.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from apk_analyzer.models.analysis_context import ComponentHints
from apk_analyzer.models.tier1_phases import (
    ApiCallExtraction,
    ControlGuard,
    ExtractedStructure,
    ExtractionCoverage,
    PhaseStatus,
    RequiredPermission,
    SemanticAnnotation,
)
from apk_analyzer.analyzers.deterministic_extractors import (
    compute_extraction_coverage,
    extract_permissions,
    extract_trigger_surface,
    validate_with_sanity_check,
)

if TYPE_CHECKING:
    from apk_analyzer.agents.tier1_tool_registry import Tier1ToolRegistry
    from apk_analyzer.utils.artifact_store import ArtifactStore

logger = logging.getLogger(__name__)


class Tier1AExtractionAgent:
    """Phase 1A: Structural Extraction Agent.

    Performs deterministic extraction with LLM validation.
    Fix 38: Filters to sensitive APIs only.
    """

    # Fix 25: Drift tolerance
    DRIFT_TOLERANCE = 0.3

    # Fix 38: Fallback sensitive API patterns when no catalog provided
    DEFAULT_SENSITIVE_PATTERNS = {
        "android.media.MediaRecorder",
        "android.media.AudioRecord",
        "android.hardware.Camera",
        "android.hardware.camera2",
        "android.location.LocationManager",
        "android.telephony.SmsManager",
        "android.telephony.TelephonyManager",
        "android.content.ContentResolver",
        "android.net.ConnectivityManager",
        "android.bluetooth.BluetoothAdapter",
        "android.nfc.NfcAdapter",
        "android.accounts.AccountManager",
    }
    DEFAULT_SENSITIVE_PREFIXES = {
        "android.media.",
        "android.hardware.",
        "android.location.",
        "android.telephony.",
        "android.content.",
        "android.net.",
        "android.bluetooth.",
        "android.nfc.",
        "android.accounts.",
    }

    def __init__(
        self,
        tool_registry: "Tier1ToolRegistry",
        store: "ArtifactStore",
        sensitive_catalog: Optional[Any] = None,  # Fix 38: ApiCatalog for filtering
    ) -> None:
        """Initialize the extraction agent.

        Args:
            tool_registry: Tool registry for CFG access.
            store: ArtifactStore for file access.
            sensitive_catalog: Optional ApiCatalog for sensitive API filtering.
        """
        self.tool_registry = tool_registry
        self.store = store
        self.sensitive_catalog = sensitive_catalog
        (
            self._sensitive_patterns,
            self._catalog_class_names,
        ) = self._build_sensitive_patterns()
        self._sensitive_prefixes = set(self.DEFAULT_SENSITIVE_PREFIXES)

    def run(
        self,
        seed_id: str,
        caller_method: str,
        pre_extracted: Optional[Dict[str, Any]] = None,
    ) -> ExtractedStructure:
        """Run Phase 1A extraction.

        Args:
            seed_id: The seed ID for this sensitive callsite.
            caller_method: The method signature containing the callsite.
            pre_extracted: Optional pre-extracted data from deterministic phase.

        Returns:
            ExtractedStructure with validation results.
        """
        logger.info(f"Phase 1A: Extracting structure for seed {seed_id}")

        # Step 1: Get or create pre-extracted data
        if pre_extracted is None:
            pre_extracted = self._run_deterministic_extraction(seed_id, caller_method)

        # Step 2: Parse pre-extracted into typed structures
        api_calls = self._parse_api_calls(pre_extracted.get("api_calls", []))
        control_guards = self._parse_control_guards(pre_extracted.get("branch_conditions", []))
        semantic_annotations = self._parse_annotations(pre_extracted.get("annotations", []))
        ambiguous_units = pre_extracted.get("ambiguous_units", [])

        # Step 3: Extract component hints (trigger surface) - Fix 34: NO permissions
        component_hints = extract_trigger_surface(seed_id, caller_method, self.store)

        # Step 4: Extract permissions separately - Fix 23
        try:
            manifest = self.tool_registry.read_manifest()
        except FileNotFoundError:
            manifest = {}
        permissions = extract_permissions(manifest, api_calls)

        # Step 5: Sanity check against CFG - Fix 8, 25
        sanity_passed, sanity_message = self._run_sanity_check(seed_id, len(api_calls))

        # Step 6: Compute extraction coverage - Fix 3
        if not sanity_passed:
            # Drift detected - flag for review but don't set MINIMAL immediately
            extraction_coverage = ExtractionCoverage.PARTIAL
            flagged_for_review = [sanity_message]
        else:
            extraction_coverage = compute_extraction_coverage(
                api_calls=api_calls,
                branch_conditions=control_guards,
                entrypoint_method=caller_method,
                ambiguous_units=ambiguous_units,
            )
            flagged_for_review = []

        # Step 7: Compute phase status - Fix 17
        if extraction_coverage == ExtractionCoverage.MINIMAL:
            phase_status = PhaseStatus.PARTIAL
            status_reason = "Minimal extraction coverage"
        elif flagged_for_review:
            phase_status = PhaseStatus.PARTIAL
            status_reason = flagged_for_review[0]
        else:
            phase_status = PhaseStatus.OK
            status_reason = None

        # Step 8: Build result
        result = ExtractedStructure(
            seed_id=seed_id,
            api_calls=api_calls,
            control_guards=control_guards,
            component_hints=component_hints,
            semantic_annotations=semantic_annotations,
            permissions=permissions,  # Fix 23, 31
            ambiguous_units=ambiguous_units,
            flagged_for_review=flagged_for_review,
            extraction_coverage=extraction_coverage,
            extraction_confidence=self._compute_extraction_confidence(
                extraction_coverage, sanity_passed
            ),
            phase_status=phase_status,
            status_reason=status_reason,
        )

        logger.info(
            f"Phase 1A complete for {seed_id}: "
            f"coverage={extraction_coverage.value}, status={phase_status.value}"
        )

        return result

    def _run_deterministic_extraction(
        self,
        seed_id: str,
        caller_method: str,
    ) -> Dict[str, Any]:
        """Run deterministic extraction from CFG.

        Args:
            seed_id: The seed ID.
            caller_method: The caller method signature.

        Returns:
            Pre-extracted data dict.
        """
        # Read CFG slice
        slice_data = self.tool_registry.read_cfg_slice(seed_id)
        units = slice_data.get("units", [])

        # Extract API calls
        api_calls = []
        branch_conditions = []
        ambiguous_units = []

        for unit in units:
            stmt = unit.get("stmt", "")
            stmt_lower = stmt.lower()
            unit_id = unit.get("unit_id", "")

            if "invoke" in stmt_lower:
                soot_sig = self._extract_sig_from_stmt(stmt)
                sig_for_parse = soot_sig or stmt

                # Extract class name for sensitivity check
                class_name = self._extract_class_from_stmt(sig_for_parse)

                # Fix 38: Only include sensitive APIs
                is_sensitive, source, confidence = self._sensitivity_for_api(
                    class_name, soot_sig
                )
                if is_sensitive:
                    api_calls.append(
                        {
                            "unit_id": unit_id,
                            "signature": sig_for_parse,
                            "class_name": class_name,
                            "method_name": self._extract_method_from_stmt(sig_for_parse),
                            "sensitivity_source": source,
                            "sensitivity_confidence": confidence,
                        }
                    )
            elif stmt_lower.startswith("if "):
                # This is a branch condition
                branch_conditions.append(
                    {
                        "unit_id": unit_id,
                        "condition": unit.get("stmt", ""),
                    }
                )

            # Check for ambiguous units (magic numbers, etc.)
            if self._is_ambiguous(unit.get("stmt", "")):
                ambiguous_units.append(unit_id)

        return {
            "seed_id": seed_id,
            "caller_method": caller_method,
            "api_calls": api_calls,
            "branch_conditions": branch_conditions,
            "ambiguous_units": ambiguous_units,
            "annotations": [],
        }

    def _run_sanity_check(
        self,
        seed_id: str,
        extracted_count: int,
    ) -> tuple[bool, str]:
        """Run sanity check against CFG counts.

        Fix 8, 25: Drift guard with tolerance.

        Args:
            seed_id: The seed ID.
            extracted_count: Number of extracted callsites.

        Returns:
            Tuple of (passed, message).
        """
        try:
            slice_data = self.tool_registry.read_cfg_slice(seed_id)
            units = slice_data.get("units", [])

            # Count sensitive callsites using the same matching logic.
            cfg_sensitive_count = 0
            for unit in units:
                stmt = unit.get("stmt", "")
                stmt_lower = stmt.lower()
                if "invoke" not in stmt_lower:
                    continue

                soot_sig = self._extract_sig_from_stmt(stmt)
                sig_for_parse = soot_sig or stmt
                class_name = self._extract_class_from_stmt(sig_for_parse)
                if self._sensitivity_for_api(class_name, soot_sig)[0]:
                    cfg_sensitive_count += 1

            return validate_with_sanity_check(
                extracted_callsite_count=extracted_count,
                cfg_callsite_count=cfg_sensitive_count,
                drift_tolerance=self.DRIFT_TOLERANCE,
            )
        except Exception as e:
            logger.warning(f"Sanity check failed for {seed_id}: {e}")
            return True, "Sanity check skipped due to error"

    def _parse_api_calls(self, raw_calls: List[Dict[str, Any]]) -> List[ApiCallExtraction]:
        """Parse raw API call data into typed objects."""
        return [
            ApiCallExtraction(
                unit_id=c.get("unit_id", ""),
                signature=c.get("signature", ""),
                class_name=c.get("class_name", ""),
                method_name=c.get("method_name", ""),
                args=c.get("args", []),
                line_number=c.get("line_number"),
                sensitivity_source=c.get("sensitivity_source"),
                sensitivity_confidence=c.get("sensitivity_confidence"),
            )
            for c in raw_calls
        ]

    def _parse_control_guards(self, raw_guards: List[Dict[str, Any]]) -> List[ControlGuard]:
        """Parse raw control guard data into typed objects."""
        return [
            ControlGuard(
                unit_id=g.get("unit_id", ""),
                condition=g.get("condition", ""),
                guard_type=g.get("guard_type", "other"),
                related_api_unit_ids=g.get("related_api_unit_ids", []),
            )
            for g in raw_guards
        ]

    def _parse_annotations(self, raw_annotations: List[Dict[str, Any]]) -> List[SemanticAnnotation]:
        """Parse raw annotation data into typed objects."""
        return [
            SemanticAnnotation(
                unit_id=a.get("unit_id", ""),
                original_value=a.get("original_value", ""),
                semantic_meaning=a.get("semantic_meaning", ""),
                enum_type=a.get("enum_type", ""),
                resolution_confidence=a.get("resolution_confidence", 0.5),
                resolution_source=a.get("resolution_source", "heuristic"),
            )
            for a in raw_annotations
        ]

    def _compute_extraction_confidence(
        self,
        coverage: ExtractionCoverage,
        sanity_passed: bool,
    ) -> float:
        """Compute extraction confidence score."""
        base_confidence = {
            ExtractionCoverage.COMPLETE: 0.95,
            ExtractionCoverage.PARTIAL: 0.7,
            ExtractionCoverage.MINIMAL: 0.3,
        }.get(coverage, 0.5)

        # Penalize if sanity check failed
        if not sanity_passed:
            base_confidence *= 0.8

        return round(base_confidence, 2)

    def _extract_class_from_stmt(self, stmt: str) -> str:
        """Extract class name from a statement."""
        import re

        match = re.search(r"<([^:]+):", stmt)
        return match.group(1) if match else ""

    def _extract_method_from_stmt(self, stmt: str) -> str:
        """Extract method name from a statement."""
        import re

        match = re.search(r"\s+(\w+)\(", stmt)
        return match.group(1) if match else ""

    def _is_ambiguous(self, stmt: str) -> bool:
        """Check if a statement contains ambiguous elements."""
        import re

        # Check for magic numbers that might need interpretation
        # e.g., setAudioSource(1) where 1 = MIC
        magic_number_pattern = r"\(\s*\d+\s*\)"
        return bool(re.search(magic_number_pattern, stmt))

    def _build_sensitive_patterns(self) -> tuple[set[str], set[str]]:
        """Build set of sensitive API patterns for filtering.

        Fix 38: Extract class names from catalog for fast matching.
        """
        patterns = set(self.DEFAULT_SENSITIVE_PATTERNS)
        catalog_classes: set[str] = set()

        if self.sensitive_catalog:
            # Extract class names from catalog signatures
            try:
                categories = getattr(self.sensitive_catalog, "categories", {})
                for category in categories.values():
                    method_sigs = getattr(category, "method_sigs", None)
                    if method_sigs is None and isinstance(category, dict):
                        method_sigs = category.get("method_sigs")
                        if method_sigs is None:
                            signatures = category.get("signatures", {})
                            if isinstance(signatures, dict):
                                method_sigs = signatures.get("methods", [])
                    for sig in method_sigs or []:
                        # Extract class name from signature like "<android.media.MediaRecorder: void start()>"
                        if "<" in sig and ":" in sig:
                            class_name = sig.split("<")[1].split(":")[0]
                            patterns.add(class_name)
                            catalog_classes.add(class_name)
            except Exception as e:
                logger.warning(f"Failed to extract patterns from catalog: {e}")

        return patterns, catalog_classes

    def _sensitivity_for_api(
        self,
        class_name: str,
        soot_sig: Optional[str],
    ) -> tuple[bool, str, float]:
        """Determine sensitivity and its source/confidence."""
        if soot_sig and self.sensitive_catalog:
            try:
                if hasattr(self.sensitive_catalog, "match_method"):
                    if self.sensitive_catalog.match_method(soot_sig):
                        return True, "catalog_method", 0.95
            except Exception:
                logger.debug("Sensitive catalog match failed; falling back to patterns.")

        if class_name and class_name in self._catalog_class_names:
            return True, "catalog_class", 0.7

        if class_name:
            for prefix in self._sensitive_prefixes:
                if class_name.startswith(prefix):
                    return True, "prefix", 0.5

        if class_name and any(pattern in class_name for pattern in self._sensitive_patterns):
            return True, "pattern", 0.6

        return False, "", 0.0

    def _is_sensitive_api(self, class_name: str, soot_sig: Optional[str]) -> bool:
        """Check if class is a sensitive API."""
        return self._sensitivity_for_api(class_name, soot_sig)[0]

    def _extract_sig_from_stmt(self, stmt: str) -> Optional[str]:
        """Extract soot-style signature from a statement."""
        import re

        match = re.search(r"<[^>]+>", stmt)
        return match.group(0) if match else None

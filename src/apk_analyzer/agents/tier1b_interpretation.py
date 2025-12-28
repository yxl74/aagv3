"""Tier1 Phase 1B: Semantic Interpretation Agent.

This module implements Phase 1B of the three-phase Tier1 analysis:
- Behavioral interpretation of API calls
- Ambiguity resolution via JADX/CFG tools
- Strict per-callsite claim enforcement

Fix 1: JADX fallback strategy with resolved_by tracking.
Fix 9: tier1_field in each claim.
Fix 11: Per-unit source_lookups tracking.
Fix 17: PhaseStatus based on interpretation results.
Fix 19: Run for ALL sensitive API callsites.
Fix 22: API claim coverage validation.
Fix 27: Strict per-callsite claim enforcement with unclaimed_apis.
Fix 32: Unified claim coverage policy - per-callsite EFFECT claims.
Fix 33: Unknown API handling with needs_investigation.
Improvement D: unresolved_ratio in output.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from apk_analyzer.models.tier1_phases import (
    ApiCallExtraction,
    ExtractedStructure,
    InterpretedBehavior,
    InterpretedClaim,
    PhaseStatus,
    SourceLookup,
)
from apk_analyzer.utils.signature_normalize import normalize_signature

if TYPE_CHECKING:
    from apk_analyzer.agents.tier1_tool_registry import Tier1ToolRegistry

logger = logging.getLogger(__name__)


class JADXDecompilationError(Exception):
    """Raised when JADX decompilation fails."""

    pass


class Tier1BInterpretationAgent:
    """Phase 1B: Semantic Interpretation Agent.

    Performs behavioral interpretation with strict claim enforcement.
    Fix 39: Properly handles ApiCatalog object for known API lookups.
    """

    DEFAULT_KNOWN_PREFIXES = {
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
        api_catalog: Optional[Any] = None,  # Fix 39: Accept ApiCatalog or Dict
    ) -> None:
        """Initialize the interpretation agent.

        Args:
            tool_registry: Tool registry for source access.
            api_catalog: Optional API catalog (ApiCatalog object or Dict).
        """
        self.tool_registry = tool_registry
        self._api_catalog_raw = api_catalog
        self._claim_counter = 0
        self._known_prefixes = set(self.DEFAULT_KNOWN_PREFIXES)
        self._warned_empty_catalog = False

        # Fix 39: Build signature set for fast lookup
        self._known_signatures: set = set()
        self._build_signature_set(api_catalog)

    def run(
        self,
        seed_id: str,
        extracted: ExtractedStructure,
    ) -> InterpretedBehavior:
        """Run Phase 1B interpretation.

        Fix 19: Run for ALL seeds with sensitive API callsites.
        Fix 32: Strict per-callsite EFFECT claim enforcement.

        Args:
            seed_id: The seed ID.
            extracted: Phase 1A output.

        Returns:
            InterpretedBehavior with claims and source lookups.
        """
        logger.info(f"Phase 1B: Interpreting behavior for seed {seed_id}")

        claims: List[InterpretedClaim] = []
        source_lookups: List[SourceLookup] = []
        unresolved: List[str] = []

        # Reset claim counter for this seed
        self._claim_counter = 0

        # Part 1: Behavioral interpretation for ALL API callsites (Fix 19)
        for api_call in extracted.api_calls:
            claim = self._interpret_api_call(api_call, source_lookups)
            claims.append(claim)

        # Part 2: Ambiguity resolution for ambiguous units
        for unit_id in extracted.ambiguous_units:
            result = self._resolve_ambiguity(
                seed_id, unit_id, source_lookups
            )
            if result:
                claims.append(result)
            else:
                unresolved.append(unit_id)

        # Build result with strict audit (Fix 32)
        result = InterpretedBehavior.compute_with_strict_audit(
            seed_id=seed_id,
            claims=claims,
            source_lookups=source_lookups,
            api_calls=extracted.api_calls,
            ambiguous_units=extracted.ambiguous_units,
            unresolved=unresolved,
        )

        logger.info(
            f"Phase 1B complete for {seed_id}: "
            f"claims={len(claims)}, unclaimed={len(result.unclaimed_apis)}, "
            f"status={result.phase_status.value}"
        )

        return result

    def _interpret_api_call(
        self,
        api_call: ApiCallExtraction,
        source_lookups: List[SourceLookup],
    ) -> InterpretedClaim:
        """Interpret a single API call.

        Fix 32: Every API callsite MUST have an EFFECT claim.
        Fix 33: Unknown APIs get needs_investigation=True.

        Args:
            api_call: The API call to interpret.
            source_lookups: List to append source lookup to.

        Returns:
            InterpretedClaim for this API call.
        """
        # Check if API is in catalog (behavior known)
        is_known = self._is_known_api(api_call.signature)
        sensitivity_confidence = api_call.sensitivity_confidence or 0.0

        if is_known:
            # Known API - interpret with high confidence
            interpretation = self._get_api_interpretation(api_call)
            confidence = 0.85
            needs_investigation = False
            resolved_by = "heuristic"
        else:
            # Unknown API - still produce claim per Fix 32, flag per Fix 33
            interpretation = (
                f"Unknown API effect: {api_call.signature} - requires investigation"
            )
            confidence = 0.3
            needs_investigation = True
            resolved_by = "heuristic"

        if sensitivity_confidence:
            confidence = min(confidence, sensitivity_confidence)

        # Record source lookup (Fix 11)
        source_lookups.append(
            SourceLookup(
                unit_id=api_call.unit_id,
                tool_used="read_cfg_units",
                tool_args={"unit_id": api_call.unit_id},
                success=is_known,
                failure_reason=None if is_known else "Behavior unclear from catalog/context",
            )
        )

        self._claim_counter += 1
        return InterpretedClaim(
            claim_id=f"c{self._claim_counter:03d}",
            unit_id=api_call.unit_id,
            claim_type="effect",  # Fix 32: EFFECT claims required
            tier1_field="observable_effects",  # Fix 9
            interpretation=interpretation,
            source_unit_ids=[api_call.unit_id],
            resolved_by=resolved_by,  # Fix 1
            confidence=confidence,
            needs_investigation=needs_investigation,  # Fix 33
        )

    def _resolve_ambiguity(
        self,
        seed_id: str,
        unit_id: str,
        source_lookups: List[SourceLookup],
    ) -> Optional[InterpretedClaim]:
        """Resolve an ambiguous unit via JADX/CFG fallback.

        Fix 1: Tiered resolution with tracking.

        Args:
            seed_id: The seed ID.
            unit_id: The unit ID to resolve.
            source_lookups: List to append source lookup to.

        Returns:
            InterpretedClaim if resolved, None otherwise.
        """
        # Try JADX first
        try:
            parsed_units = self.tool_registry.read_cfg_units_parsed(seed_id, [unit_id])
            if parsed_units:
                unit = parsed_units[0]
                if unit.call_sig:
                    # Try to get Java source
                    source = self.tool_registry.read_java_source(unit.call_sig)
                    if source:
                        source_lookups.append(
                            SourceLookup(
                                unit_id=unit_id,
                                tool_used="read_java_source",
                                tool_args={"method_sig": unit.call_sig},
                                success=True,
                            )
                        )

                        self._claim_counter += 1
                        return InterpretedClaim(
                            claim_id=f"c{self._claim_counter:03d}",
                            unit_id=unit_id,
                            claim_type="constraint",
                            tier1_field="path_constraints",
                            interpretation=f"Resolved via JADX: {unit.raw_stmt[:100]}",
                            source_unit_ids=[unit_id],
                            resolved_by="jadx",
                            confidence=0.9,
                        )
        except Exception as e:
            logger.debug(f"JADX resolution failed for {unit_id}: {e}")

        # Fallback to CFG-based interpretation
        try:
            units = self.tool_registry.read_cfg_units(seed_id, [unit_id])
            if units:
                source_lookups.append(
                    SourceLookup(
                        unit_id=unit_id,
                        tool_used="read_cfg_units",
                        tool_args={"unit_ids": [unit_id]},
                        success=True,
                    )
                )

                self._claim_counter += 1
                return InterpretedClaim(
                    claim_id=f"c{self._claim_counter:03d}",
                    unit_id=unit_id,
                    claim_type="constraint",
                    tier1_field="path_constraints",
                    interpretation=f"Resolved via CFG: {units[0].get('stmt', '')[:100]}",
                    source_unit_ids=[unit_id],
                    resolved_by="cfg",
                    confidence=0.7,
                )
        except Exception as e:
            logger.debug(f"CFG resolution failed for {unit_id}: {e}")

        # Both failed - record as unresolved
        source_lookups.append(
            SourceLookup(
                unit_id=unit_id,
                tool_used="read_cfg_units",
                tool_args={"unit_ids": [unit_id]},
                success=False,
                failure_reason="JADX and CFG resolution both failed",
            )
        )

        return None

    def _build_signature_set(self, api_catalog: Optional[Any]) -> None:
        """Build signature set from API catalog for fast lookup.

        Fix 39: Properly extracts signatures from ApiCatalog object.
        """
        if not api_catalog:
            return

        try:
            # Try to get categories from ApiCatalog object
            categories = getattr(api_catalog, 'categories', None)
            if categories is None and isinstance(api_catalog, dict):
                categories = api_catalog

            if categories:
                for category in categories.values():
                    # Handle ApiCategory objects first
                    method_sigs = getattr(category, "method_sigs", None)

                    # Fallback for dict-based categories
                    if method_sigs is None and isinstance(category, dict):
                        method_sigs = category.get("method_sigs")
                        if method_sigs is None:
                            signatures = category.get("signatures", {})
                            if isinstance(signatures, dict):
                                method_sigs = signatures.get("methods", [])

                    if method_sigs:
                        self._known_signatures.update(method_sigs)

            logger.debug(f"Built signature set with {len(self._known_signatures)} entries")
            if not self._known_signatures:
                logger.warning("API catalog signature set is empty; falling back to prefix matching.")
        except Exception as e:
            logger.warning(f"Failed to build signature set from catalog: {e}")

    def _is_known_api(self, signature: str) -> bool:
        """Check if an API is in the known catalog.

        Fix 39: Uses pre-built signature set for fast lookup.
        """
        # First check: exact soot signature match in catalog
        signature = normalize_signature(signature) if signature else ""
        if self._known_signatures:
            soot_sig = self._extract_soot_signature(signature)
            if soot_sig and soot_sig in self._known_signatures:
                return True

            # Check if any known signature is contained in this signature (or vice versa)
            for known in self._known_signatures:
                if known in signature or signature in known:
                    return True
        elif not self._warned_empty_catalog:
            self._warned_empty_catalog = True
            logger.warning("Known signature set empty; using prefix fallback for API checks.")

        class_name = self._extract_class_from_signature(signature)
        if class_name and any(class_name.startswith(prefix) for prefix in self._known_prefixes):
            return True
        for prefix in self._known_prefixes:
            if prefix in signature:
                return True

        return False

    def _extract_soot_signature(self, signature: str) -> Optional[str]:
        """Extract soot-style signature from a statement or signature string."""
        match = re.search(r"<[^>]+>", signature)
        return match.group(0) if match else None

    def _extract_class_from_signature(self, signature: str) -> str:
        """Extract class name from a soot-style signature."""
        match = re.search(r"<([^:]+):", signature)
        return match.group(1) if match else ""

    def _get_api_interpretation(self, api_call: ApiCallExtraction) -> str:
        """Get interpretation for a known API call."""
        sig = api_call.signature.lower()

        # Common sensitive API interpretations
        if "mediarecorder" in sig and "setaudiosource" in sig:
            return "Configures audio recording from device microphone"
        if "mediarecorder" in sig and "start" in sig:
            return "Starts audio/video recording"
        if "camera" in sig and "takepicture" in sig:
            return "Captures photo from device camera"
        if "locationmanager" in sig and "requestlocationupdates" in sig:
            return "Requests continuous GPS location updates"
        if "telephonymanager" in sig and "getdeviceid" in sig:
            return "Retrieves unique device identifier (IMEI)"
        if "smsmanager" in sig and "sendtextmessage" in sig:
            return "Sends SMS text message"
        if "contentresolver" in sig and "query" in sig:
            return "Queries device content provider (contacts, calendar, etc.)"

        # Default interpretation
        return f"Calls sensitive API: {api_call.method_name} on {api_call.class_name}"

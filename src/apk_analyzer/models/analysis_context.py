"""Analysis context and sourced field models.

This module provides the AnalysisContext class for tracking analysis identifiers
and the SourcedField base class for tracking data provenance.

Fix 12: Run-scoped artifact paths
Fix 18: Source field for all structural fields
Fix 26: ArtifactStore as single path source - AnalysisContext holds IDs only
Fix 28: Terminology audit - analysis_id vs run_id
Fix 29: Remove path methods from AnalysisContext
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class AnalysisContext:
    """Holds analysis identifiers for logging and traceability.

    IMPORTANT: Does NOT define paths - all path access via ArtifactStore.

    Attributes:
        analysis_id: APK hash - identifies the APK being analyzed.
            Used for artifact directory structure (artifacts/{analysis_id}/...).
            Stable across runs of the same APK.
        run_id: Per-execution UUID - identifies a single analysis execution.
            Used for cache isolation and run-scoped subdirectory.
            Unique per run (even for same APK).

    Examples:
        >>> ctx = AnalysisContext(
        ...     analysis_id="a1b2c3d4e5f6",  # APK hash
        ...     run_id="r7h8i9j0",            # Per-run UUID
        ... )
        >>> # DO NOT use ctx for path construction
        >>> # Instead, use ArtifactStore.read_json(), write_json(), etc.

    Note:
        Per Fix 26 and Fix 29, this class has NO path methods.
        All file access should go through ArtifactStore:
        - store.read_json("graphs/slices/{seed_id}.json")
        - store.write_json("llm/tier1/{seed_id}.json", output)
    """

    analysis_id: str  # APK hash - for artifact directory structure
    run_id: str  # Per-run UUID - for cache isolation

    # NO path methods - removed per Fix 26, 29
    # NO artifact_base property
    # NO entrypoint_path() - use ArtifactStore.read_json()
    # NO slice_path() - use ArtifactStore.read_json()


@dataclass(kw_only=True)
class SourcedField:
    """Base class for fields that track their origin.

    Provides source tracking for structural fields to help downstream
    consumers understand the reliability and provenance of each value.

    Attributes:
        source: Where this data came from, e.g.,
            - "entrypoint_paths" (high trust)
            - "manifest" (medium trust)
            - "inferred" (lower trust)
            - "api_call" (inferred from API signature)
        source_confidence: How reliable is this source (0.0-1.0).

    Fix 18: Source field for all structural fields.
    """

    source: str
    source_confidence: float = 1.0

    def validate_source_confidence(self) -> None:
        """Validate that source_confidence is in valid range."""
        if not 0.0 <= self.source_confidence <= 1.0:
            raise ValueError(
                f"source_confidence must be 0.0-1.0, got {self.source_confidence}"
            )


@dataclass
class ComponentHints(SourcedField):
    """Trigger surface information extracted from various sources.

    Fix 23: NO permissions here - moved to ExtractedStructure.permissions.
    Fix 34: extract_trigger_surface() returns this without permissions.

    Attributes:
        component_name: Android component name (e.g., "AudioRecorderService").
        component_type: Type of component ("Activity", "Service", etc.).
        entrypoint_method: Method signature of the entry point.
        source: Where this info came from (inherited from SourcedField).
        source_confidence: Reliability of this source (inherited from SourcedField).
    """

    component_name: str
    component_type: str  # Activity, Service, BroadcastReceiver, ContentProvider, Unknown
    entrypoint_method: str

    # NO required_permissions - moved to ExtractedStructure.permissions per Fix 23

    @classmethod
    def unknown(cls, entrypoint_method: str = "") -> "ComponentHints":
        """Create ComponentHints for unknown components."""
        return cls(
            component_name="Unknown",
            component_type="Unknown",
            entrypoint_method=entrypoint_method,
            source="inferred",
            source_confidence=0.1,
        )


@dataclass
class TriggerSurface:
    """Final trigger surface representation for Tier1 output.

    Each field includes its source for downstream consumers to understand
    provenance and reliability.

    Fix 18: Source field for every structural value.
    """

    component_name: str
    component_name_source: str
    component_type: str
    component_type_source: str
    entrypoint_method: str
    entrypoint_method_source: str

    @classmethod
    def from_hints(cls, hints: ComponentHints) -> "TriggerSurface":
        """Create TriggerSurface from ComponentHints."""
        return cls(
            component_name=hints.component_name,
            component_name_source=hints.source,
            component_type=hints.component_type,
            component_type_source=hints.source,
            entrypoint_method=hints.entrypoint_method,
            entrypoint_method_source=hints.source,
        )

"""SliceProvider interface for verifier integration.

This module defines an abstract interface for accessing slice data,
enabling both new (Tier1ToolRegistry) and legacy (context bundle) paths.

Fix 10: Verifier interface - SliceProvider pattern.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from apk_analyzer.agents.tier1_tool_registry import Tier1ToolRegistry


class SliceProvider(ABC):
    """Abstract interface for accessing slice data.

    Fix 10: Refactor verifier to use SliceProvider interface.
    This enables both tool-registry-based and legacy bundle-based access.
    """

    @abstractmethod
    def get_unit(self, unit_id: str) -> Optional[Dict[str, Any]]:
        """Get a single unit by ID.

        Args:
            unit_id: The unit ID to retrieve.

        Returns:
            Unit data dict or None if not found.
        """
        pass

    @abstractmethod
    def verify_unit_exists(self, unit_id: str) -> bool:
        """Check if a unit exists.

        Args:
            unit_id: The unit ID to check.

        Returns:
            True if unit exists, False otherwise.
        """
        pass

    @abstractmethod
    def get_all_unit_ids(self) -> List[str]:
        """Get all unit IDs in this slice.

        Returns:
            List of all unit IDs.
        """
        pass


class ToolRegistrySliceProvider(SliceProvider):
    """Implements SliceProvider using Tier1ToolRegistry.

    Uses the tool registry to fetch slice data on-demand.
    """

    def __init__(self, seed_id: str, tool_registry: "Tier1ToolRegistry") -> None:
        self.seed_id = seed_id
        self.tool_registry = tool_registry
        self._slice_cache: Optional[Dict[str, Any]] = None

    def _load_slice(self) -> Dict[str, Any]:
        """Load and cache the slice data."""
        if self._slice_cache is None:
            self._slice_cache = self.tool_registry.read_cfg_slice(self.seed_id)
        return self._slice_cache

    def get_unit(self, unit_id: str) -> Optional[Dict[str, Any]]:
        """Get a unit by ID from the slice."""
        for unit in self._load_slice().get("units", []):
            if unit.get("unit_id") == unit_id:
                return unit
        return None

    def verify_unit_exists(self, unit_id: str) -> bool:
        """Check if a unit exists in the slice."""
        return self.get_unit(unit_id) is not None

    def get_all_unit_ids(self) -> List[str]:
        """Get all unit IDs from the slice."""
        return [u.get("unit_id") for u in self._load_slice().get("units", []) if u.get("unit_id")]


class BundleSliceProvider(SliceProvider):
    """Legacy: Implements SliceProvider using context bundle.

    For backward compatibility with existing code that uses full context bundles.
    """

    def __init__(self, context_bundle: Dict[str, Any]) -> None:
        self.sliced_cfg = context_bundle.get("sliced_cfg", {})
        self._units = self.sliced_cfg.get("units", [])

    def get_unit(self, unit_id: str) -> Optional[Dict[str, Any]]:
        """Get a unit by ID from the bundle."""
        for unit in self._units:
            if unit.get("unit_id") == unit_id:
                return unit
        return None

    def verify_unit_exists(self, unit_id: str) -> bool:
        """Check if a unit exists in the bundle."""
        return self.get_unit(unit_id) is not None

    def get_all_unit_ids(self) -> List[str]:
        """Get all unit IDs from the bundle."""
        return [u.get("unit_id") for u in self._units if u.get("unit_id")]

"""SliceProvider interface for verifier integration.

This module defines an abstract interface for accessing slice data.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class SliceProvider(ABC):
    """Abstract interface for accessing slice data."""

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


class BundleSliceProvider(SliceProvider):
    """Implements SliceProvider using context bundle."""

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

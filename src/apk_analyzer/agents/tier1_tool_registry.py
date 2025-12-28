"""Tier1 Tool Registry for LLM agent tools.

This module provides the tool registry for Tier1 phases, with
ArtifactStore-based path access and run-scoped caching.

Fix 5: Tool size caps and summary views.
Fix 8: Sanity check with CFG slice summary.
Fix 13: Per-run cache isolation with run_id.
Fix 21: Artifact path layout matches ArtifactStore.
Fix 26: ArtifactStore as single path source.
Fix 30: Cache key uses run_id (not analysis_id).
Improvement B: Pre-parsed CFG units.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, TYPE_CHECKING

from apk_analyzer.models.tier1_phases import ParsedUnit
from apk_analyzer.analyzers.deterministic_extractors import parse_unit

if TYPE_CHECKING:
    from apk_analyzer.utils.artifact_store import ArtifactStore


class Tier1ToolRegistry:
    """Tool registry for Tier1 LLM agents.

    All file access goes through self.store (ArtifactStore).
    Never construct paths manually.

    Fix 26: ArtifactStore as single source of truth.
    Fix 30: Cache key uses run_id for isolation.
    """

    # Fix 5: Size caps
    MAX_UNITS_PER_CALL = 20
    MAX_CHARS_PER_UNIT = 500

    def __init__(
        self,
        store: "ArtifactStore",
        jadx_dir: Path,
    ) -> None:
        """Initialize the tool registry.

        Args:
            store: ArtifactStore instance (single source of truth for paths).
            jadx_dir: Directory containing JADX decompiled sources.
        """
        self.store = store
        self.jadx_dir = jadx_dir
        self.run_id = store.run_id or ""  # For cache key only (Fix 30)
        self._cache: Dict[Tuple[str, ...], Any] = {}

    def _cached(
        self,
        seed_id: str,
        tool_name: str,
        args: Tuple[Any, ...],
        fetch_fn: Callable[[], Any],
    ) -> Any:
        """Cache scoped by run_id per Fix 30.

        Args:
            seed_id: The seed ID.
            tool_name: Name of the tool being called.
            args: Tool arguments (must be hashable).
            fetch_fn: Function to call on cache miss.

        Returns:
            Cached or freshly fetched result.
        """
        key = (self.run_id, seed_id, tool_name, args)
        if key not in self._cache:
            self._cache[key] = fetch_fn()
        return self._cache[key]

    def clear_cache(self) -> None:
        """Clear the cache between runs."""
        self._cache.clear()

    # =========================================================================
    # CFG Slice Tools
    # =========================================================================

    def read_cfg_slice(self, seed_id: str) -> Dict[str, Any]:
        """Read a CFG slice for a seed.

        Fix 26: Always use store.read_json(), never manual paths.

        Args:
            seed_id: The seed ID.

        Returns:
            CFG slice data dict.
        """
        return self._cached(
            seed_id,
            "read_cfg_slice",
            (),
            lambda: self.store.read_json(f"graphs/slices/{seed_id}.json"),
        )

    def read_cfg_slice_summary(self, seed_id: str) -> Dict[str, Any]:
        """Summary view: counts and key info only, not full units.

        Fix 5: Size caps and summary mode.
        Fix 8: For sanity check comparing pre_extracted vs CFG counts.
        Fix 25: Use parsed operation counts.

        Args:
            seed_id: The seed ID.

        Returns:
            Summary dict with counts and limited unit IDs.
        """
        full_slice = self.read_cfg_slice(seed_id)
        units = full_slice.get("units", [])

        # Parse each unit to get accurate counts (Improvement B)
        parsed_units = [parse_unit(u) for u in units]

        return {
            "seed_id": seed_id,
            "unit_count": len(units),
            # Use parsed op field, not string search (Fix 25)
            "parsed_invoke_count": sum(1 for pu in parsed_units if pu.op == "invoke"),
            "parsed_branch_count": sum(1 for pu in parsed_units if pu.op == "if"),
            "parsed_assign_count": sum(1 for pu in parsed_units if pu.op == "assign"),
            # Keep legacy heuristic for comparison
            "callsite_count_heuristic": sum(
                1 for u in units if "invoke" in u.get("stmt", "").lower()
            ),
            "unit_ids": [u.get("unit_id") for u in units][: 50],  # First 50 IDs only
        }

    def read_cfg_units(
        self,
        seed_id: str,
        unit_ids: List[str],
        summary_mode: bool = False,
    ) -> List[Dict[str, Any]]:
        """Fetch specific units with size caps.

        Fix 5: MAX_UNITS_PER_CALL and MAX_CHARS_PER_UNIT limits.

        Args:
            seed_id: The seed ID.
            unit_ids: List of unit IDs to fetch.
            summary_mode: If True, return minimal info only.

        Returns:
            List of unit data dicts.
        """
        slice_data = self.read_cfg_slice(seed_id)
        all_units = slice_data.get("units", [])

        # Find requested units (limited by MAX_UNITS_PER_CALL)
        requested_ids = set(unit_ids[: self.MAX_UNITS_PER_CALL])
        units = [u for u in all_units if u.get("unit_id") in requested_ids]

        if summary_mode:
            # Return minimal info for context, not full statements
            return [
                {
                    "unit_id": u.get("unit_id"),
                    "type": u.get("type"),
                    "signature": self._extract_signature(u),
                }
                for u in units
            ]

        # Truncate long statements (Fix 5)
        for u in units:
            stmt = u.get("stmt", "")
            if len(stmt) > self.MAX_CHARS_PER_UNIT:
                u["stmt"] = stmt[: self.MAX_CHARS_PER_UNIT] + "... [truncated]"

        return units

    def read_cfg_units_parsed(
        self,
        seed_id: str,
        unit_ids: List[str],
    ) -> List[ParsedUnit]:
        """Return pre-parsed units.

        Improvement B: Pre-parsed fields so 1B doesn't parse Jimple text.

        Args:
            seed_id: The seed ID.
            unit_ids: List of unit IDs to fetch.

        Returns:
            List of ParsedUnit objects.
        """
        raw_units = self.read_cfg_units(seed_id, unit_ids)
        return [parse_unit(u) for u in raw_units]

    def _extract_signature(self, unit: Dict[str, Any]) -> Optional[str]:
        """Extract method signature from a unit statement."""
        stmt = unit.get("stmt", "")
        match = re.search(r"<([^>]+)>", stmt)
        return match.group(1) if match else None

    # =========================================================================
    # Entrypoint Tools
    # =========================================================================

    def read_entrypoint_paths(self, seed_id: str) -> Dict[str, Any]:
        """Read entrypoint paths for a seed.

        Fix 26: Always use store.read_json().

        Args:
            seed_id: The seed ID.

        Returns:
            Entrypoint paths data dict.
        """
        return self._cached(
            seed_id,
            "read_entrypoint_paths",
            (),
            lambda: self.store.read_json(f"graphs/entrypoint_paths/{seed_id}.json"),
        )

    def read_entrypoint_paths_aggregated(self) -> Dict[str, Any]:
        """Read aggregated entrypoint paths.

        Returns:
            Aggregated entrypoint paths data dict.
        """
        return self._cached(
            "__aggregated__",
            "read_entrypoint_paths_aggregated",
            (),
            lambda: self.store.read_json("graphs/entrypoint_paths.json"),
        )

    # =========================================================================
    # JADX Source Tools
    # =========================================================================

    def read_java_source(self, method_sig: str) -> Optional[str]:
        """Read Java source from JADX decompiled output.

        Args:
            method_sig: Method signature like "com.example.MyClass: void myMethod()".

        Returns:
            Java source code or None if not found/failed.
        """
        # Parse class name from signature
        if ":" in method_sig:
            class_name = method_sig.split(":")[0].strip("<>").strip()
        else:
            class_name = method_sig

        # Convert class name to file path
        class_path = class_name.replace(".", "/") + ".java"
        source_file = self.jadx_dir / "sources" / class_path

        try:
            if source_file.exists():
                content = source_file.read_text(encoding="utf-8", errors="replace")
                # Truncate if too long
                if len(content) > 10000:
                    content = content[:10000] + "\n... [truncated]"
                return content
        except Exception:
            pass

        return None

    def search_java_source(
        self,
        class_name: str,
        pattern: str,
    ) -> List[Dict[str, Any]]:
        """Search Java source for a pattern.

        Args:
            class_name: Class name to search in.
            pattern: Regex pattern to search for.

        Returns:
            List of matches with line numbers.
        """
        source = self.read_java_source(class_name)
        if not source:
            return []

        matches = []
        try:
            regex = re.compile(pattern)
            for i, line in enumerate(source.split("\n"), 1):
                if regex.search(line):
                    matches.append({"line": i, "content": line.strip()})
                    if len(matches) >= 20:  # Limit matches
                        break
        except re.error:
            pass

        return matches

    # =========================================================================
    # Output Tools
    # =========================================================================

    def write_tier1_output(
        self,
        seed_id: str,
        output: Dict[str, Any],
    ) -> Path:
        """Write Tier1 output to artifact store.

        Fix 26: Always use store.write_json().

        Args:
            seed_id: The seed ID.
            output: Tier1 output data.

        Returns:
            Path where output was written.
        """
        return self.store.write_json(f"llm/tier1/{seed_id}.json", output)

    def read_manifest(self) -> Dict[str, Any]:
        """Read parsed manifest data.

        Returns:
            Manifest data dict.
        """
        return self._cached(
            "__manifest__",
            "read_manifest",
            (),
            lambda: self.store.read_json("static/manifest.json"),
        )

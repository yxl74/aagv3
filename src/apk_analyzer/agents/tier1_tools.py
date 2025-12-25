from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from apk_analyzer.analyzers.jadx_extractors import extract_method_source
from apk_analyzer.analyzers.local_query import search_source_code
from apk_analyzer.utils.artifact_store import ArtifactStore


class Tier1ToolRunner:
    """
    Tool runner for Tier1 agent - provides JADX source code access.

    Used in repair passes when the initial Tier1 analysis fails verification
    or has low confidence. Allows the LLM to query decompiled Java source
    to better understand bytecode semantics.
    """

    def __init__(
        self,
        jadx_root: Optional[Path] = None,
        artifact_store: Optional[ArtifactStore] = None,
    ) -> None:
        self.jadx_root = jadx_root
        self.artifact_store = artifact_store
        self._call_count = 0

    @staticmethod
    def schema() -> Dict[str, Any]:
        """Return tool schema for LLM prompt."""
        return {
            "tools": [
                {
                    "name": "read_java_source",
                    "description": (
                        "Read decompiled Java source for a method. "
                        "Use when Jimple bytecode is unclear (e.g., numeric constants, complex control flow)."
                    ),
                    "args": {
                        "method_signature": "string - Soot method signature like '<com.pkg.Class: void method(int)>'"
                    },
                },
                {
                    "name": "search_java_source",
                    "description": (
                        "Search decompiled code for a pattern. "
                        "Use to find related code, string usages, or class definitions."
                    ),
                    "args": {
                        "query": "string - Search pattern (class name, method name, string literal)",
                        "limit": "int (optional, default 5) - Max results",
                    },
                },
            ]
        }

    def run(self, requests: List[Dict[str, Any]], seed_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Execute tool requests and return results.

        Args:
            requests: List of tool requests, each with 'tool' and 'args' keys
            seed_id: Optional seed ID for artifact logging

        Returns:
            List of results, each with 'tool', 'ok', and 'result' or 'error' keys
        """
        results: List[Dict[str, Any]] = []
        for req in requests:
            tool = req.get("tool", "")
            args = req.get("args", {})
            if tool == "read_java_source":
                results.append(self._read_java_source(tool, args))
            elif tool == "search_java_source":
                results.append(self._search_java_source(tool, args))
            else:
                results.append({"tool": tool, "ok": False, "error": "unknown_tool"})

        # Log to artifacts for reproducibility
        if self.artifact_store and seed_id:
            self._call_count += 1
            self.artifact_store.ensure_dir("llm/tier1_tools")
            self.artifact_store.write_json(
                f"llm/tier1_tools/{seed_id}_{self._call_count}.json",
                {"requests": requests, "results": results},
            )

        return results

    def _read_java_source(self, tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Extract method source from JADX output."""
        method_sig = args.get("method_signature", "")
        if not method_sig:
            return {"tool": tool, "ok": False, "error": "method_signature_required"}

        if not self.jadx_root:
            return {"tool": tool, "ok": False, "error": "jadx_not_available"}

        source = extract_method_source(
            self.jadx_root,
            method_sig,
            max_lines=100,
            max_chars=5000,
        )

        if source is None:
            return {"tool": tool, "ok": False, "error": "method_not_found"}

        return {"tool": tool, "ok": True, "result": source}

    def _search_java_source(self, tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Search JADX source files for a pattern."""
        query = args.get("query", "")
        if not query:
            return {"tool": tool, "ok": False, "error": "query_required"}

        if not self.jadx_root:
            return {"tool": tool, "ok": False, "error": "jadx_not_available"}

        limit = args.get("limit", 5)
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 5
        limit = min(limit, 10)  # Cap at 10 results

        # Search in sources subdirectory
        sources_dir = self.jadx_root / "sources"
        if not sources_dir.exists():
            sources_dir = self.jadx_root

        hits = search_source_code(
            sources_dir,
            query,
            limit=limit,
            extensions={".java"},
        )

        return {"tool": tool, "ok": True, "result": hits}

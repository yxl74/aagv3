from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional


class ReconToolRunner:
    def __init__(
        self,
        sensitive_hits: Dict[str, Any],
        hit_groups: Optional[Dict[str, Any]] = None,
        code_blocks: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self.sensitive_hits = sensitive_hits
        self.hits = list(sensitive_hits.get("hits", []) or [])
        self.hits_by_id = {hit.get("hit_id"): hit for hit in self.hits if hit.get("hit_id")}
        self.summary = sensitive_hits.get("summary", {}) or {}
        self.callgraph_summary = sensitive_hits.get("callgraph_summary", {}) or {}
        self.groups = list((hit_groups or {}).get("groups", []) or [])
        self.groups_by_id = {
            group.get("group_id"): group
            for group in self.groups
            if group.get("group_id")
        }
        self.blocks = code_blocks or []
        self.blocks_by_id = {
            block.get("block_id"): block
            for block in self.blocks
            if block.get("block_id")
        }

    @staticmethod
    def schema() -> Dict[str, Any]:
        return {
            "tools": [
                {"name": "get_block", "args": {"block_id": "string"}},
                {"name": "list_blocks", "args": {"limit": "int (optional)"}},
                {"name": "get_hit", "args": {"hit_id": "string"}},
                {"name": "list_hits", "args": {"category_id": "string (optional)", "limit": "int (optional)"}},
                {"name": "get_group", "args": {"group_id": "string"}},
                {"name": "list_groups", "args": {"category_id": "string (optional)", "limit": "int (optional)"}},
                {"name": "get_summary", "args": {}},
                {"name": "get_entrypoints", "args": {}},
            ]
        }

    def run(self, requests: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for request in requests:
            tool = str(request.get("tool", ""))
            args = request.get("args") or {}
            if tool == "get_block":
                results.append(self._get_block(tool, args))
            elif tool == "list_blocks":
                results.append(self._list_blocks(tool, args))
            elif tool == "get_hit":
                results.append(self._get_hit(tool, args))
            elif tool == "list_hits":
                results.append(self._list_hits(tool, args))
            elif tool == "get_group":
                results.append(self._get_group(tool, args))
            elif tool == "list_groups":
                results.append(self._list_groups(tool, args))
            elif tool == "get_summary":
                results.append({"tool": tool, "ok": True, "result": self.summary})
            elif tool == "get_entrypoints":
                results.append({"tool": tool, "ok": True, "result": self.callgraph_summary.get("entrypoints", [])})
            else:
                results.append({"tool": tool, "ok": False, "error": "unknown_tool"})
        return results

    def _get_block(self, tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        block_id = args.get("block_id")
        if not block_id:
            return {"tool": tool, "ok": False, "error": "block_id_required"}
        block = self.blocks_by_id.get(block_id)
        if not block:
            return {"tool": tool, "ok": False, "error": "block_not_found"}
        return {"tool": tool, "ok": True, "result": block}

    def _list_blocks(self, tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        limit = args.get("limit", 50)
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 50
        results = []
        for block in self.blocks[:limit]:
            threat_meta = block.get("threat_meta") or {}
            results.append({
                "block_id": block.get("block_id"),
                "caller_class": block.get("caller_class"),
                "component_type": block.get("component_type"),
                "categories": block.get("categories", []),
                "string_categories": block.get("string_categories", []),
                "priority_max": block.get("priority_max"),
                "effective_priority": block.get("effective_priority"),
                "threat_score": block.get("threat_score"),
                "threat_score_raw": block.get("threat_score_raw"),
                "pattern_count": threat_meta.get("pattern_count", 0),
                "hit_count": block.get("hit_count"),
                "group_count": block.get("group_count"),
                "methods": block.get("methods", []),
                "investigability_score": block.get("investigability_score"),
                "has_reflection": block.get("has_reflection"),
            })
        return {"tool": tool, "ok": True, "result": results}

    def _get_hit(self, tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        hit_id = args.get("hit_id")
        if not hit_id:
            return {"tool": tool, "ok": False, "error": "hit_id_required"}
        hit = self.hits_by_id.get(hit_id)
        if not hit:
            return {"tool": tool, "ok": False, "error": "hit_not_found"}
        return {"tool": tool, "ok": True, "result": hit}

    def _list_hits(self, tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        category_id = args.get("category_id")
        limit = args.get("limit", 20)
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 20
        results = []
        for hit in self.hits:
            if category_id and hit.get("category_id") != category_id:
                continue
            results.append({
                "hit_id": hit.get("hit_id"),
                "category_id": hit.get("category_id"),
                "priority": hit.get("priority"),
                "caller": hit.get("caller"),
                "signature": hit.get("signature"),
            })
            if len(results) >= limit:
                break
        return {"tool": tool, "ok": True, "result": results}

    def _get_group(self, tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        group_id = args.get("group_id")
        if not group_id:
            return {"tool": tool, "ok": False, "error": "group_id_required"}
        group = self.groups_by_id.get(group_id)
        if not group:
            return {"tool": tool, "ok": False, "error": "group_not_found"}
        return {"tool": tool, "ok": True, "result": group}

    def _list_groups(self, tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        category_id = args.get("category_id")
        limit = args.get("limit", 20)
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 20
        results = []
        for group in self.groups:
            categories = group.get("categories") or []
            string_categories = group.get("string_categories") or []
            if category_id and category_id not in set(categories) | set(string_categories):
                continue
            threat_meta = group.get("threat_meta") or {}
            results.append({
                "group_id": group.get("group_id"),
                "caller_method": group.get("caller_method"),
                "categories": categories,
                "string_categories": string_categories,
                "priority_max": group.get("priority_max"),
                "effective_priority": group.get("effective_priority"),
                "threat_score": group.get("threat_score"),
                "threat_score_raw": group.get("threat_score_raw"),
                "pattern_count": threat_meta.get("pattern_count", 0),
                "hit_count": group.get("hit_count"),
            })
            if len(results) >= limit:
                break
        return {"tool": tool, "ok": True, "result": results}

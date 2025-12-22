from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional


class ReconToolRunner:
    def __init__(self, sensitive_hits: Dict[str, Any]) -> None:
        self.sensitive_hits = sensitive_hits
        self.hits = list(sensitive_hits.get("hits", []) or [])
        self.hits_by_id = {hit.get("hit_id"): hit for hit in self.hits if hit.get("hit_id")}
        self.summary = sensitive_hits.get("summary", {}) or {}
        self.callgraph_summary = sensitive_hits.get("callgraph_summary", {}) or {}

    @staticmethod
    def schema() -> Dict[str, Any]:
        return {
            "tools": [
                {"name": "get_hit", "args": {"hit_id": "string"}},
                {"name": "list_hits", "args": {"category_id": "string (optional)", "limit": "int (optional)"}},
                {"name": "get_summary", "args": {}},
                {"name": "get_entrypoints", "args": {}},
            ]
        }

    def run(self, requests: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for request in requests:
            tool = str(request.get("tool", ""))
            args = request.get("args") or {}
            if tool == "get_hit":
                results.append(self._get_hit(tool, args))
            elif tool == "list_hits":
                results.append(self._list_hits(tool, args))
            elif tool == "get_summary":
                results.append({"tool": tool, "ok": True, "result": self.summary})
            elif tool == "get_entrypoints":
                results.append({"tool": tool, "ok": True, "result": self.callgraph_summary.get("entrypoints", [])})
            else:
                results.append({"tool": tool, "ok": False, "error": "unknown_tool"})
        return results

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

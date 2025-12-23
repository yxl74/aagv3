from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from apk_analyzer.utils.artifact_store import ArtifactStore


class EventLogger:
    def __init__(
        self,
        store: ArtifactStore,
        run_id: Optional[str] = None,
        enabled: bool = True,
    ) -> None:
        self.store = store
        self.enabled = enabled
        self.run_id = run_id
        self.path = self._resolve_path()

    def set_run_id(self, run_id: str) -> None:
        self.run_id = run_id
        self.path = self._resolve_path()

    def _resolve_path(self) -> Path:
        if self.run_id:
            path = self.store.path("observability", "runs", f"{self.run_id}.jsonl")
        else:
            path = self.store.path("observability/run.jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def log(self, event_type: str, **fields: Any) -> None:
        if not self.enabled:
            return
        event: Dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event_type": event_type,
            "analysis_id": self.store.analysis_id,
        }
        if self.run_id:
            event["run_id"] = self.run_id
        event.update(fields)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=True, default=str))
            handle.write("\n")

    def stage_start(self, stage: str, **fields: Any) -> None:
        self.log("stage.start", stage=stage, **fields)

    def stage_end(self, stage: str, status: str = "ok", **fields: Any) -> None:
        self.log("stage.end", stage=stage, status=status, **fields)

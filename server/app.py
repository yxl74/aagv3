from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates


ARTIFACTS_DIR = Path(os.environ.get("ARTIFACTS_DIR", "/workspace/artifacts"))
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app = FastAPI(title="APK Analysis Observability")


def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        if ts.endswith("Z"):
            ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _read_events(path: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    if not path.exists():
        return events
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def _list_runs() -> List[Dict[str, Any]]:
    runs = []
    if not ARTIFACTS_DIR.exists():
        return runs
    for run_dir in sorted(ARTIFACTS_DIR.iterdir()):
        if not run_dir.is_dir():
            continue
        events_path = run_dir / "observability" / "run.jsonl"
        if not events_path.exists():
            continue
        events = _read_events(events_path)
        start = next((e for e in events if e.get("event_type") == "run.start"), None)
        end = next((e for e in reversed(events) if e.get("event_type") == "run.end"), None)
        runs.append({
            "analysis_id": run_dir.name,
            "mode": (start or {}).get("mode"),
            "start_ts": (start or {}).get("ts"),
            "end_status": (end or {}).get("status"),
            "event_count": len(events),
        })
    return runs


def _stage_summary(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    stages: Dict[str, Dict[str, Any]] = {}
    for event in events:
        stage = event.get("stage")
        if not stage:
            continue
        if stage not in stages:
            stages[stage] = {"stage": stage}
        if event.get("event_type") == "stage.start":
            stages[stage]["start_ts"] = event.get("ts")
        if event.get("event_type") == "stage.end":
            stages[stage]["end_ts"] = event.get("ts")
            stages[stage]["status"] = event.get("status", "ok")
    results = []
    for stage, data in stages.items():
        start = _parse_ts(data.get("start_ts"))
        end = _parse_ts(data.get("end_ts"))
        duration = None
        if start and end:
            duration = (end - start).total_seconds()
        results.append({
            **data,
            "duration_sec": duration,
        })
    return sorted(results, key=lambda x: x.get("start_ts") or "")


def _is_api_tool_event(event_type: str) -> bool:
    return event_type.startswith(("api.", "tool.", "flowdroid."))


def _format_api_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    formatted = []
    for event in events:
        event_type = event.get("event_type", "")
        if not event_type or not _is_api_tool_event(event_type):
            continue
        extra = {
            k: v for k, v in event.items()
            if k not in {
                "ts",
                "event_type",
                "analysis_id",
                "run_id",
                "http_method",
                "path",
                "status_code",
                "status",
                "ref",
                "tool",
            }
        }
        formatted.append({
            "ts": event.get("ts"),
            "event_type": event_type,
            "method": event.get("http_method"),
            "path": event.get("path") or event.get("tool"),
            "status": event.get("status_code") or event.get("status"),
            "ref": event.get("ref"),
            "extra": json.dumps(extra, indent=2, ensure_ascii=True) if extra else "",
        })
    return formatted


def _safe_artifact_path(analysis_id: str, rel_path: str) -> Path:
    base = (ARTIFACTS_DIR / analysis_id).resolve()
    candidate = (base / rel_path).resolve()
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid artifact path") from exc
    return candidate


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    runs = _list_runs()
    return templates.TemplateResponse("runs.html", {"request": request, "runs": runs})


@app.get("/runs", response_class=HTMLResponse)
def runs_page(request: Request):
    runs = _list_runs()
    return templates.TemplateResponse("runs.html", {"request": request, "runs": runs})


@app.get("/api/runs")
def runs_api():
    return _list_runs()


@app.get("/runs/{analysis_id}", response_class=HTMLResponse)
def run_detail(request: Request, analysis_id: str):
    events_path = ARTIFACTS_DIR / analysis_id / "observability" / "run.jsonl"
    if not events_path.exists():
        raise HTTPException(status_code=404, detail="Run not found")
    events = _read_events(events_path)
    stages = _stage_summary(events)
    seeding_stats = next((e for e in events if e.get("stage") == "seeding" and e.get("event_type") == "stage.end"), None)
    sensitive_api = next((e for e in events if e.get("stage") == "sensitive_api" and e.get("event_type") == "stage.end"), None)
    recon = next((e for e in events if e.get("stage") == "recon" and e.get("event_type") == "stage.end"), None)
    graphs = next((e for e in events if e.get("stage") == "graphs" and e.get("event_type") == "stage.end"), None)
    bundles = next((e for e in events if e.get("stage") == "context_bundles" and e.get("event_type") == "stage.end"), None)
    flowdroid = next((e for e in events if e.get("event_type") in {"flowdroid.summary", "tool.flowdroid"}), None)
    llm_events = [e for e in events if e.get("event_type", "").startswith("llm.")]
    api_events = _format_api_events(events)
    return templates.TemplateResponse(
        "run_detail.html",
        {
            "request": request,
            "analysis_id": analysis_id,
            "events": events,
            "stages": stages,
            "seeding": seeding_stats,
            "sensitive_api": sensitive_api,
            "recon": recon,
            "graphs": graphs,
            "bundles": bundles,
            "flowdroid": flowdroid,
            "llm_events": llm_events,
            "api_events": api_events,
        },
    )


@app.get("/api/runs/{analysis_id}")
def run_api(analysis_id: str):
    events_path = ARTIFACTS_DIR / analysis_id / "observability" / "run.jsonl"
    if not events_path.exists():
        raise HTTPException(status_code=404, detail="Run not found")
    return _read_events(events_path)


@app.get("/runs/{analysis_id}/artifact/{rel_path:path}")
def artifact(analysis_id: str, rel_path: str):
    path = _safe_artifact_path(analysis_id, rel_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Artifact not found")
    if path.suffix in {".json", ".txt", ".md", ".log", ".xml"}:
        return PlainTextResponse(path.read_text(encoding="utf-8", errors="ignore"))
    return FileResponse(str(path))

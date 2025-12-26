from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from apk_analyzer.analyzers.static_extractors import extract_manifest
from apk_analyzer.utils.artifact_store import ArtifactStore


def _resolve_artifacts_dir() -> Path:
    return Path(os.environ.get("ARTIFACTS_DIR", "/workspace/artifacts"))


ARTIFACTS_DIR = _resolve_artifacts_dir()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app = FastAPI(title="APK Analysis Observability")
REPO_ROOT = Path(__file__).resolve().parents[1]
_RUN_ID_SAFE_RE = re.compile(r"[^a-zA-Z0-9._-]+")


class StartRunRequest(BaseModel):
    apk_path: str = Field(..., description="Filesystem path to the APK")
    mode: str = Field("apk-only", description="Analysis mode")
    knox_apk_id: Optional[str] = Field(None, description="Knox APK ID for combined mode")
    settings_path: Optional[str] = Field(None, description="Settings YAML path")


def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        if ts.endswith("Z"):
            ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _sanitize_run_id_part(value: str, max_len: int = 60) -> str:
    value = (value or "").strip()
    if not value:
        return "unknown"
    value = _RUN_ID_SAFE_RE.sub("_", value).strip("._-")
    if not value:
        return "unknown"
    return value[:max_len]


def _friendly_run_id(apk_path: Path) -> str:
    package_name = None
    try:
        manifest = extract_manifest(apk_path)
        if isinstance(manifest, dict):
            package_name = manifest.get("package_name")
    except Exception:
        package_name = None

    base = _sanitize_run_id_part(str(package_name) if package_name else apk_path.stem)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    suffix = uuid.uuid4().hex[:6]
    return f"{base}_{ts}_{suffix}"


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


def _list_run_dirs(analysis_dir: Path) -> List[Path]:
    runs_dir = analysis_dir / "runs"
    if not runs_dir.exists():
        return []
    return [p for p in sorted(runs_dir.iterdir()) if p.is_dir()]


def _summarize_run_dir(analysis_id: str, run_dir: Path) -> Dict[str, Any]:
    ts = None
    report_path = run_dir / "report" / "threat_report.json"
    target = report_path if report_path.exists() else run_dir
    try:
        ts = datetime.fromtimestamp(target.stat().st_mtime, tz=timezone.utc)
    except OSError:
        ts = None
    return {
        "analysis_id": analysis_id,
        "run_id": run_dir.name,
        "mode": None,
        "start_ts": ts.isoformat().replace("+00:00", "Z") if ts else None,
        "end_status": None,
        "event_count": 0,
        "events_path": None,
    }


def _list_runs() -> List[Dict[str, Any]]:
    runs = []
    if not ARTIFACTS_DIR.exists():
        return runs
    for analysis_dir in sorted(ARTIFACTS_DIR.iterdir()):
        if not analysis_dir.is_dir():
            continue
        seen_run_ids = set()
        runs_dir = analysis_dir / "observability" / "runs"
        if runs_dir.exists():
            for events_path in sorted(runs_dir.glob("*.jsonl")):
                run = _summarize_run(analysis_dir.name, events_path)
                if run:
                    runs.append(run)
                    if run.get("run_id"):
                        seen_run_ids.add(run["run_id"])
        legacy_path = analysis_dir / "observability" / "run.jsonl"
        if legacy_path.exists():
            run = _summarize_run(analysis_dir.name, legacy_path)
            if run:
                runs.append(run)
        for run_dir in _list_run_dirs(analysis_dir):
            if run_dir.name in seen_run_ids:
                continue
            runs.append(_summarize_run_dir(analysis_dir.name, run_dir))
    return runs


def _summarize_run(analysis_id: str, events_path: Path) -> Dict[str, Any] | None:
    events = _read_events(events_path)
    if not events:
        return None
    start = next((e for e in events if e.get("event_type") == "run.start"), None)
    end = next((e for e in reversed(events) if e.get("event_type") == "run.end"), None)
    run_id = (start or {}).get("run_id") or _run_id_from_path(events_path)
    return {
        "analysis_id": analysis_id,
        "run_id": run_id,
        "mode": (start or {}).get("mode"),
        "start_ts": (start or {}).get("ts"),
        "end_status": (end or {}).get("status"),
        "event_count": len(events),
        "events_path": str(events_path),
    }


def _run_id_from_path(events_path: Path) -> str | None:
    if events_path.name == "run.jsonl":
        return None
    return events_path.stem


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


def _format_execution_flow(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    enriched: List[Dict[str, Any]] = []
    for idx, event in enumerate(events):
        ts = event.get("ts")
        parsed = _parse_ts(ts)
        sort_key = parsed.timestamp() if parsed else float(idx)
        event_type = event.get("event_type", "")
        stage = event.get("stage")
        is_stage = event_type.startswith("stage.") or event_type in {"run.start", "run.end"}
        level = _event_level(event)
        summary = _event_summary(event)
        extra = {
            k: v for k, v in event.items()
            if k not in {
                "ts",
                "event_type",
                "analysis_id",
                "run_id",
                "stage",
                "ref",
            }
        }
        enriched.append({
            "ts": ts,
            "event_type": event_type,
            "stage": stage,
            "summary": summary,
            "ref": event.get("ref"),
            "details": json.dumps(extra, indent=2, ensure_ascii=True) if extra else "",
            "is_stage": is_stage,
            "level": level,
            "sort_key": sort_key,
        })
    return sorted(enriched, key=lambda item: item["sort_key"])


def _event_level(event: Dict[str, Any]) -> str:
    status = event.get("status") or event.get("status_code")
    if event.get("error"):
        return "error"
    if isinstance(status, str) and status.lower() in {"error", "failed"}:
        return "error"
    if isinstance(status, int) and status >= 400:
        return "error"
    return "info"


def _event_summary(event: Dict[str, Any]) -> str:
    event_type = event.get("event_type", "")
    stage = event.get("stage")
    if event_type == "run.start":
        return f"run.start mode={event.get('mode') or '-'}"
    if event_type == "run.end":
        return f"run.end status={event.get('status') or '-'}"
    if event_type.startswith("stage."):
        status = event.get("status")
        if status:
            return f"{stage or '-'} status={status}"
        return f"{stage or '-'}"
    if event_type.startswith("llm."):
        step = event.get("llm_step") or "-"
        seed = event.get("seed_id") or "-"
        if event_type == "llm.fallback":
            return f"llm.fallback step={step} seed={seed} reason={event.get('error_type') or '-'}"
        if event_type == "llm.parse_error":
            return f"llm.parse_error step={step} seed={seed} type={event.get('error_type') or '-'}"
        return f"{event_type} step={step} seed={seed}"
    if event_type.startswith("api."):
        return f"{event.get('http_method') or '-'} {event.get('path') or '-'}"
    if event_type.startswith("tool."):
        return f"{event.get('tool') or event_type}"
    return event_type or "-"


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
    return templates.TemplateResponse("runs.html", {"request": request, "runs": runs, "artifacts_dir": str(ARTIFACTS_DIR)})


@app.get("/runs", response_class=HTMLResponse)
def runs_page(request: Request):
    runs = _list_runs()
    return templates.TemplateResponse("runs.html", {"request": request, "runs": runs, "artifacts_dir": str(ARTIFACTS_DIR)})


@app.get("/api/runs")
def runs_api():
    return _list_runs()


@app.get("/runs/{analysis_id}", response_class=HTMLResponse)
def run_detail_latest(request: Request, analysis_id: str):
    events_path, run_id = _latest_run_entry(analysis_id)
    if not events_path and not run_id:
        raise HTTPException(status_code=404, detail="Run not found")
    return _render_run_detail(request, analysis_id, events_path, run_id_override=run_id)


@app.get("/runs/{analysis_id}/{run_id}", response_class=HTMLResponse)
def run_detail(request: Request, analysis_id: str, run_id: str):
    events_path = _resolve_run_path(analysis_id, run_id)
    if not events_path:
        run_dir = ARTIFACTS_DIR / analysis_id / "runs" / run_id
        if not run_dir.exists():
            raise HTTPException(status_code=404, detail="Run not found")
    return _render_run_detail(request, analysis_id, events_path, run_id_override=run_id)


def _render_run_detail(
    request: Request,
    analysis_id: str,
    events_path: Path | None,
    run_id_override: str | None = None,
):
    events = _read_events(events_path) if events_path else []
    stages = _stage_summary(events)
    seeding_stats = next((e for e in events if e.get("stage") == "seeding" and e.get("event_type") == "stage.end"), None)
    sensitive_api = next((e for e in events if e.get("stage") == "sensitive_api" and e.get("event_type") == "stage.end"), None)
    recon = next((e for e in events if e.get("stage") == "recon" and e.get("event_type") == "stage.end"), None)
    graphs = next((e for e in events if e.get("stage") == "graphs" and e.get("event_type") == "stage.end"), None)
    bundles = next((e for e in events if e.get("stage") == "context_bundles" and e.get("event_type") == "stage.end"), None)
    flowdroid = next((e for e in events if e.get("event_type") in {"flowdroid.summary", "tool.flowdroid"}), None)
    llm_events = [e for e in events if e.get("event_type", "").startswith("llm.")]
    api_events = _format_api_events(events)
    execution_flow = _format_execution_flow(events)
    run_id = run_id_override or next((e.get("run_id") for e in events if e.get("run_id")), None)
    if not run_id and events_path:
        run_id = _run_id_from_path(events_path)

    # Load threat report if available
    threat_report = None
    # Try to find report in run directory
    report_candidates = []
    if events_path:
        report_candidates.append(events_path.parent / "report" / "threat_report.json")
    if run_id:
        report_candidates.append(ARTIFACTS_DIR / analysis_id / "runs" / run_id / "report" / "threat_report.json")
    for report_path in report_candidates:
        if report_path.exists():
            try:
                threat_report = json.loads(report_path.read_text())
                break
            except Exception:
                pass

    return templates.TemplateResponse(
        "run_detail.html",
        {
            "request": request,
            "analysis_id": analysis_id,
            "run_id": run_id,
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
            "execution_flow": execution_flow,
            "artifacts_dir": str(ARTIFACTS_DIR),
            "threat_report": threat_report,
        },
    )


@app.get("/api/runs/list/stream")
def stream_run_list():
    """Stream run list updates via SSE."""
    async def _run_list_stream():
        last_state: Dict[str, Any] = {}
        while True:
            runs = _list_runs()
            current_state = {r.get("run_id") or r.get("analysis_id"): r for r in runs}
            if current_state != last_state:
                yield f"event: runs\n"
                yield f"data: {json.dumps(runs, ensure_ascii=True)}\n\n"
                last_state = current_state
            yield ": heartbeat\n\n"
            await asyncio.sleep(2)
    return StreamingResponse(
        _run_list_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.get("/api/runs/stream/{analysis_id}")
def stream_run(analysis_id: str, run_id: str | None = None, from_start: bool = False):
    return StreamingResponse(
        _event_stream(analysis_id, run_id, from_start=from_start),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.get("/api/runs/{analysis_id}")
def run_api(analysis_id: str):
    events_path, run_id = _latest_run_entry(analysis_id)
    if not events_path and not run_id:
        raise HTTPException(status_code=404, detail="Run not found")
    if not events_path:
        return []
    return _read_events(events_path)


@app.get("/api/runs/{analysis_id}/{run_id}")
def run_api_by_id(analysis_id: str, run_id: str):
    events_path = _resolve_run_path(analysis_id, run_id)
    if not events_path:
        run_dir = ARTIFACTS_DIR / analysis_id / "runs" / run_id
        if not run_dir.exists():
            raise HTTPException(status_code=404, detail="Run not found")
        return []
    return _read_events(events_path)


def _resolve_run_path(analysis_id: str, run_id: str) -> Path | None:
    runs_dir = ARTIFACTS_DIR / analysis_id / "observability" / "runs"
    candidate = runs_dir / f"{run_id}.jsonl"
    if candidate.exists():
        return candidate
    legacy_path = ARTIFACTS_DIR / analysis_id / "observability" / "run.jsonl"
    if legacy_path.exists():
        return legacy_path
    return None


def _latest_run_path(analysis_id: str) -> Path | None:
    runs_dir = ARTIFACTS_DIR / analysis_id / "observability" / "runs"
    if runs_dir.exists():
        candidates = list(runs_dir.glob("*.jsonl"))
        if candidates:
            return max(candidates, key=lambda p: p.stat().st_mtime)
    legacy_path = ARTIFACTS_DIR / analysis_id / "observability" / "run.jsonl"
    if legacy_path.exists():
        return legacy_path
    return None


def _latest_run_entry(analysis_id: str) -> tuple[Path | None, str | None]:
    candidates: list[tuple[float, Path | None, str | None]] = []
    runs_dir = ARTIFACTS_DIR / analysis_id / "observability" / "runs"
    if runs_dir.exists():
        for events_path in runs_dir.glob("*.jsonl"):
            candidates.append((events_path.stat().st_mtime, events_path, events_path.stem))
    legacy_path = ARTIFACTS_DIR / analysis_id / "observability" / "run.jsonl"
    if legacy_path.exists():
        candidates.append((legacy_path.stat().st_mtime, legacy_path, None))
    for run_dir in _list_run_dirs(ARTIFACTS_DIR / analysis_id):
        try:
            candidates.append((run_dir.stat().st_mtime, None, run_dir.name))
        except OSError:
            continue
    if not candidates:
        return None, None
    _, events_path, run_id = max(candidates, key=lambda entry: entry[0])
    return events_path, run_id


async def _event_stream(
    analysis_id: str,
    run_id: str | None,
    from_start: bool,
    heartbeat_sec: float = 5.0,
    max_wait_sec: float = 30.0,
):
    last_heartbeat = asyncio.get_event_loop().time()
    events_path: Path | None = None
    event_id = 0
    waited = 0.0
    while not events_path:
        if run_id:
            events_path = _resolve_run_path(analysis_id, run_id)
        else:
            events_path = _latest_run_path(analysis_id)
        if events_path:
            break
        if waited >= max_wait_sec:
            yield f'event: error\ndata: {{"error": "Events file not found after {max_wait_sec:.0f}s", "analysis_id": "{analysis_id}", "run_id": "{run_id or ""}"}}\n\n'
            return
        yield ": waiting-for-events\n\n"
        await asyncio.sleep(0.5)
        waited += 0.5

    if not events_path:
        return

    with events_path.open("r", encoding="utf-8") as handle:
        if not from_start:
            handle.seek(0, os.SEEK_END)
        while True:
            line = handle.readline()
            if line:
                payload = line.strip()
                if payload:
                    event_id += 1
                    yield f"id: {event_id}\n"
                    yield f"event: ledger\n"
                    yield f"data: {payload}\n\n"
                continue
            now = asyncio.get_event_loop().time()
            if now - last_heartbeat >= heartbeat_sec:
                yield ": heartbeat\n\n"
                last_heartbeat = now
            await asyncio.sleep(0.5)


@app.post("/api/runs/start")
def start_run(payload: StartRunRequest):
    mode = payload.mode or "apk-only"
    if mode not in {"apk-only", "combined"}:
        raise HTTPException(status_code=400, detail="mode must be apk-only or combined")
    if mode == "combined" and not payload.knox_apk_id:
        raise HTTPException(status_code=400, detail="knox_apk_id is required for combined mode")
    apk_path = Path(payload.apk_path)
    if not apk_path.exists():
        raise HTTPException(status_code=400, detail=f"APK path not found: {apk_path}")
    analysis_id = ArtifactStore.compute_analysis_id(str(apk_path), payload.knox_apk_id)
    run_id = _friendly_run_id(apk_path)
    log_path = ARTIFACTS_DIR / analysis_id / "runs" / run_id / "process.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-m", "apk_analyzer.main", "--mode", mode, "--apk", str(apk_path)]
    if payload.knox_apk_id:
        cmd.extend(["--knox-id", payload.knox_apk_id])
    if payload.settings_path:
        cmd.extend(["--settings", payload.settings_path])
    env = os.environ.copy()
    env["AAG_RUN_ID"] = run_id
    log_handle = log_path.open("a", encoding="utf-8")
    process = subprocess.Popen(
        cmd,
        cwd=str(REPO_ROOT),
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
    )
    log_handle.close()
    return {
        "analysis_id": analysis_id,
        "run_id": run_id,
        "pid": process.pid,
        "log_ref": str(Path("runs") / run_id / "process.log"),
    }


@app.delete("/api/runs/{analysis_id}/{run_id}")
def delete_run(analysis_id: str, run_id: str):
    """Delete a specific run and its artifacts."""
    import shutil

    # Delete run directory
    run_dir = ARTIFACTS_DIR / analysis_id / "runs" / run_id
    if run_dir.exists():
        shutil.rmtree(run_dir)

    # Delete observability log
    obs_log = ARTIFACTS_DIR / analysis_id / "observability" / "runs" / f"{run_id}.jsonl"
    if obs_log.exists():
        obs_log.unlink()

    # Check if analysis has any remaining runs
    runs_dir = ARTIFACTS_DIR / analysis_id / "runs"
    obs_runs_dir = ARTIFACTS_DIR / analysis_id / "observability" / "runs"
    has_runs = (runs_dir.exists() and any(runs_dir.iterdir())) or \
               (obs_runs_dir.exists() and any(obs_runs_dir.iterdir()))

    return {
        "deleted": True,
        "analysis_id": analysis_id,
        "run_id": run_id,
        "analysis_empty": not has_runs,
    }


@app.delete("/api/runs/{analysis_id}")
def delete_analysis(analysis_id: str):
    """Delete an entire analysis and all its runs."""
    import shutil

    analysis_dir = ARTIFACTS_DIR / analysis_id
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis not found")

    shutil.rmtree(analysis_dir)

    return {
        "deleted": True,
        "analysis_id": analysis_id,
    }


@app.get("/runs/{analysis_id}/artifact/{rel_path:path}")
def artifact(analysis_id: str, rel_path: str):
    path = _safe_artifact_path(analysis_id, rel_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Artifact not found")
    if path.suffix in {".json", ".txt", ".md", ".log", ".xml"}:
        return PlainTextResponse(path.read_text(encoding="utf-8", errors="ignore"))
    return FileResponse(str(path))


def _graph_to_dot(data: dict) -> str:
    """Convert graph JSON (nodes/edges or slice format) to DOT format."""
    lines = ["digraph G {"]
    lines.append('  rankdir=TB;')
    lines.append('  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10];')
    lines.append('  edge [fontname="Helvetica", fontsize=9];')

    # Handle slice format (units/edges)
    if "slice" in data and isinstance(data["slice"], dict):
        slice_data = data["slice"]
        units = slice_data.get("units", [])
        edges = slice_data.get("edges", [])

        for unit in units:
            uid = unit.get("unit_id", "")
            stmt = unit.get("stmt", "")[:60].replace('"', '\\"').replace('\n', ' ')
            tags = unit.get("tags", [])

            if "SEED" in tags:
                color = "#ff3b30"
                fontcolor = "white"
            elif "SOURCE" in tags:
                color = "#34c759"
                fontcolor = "white"
            elif "SINK" in tags:
                color = "#ff9500"
                fontcolor = "white"
            else:
                color = "#f5f5f7"
                fontcolor = "#1d1d1f"

            lines.append(f'  {uid} [label="{uid}: {stmt}", fillcolor="{color}", fontcolor="{fontcolor}"];')

        for edge in edges:
            from_id = edge.get("from", "")
            to_id = edge.get("to", "")
            edge_type = edge.get("type", "")
            style = "dashed" if "data" in edge_type else "solid"
            lines.append(f'  {from_id} -> {to_id} [style={style}];')

    # Handle standard CFG format (nodes/edges)
    elif "nodes" in data and "edges" in data:
        nodes = data.get("nodes", [])
        edges = data.get("edges", [])

        for idx, node in enumerate(nodes):
            nid = node.get("id", f"n{idx}")
            label = node.get("label", node.get("name", nid))[:50].replace('"', '\\"')
            ntype = (node.get("type", "") or "").lower()

            if ntype in ("entry", "start"):
                color = "#34c759"
                fontcolor = "white"
            elif ntype in ("exit", "end", "return"):
                color = "#ff3b30"
                fontcolor = "white"
            elif ntype in ("branch", "condition", "if"):
                color = "#ff9500"
                fontcolor = "white"
            else:
                color = "#e5e7eb"
                fontcolor = "#1d1d1f"

            lines.append(f'  {nid} [label="{label}", fillcolor="{color}", fontcolor="{fontcolor}"];')

        for edge in edges:
            from_id = edge.get("from", edge.get("source", ""))
            to_id = edge.get("to", edge.get("target", ""))
            if from_id and to_id:
                lines.append(f'  {from_id} -> {to_id};')

    lines.append("}")
    return "\n".join(lines)


@app.get("/runs/{analysis_id}/artifact/{rel_path:path}/render.png")
def artifact_graph_png(analysis_id: str, rel_path: str):
    """Render a graph JSON as PNG using Graphviz."""
    import hashlib
    import tempfile

    path = _safe_artifact_path(analysis_id, rel_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Artifact not found")

    if path.suffix != ".json":
        raise HTTPException(status_code=400, detail="Only JSON files can be rendered")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")

    # Check if it's a renderable graph
    has_slice = "slice" in data and isinstance(data.get("slice"), dict)
    has_nodes = "nodes" in data and "edges" in data

    if not has_slice and not has_nodes:
        raise HTTPException(status_code=400, detail="Not a renderable graph format")

    # Check size limits
    if has_nodes:
        node_count = len(data.get("nodes", []))
        if node_count > 500:
            raise HTTPException(status_code=400, detail=f"Graph too large ({node_count} nodes). Max 500.")

    if has_slice:
        unit_count = len(data["slice"].get("units", []))
        if unit_count > 200:
            raise HTTPException(status_code=400, detail=f"Slice too large ({unit_count} units). Max 200.")

    # Generate DOT
    dot_content = _graph_to_dot(data)

    # Check for cached PNG
    cache_dir = ARTIFACTS_DIR / analysis_id / ".cache" / "png"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_key = hashlib.md5(dot_content.encode()).hexdigest()
    cached_path = cache_dir / f"{cache_key}.png"

    if cached_path.exists():
        return FileResponse(str(cached_path), media_type="image/png")

    # Render with Graphviz
    with tempfile.NamedTemporaryFile(mode="w", suffix=".dot", delete=False) as dot_file:
        dot_file.write(dot_content)
        dot_path = dot_file.name

    try:
        result = subprocess.run(
            ["dot", "-Tpng", "-Gdpi=150", dot_path, "-o", str(cached_path)],
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0:
            error = result.stderr.decode("utf-8", errors="ignore")
            raise HTTPException(status_code=500, detail=f"Graphviz error: {error[:200]}")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Graph rendering timed out")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Graphviz not installed")
    finally:
        Path(dot_path).unlink(missing_ok=True)

    return FileResponse(str(cached_path), media_type="image/png")

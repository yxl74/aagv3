from __future__ import annotations

import os
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Dict, Iterable, Optional

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


_ANALYSIS_ID: ContextVar[str | None] = ContextVar("analysis_id", default=None)
_RUN_ID: ContextVar[str | None] = ContextVar("run_id", default=None)
_MODE: ContextVar[str | None] = ContextVar("analysis_mode", default=None)
_LLM_STEP: ContextVar[str | None] = ContextVar("llm_step", default=None)
_LLM_SEED: ContextVar[str | None] = ContextVar("llm_seed", default=None)


def init_telemetry(settings: Dict[str, Any]) -> None:
    conf = settings.get("telemetry", {}) if settings else {}
    if not conf.get("enabled"):
        return
    service_name = conf.get("service_name", "apk-analysis-agent")
    endpoint = conf.get("otlp_endpoint") or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return
    insecure = conf.get("otlp_insecure", True)
    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=endpoint, insecure=insecure)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)


def set_run_context(analysis_id: str, mode: str | None = None) -> str:
    run_id = uuid.uuid4().hex
    _ANALYSIS_ID.set(analysis_id)
    _RUN_ID.set(run_id)
    if mode:
        _MODE.set(mode)
    return run_id


@contextmanager
def span(name: str, **attrs: Any):
    tracer = trace.get_tracer("apk_analyzer")
    with tracer.start_as_current_span(name) as current:
        _apply_common_attrs(current)
        for key, value in attrs.items():
            if value is None:
                continue
            current.set_attribute(key, value)
        yield current


@contextmanager
def llm_context(step: str, seed_id: str | None = None):
    token_step = _LLM_STEP.set(step)
    token_seed = _LLM_SEED.set(seed_id)
    try:
        yield
    finally:
        _LLM_STEP.reset(token_step)
        _LLM_SEED.reset(token_seed)


def get_llm_context() -> Dict[str, Optional[str]]:
    return {
        "step": _LLM_STEP.get(),
        "seed_id": _LLM_SEED.get(),
    }


def _apply_common_attrs(span_obj) -> None:
    analysis_id = _ANALYSIS_ID.get()
    run_id = _RUN_ID.get()
    mode = _MODE.get()
    if analysis_id:
        span_obj.set_attribute("analysis_id", analysis_id)
    if run_id:
        span_obj.set_attribute("run_id", run_id)
    if mode:
        span_obj.set_attribute("analysis_mode", mode)

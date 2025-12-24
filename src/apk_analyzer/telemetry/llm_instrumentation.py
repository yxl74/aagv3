from __future__ import annotations

import json
import uuid
from typing import Any, Dict, Optional

from apk_analyzer.agents.base import LLMClient
from apk_analyzer.observability.logger import EventLogger
from apk_analyzer.telemetry.tracing import get_llm_context, span
from apk_analyzer.utils.artifact_store import ArtifactStore
from apk_analyzer.utils.llm_json import parse_llm_json


class InstrumentedLLMClient(LLMClient):
    def __init__(
        self,
        base: LLMClient,
        store: ArtifactStore,
        event_logger: EventLogger | None = None,
    ) -> None:
        self.base = base
        self.store = store
        self.event_logger = event_logger

    def complete(self, prompt: str, payload: dict, model: str | None = None) -> object:
        ctx = get_llm_context()
        step = ctx.get("step") or "llm"
        seed = ctx.get("seed_id") or "na"
        suffix = uuid.uuid4().hex[:8]
        input_ref = f"llm_inputs/{step}_{seed}_{suffix}.json"
        output_ref = f"llm_outputs/{step}_{seed}_{suffix}.txt"
        input_rel = self.store.relpath(input_ref)
        output_rel = self.store.relpath(output_ref)
        prompt_chars = len(prompt or "")
        payload_chars = _safe_json_chars(payload)

        self.store.write_json(input_ref, {
            "prompt": prompt,
            "payload": payload,
            "model": model,
        })
        if self.event_logger:
            self.event_logger.log(
                "llm.input",
                llm_step=step,
                seed_id=seed,
                model=model or "",
                ref=input_rel,
                prompt_chars=prompt_chars,
                payload_chars=payload_chars,
            )

        with span("llm.call", llm_step=step, seed_id=seed, model=model or "") as sp:
            sp.add_event("llm.input", {"ref": input_rel})
            response = self.base.complete(prompt, payload, model=model)
            output_text = _format_response(response)
            self.store.write_text(output_ref, output_text)
            sp.add_event("llm.output", {"ref": output_rel})
            if self.event_logger:
                self.event_logger.log(
                    "llm.output",
                    llm_step=step,
                    seed_id=seed,
                    model=model or "",
                    ref=output_rel,
                    size=len(output_text),
                    output_chars=len(output_text),
                )
                _log_parse_error(
                    self.event_logger,
                    step,
                    seed,
                    model,
                    response,
                    output_rel,
                )
        return response


def _format_response(response: object) -> str:
    if isinstance(response, str):
        return response
    try:
        return json.dumps(response, indent=2, ensure_ascii=True)
    except TypeError:
        return str(response)


def _safe_json_chars(payload: dict) -> int | None:
    try:
        return len(json.dumps(payload, ensure_ascii=True))
    except TypeError:
        return None


def _log_parse_error(
    event_logger: EventLogger,
    step: str,
    seed: str,
    model: str | None,
    response: object,
    output_ref: str,
) -> None:
    parsed = parse_llm_json(response)
    if not isinstance(parsed, dict) or not parsed.get("_error"):
        return
    raw_text = parsed.get("_raw_text", "")
    event_logger.log(
        "llm.parse_error",
        llm_step=step,
        seed_id=seed,
        model=model or "",
        error_type=parsed.get("_error"),
        raw_len=len(raw_text or ""),
        raw_sample=_trim_text(raw_text),
        ref=output_ref,
    )


def _trim_text(text: str, limit: int = 800) -> str:
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit]

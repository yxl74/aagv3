from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, Optional

_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", re.DOTALL)


def parse_llm_json(response: Any) -> Any:
    if isinstance(response, (dict, list)):
        return response
    if response is None:
        return {"_error": "empty_response", "_raw_text": ""}
    if not isinstance(response, str):
        return {"_error": "unsupported_type", "_raw_text": str(response)}

    text = response.strip()
    if not text:
        return {"_error": "empty_response", "_raw_text": ""}

    for candidate in _candidate_json_strings(text):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue

    return {"_error": "invalid_json", "_raw_text": text}


def coerce_llm_dict(
    response: Any,
    fallback: Dict[str, Any],
    required_keys: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    data = parse_llm_json(response)
    if not isinstance(data, dict) or data.get("_error"):
        return fallback
    if required_keys and any(key not in data for key in required_keys):
        return fallback
    return data


def _candidate_json_strings(text: str) -> Iterable[str]:
    yield text
    match = _FENCE_RE.search(text)
    if match:
        yield match.group(1).strip()
    obj_start = text.find("{")
    arr_start = text.find("[")
    if obj_start == -1 and arr_start == -1:
        return
    if arr_start != -1 and (obj_start == -1 or arr_start < obj_start):
        end = text.rfind("]")
        if end != -1:
            yield text[arr_start : end + 1]
    else:
        end = text.rfind("}")
        if end != -1:
            yield text[obj_start : end + 1]

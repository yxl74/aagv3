from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


def validate_json(data: Any, schema_path: str | Path) -> None:
    schema_path = Path(schema_path)
    with schema_path.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: e.path)
    if errors:
        messages = []
        for err in errors:
            loc = ".".join([str(p) for p in err.path])
            messages.append(f"{loc}: {err.message}")
        raise ValueError(f"Schema validation failed for {schema_path.name}: " + "; ".join(messages))

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict

import httpx

DEFAULT_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json"


def build_index(data: Dict[str, Any]) -> Dict[str, Any]:
    index: Dict[str, Any] = {}
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        external_refs = obj.get("external_references", [])
        technique_id = None
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                technique_id = ref["external_id"]
                break
        if not technique_id:
            continue
        tactics = [phase.get("phase_name") for phase in obj.get("kill_chain_phases", []) if phase.get("phase_name")]
        index[technique_id] = {
            "name": obj.get("name"),
            "tactics": tactics,
        }
    return index


def main() -> None:
    parser = argparse.ArgumentParser(description="Update MITRE Mobile ATT&CK dataset")
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--output", default="config/mitre/mobile-attack.json")
    parser.add_argument("--index-output", default="config/mitre/technique_index.json")
    args = parser.parse_args()

    response = httpx.get(args.url, timeout=60)
    response.raise_for_status()
    data = response.json()

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    index = build_index(data)
    Path(args.index_output).write_text(json.dumps(index, indent=2), encoding="utf-8")
    print(f"Wrote {len(index)} techniques to {args.index_output}")


if __name__ == "__main__":
    main()

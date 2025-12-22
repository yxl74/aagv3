from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

from apk_analyzer.telemetry import span

def _parse_flowdroid_xml(xml_path: Path) -> Dict[str, Any]:
    flows: List[Dict[str, Any]] = []
    if not xml_path.exists():
        return {"flow_count": 0, "flows": []}
    tree = ET.parse(xml_path)
    root = tree.getroot()

    for result in root.iter():
        if not result.tag.lower().endswith("result"):
            continue
        source = None
        sink = None
        for child in result:
            tag = child.tag.lower()
            if tag.endswith("source"):
                source = child.attrib.get("statement") or child.attrib.get("method") or child.text
            if tag.endswith("sink"):
                sink = child.attrib.get("statement") or child.attrib.get("method") or child.text
        if source or sink:
            flows.append({"source": source, "sink": sink})

    return {"flow_count": len(flows), "flows": flows}


def run_targeted_taint_analysis(
    apk_path: str | Path,
    sources_sinks_path: str | Path,
    android_platforms_dir: str | Path,
    flowdroid_jar: str | Path,
    output_dir: str | Path,
    timeout_sec: int = 900,
) -> Dict[str, Any]:
    apk_path = Path(apk_path)
    sources_sinks_path = Path(sources_sinks_path)
    android_platforms_dir = Path(android_platforms_dir)
    flowdroid_jar = Path(flowdroid_jar)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    xml_out = output_dir / "flowdroid.xml"

    cmd = [
        "java",
        "-jar",
        str(flowdroid_jar),
        "-a",
        str(apk_path),
        "-p",
        str(android_platforms_dir),
        "-s",
        str(sources_sinks_path),
        "-o",
        str(xml_out),
    ]
    with span("tool.flowdroid", tool_name="flowdroid", timeout_sec=timeout_sec) as sp:
        subprocess.run(cmd, check=True, timeout=timeout_sec)
        summary = _parse_flowdroid_xml(xml_out)
        sp.set_attribute("flow_count", summary.get("flow_count", 0))
    summary["xml_path"] = str(xml_out)
    return summary

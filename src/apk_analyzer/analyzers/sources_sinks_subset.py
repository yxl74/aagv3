from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Set

SOURCE_KEYWORDS = {
    "TelephonyManager",
    "READ_SMS",
    "ContactsContract",
    "Location",
    "CallLog",
    "AccountManager",
    "ContentResolver",
}

SINK_KEYWORDS = {
    "HttpURLConnection",
    "OkHttp",
    "Socket",
    "SmsManager",
    "OutputStream",
    "URLConnection",
    "sendTextMessage",
}

CATEGORY_TO_KEYWORDS = {
    "SENSITIVE_DATA_ACCESS": SOURCE_KEYWORDS,
    "DATA_TRANSMISSION": SINK_KEYWORDS,
}


def _collect_keywords(categories: Iterable[str], taint_question: str | None) -> Set[str]:
    keywords = set()
    for category in categories:
        keywords.update(CATEGORY_TO_KEYWORDS.get(category, set()))
    if taint_question:
        lowered = taint_question.lower()
        if "sms" in lowered:
            keywords.add("SmsManager")
        if "http" in lowered or "network" in lowered:
            keywords.add("HttpURLConnection")
            keywords.add("OkHttp")
        if "socket" in lowered:
            keywords.add("Socket")
    return keywords


def generate_subset(
    base_sources_sinks: str | Path,
    output_path: str | Path,
    categories_present: Iterable[str],
    taint_question: str | None = None,
) -> Path:
    base_sources_sinks = Path(base_sources_sinks)
    output_path = Path(output_path)
    keywords = _collect_keywords(categories_present, taint_question)

    lines = base_sources_sinks.read_text(encoding="utf-8").splitlines()
    subset: List[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            subset.append(line)
            continue
        if any(keyword in line for keyword in keywords):
            subset.append(line)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(subset) + "\n", encoding="utf-8")
    return output_path

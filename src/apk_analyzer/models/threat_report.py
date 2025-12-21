from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ThreatReport:
    analysis_id: str
    verdict: str
    summary: str
    seed_summaries: List[Dict[str, Any]] = field(default_factory=list)
    evidence_support_index: Dict[str, Any] = field(default_factory=dict)
    analysis_artifacts: Dict[str, Any] = field(default_factory=dict)

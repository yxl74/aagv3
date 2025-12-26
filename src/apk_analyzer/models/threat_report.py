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
    mitre_candidates: List[Dict[str, Any]] = field(default_factory=list)
    driver_guidance: List[Dict[str, Any]] = field(default_factory=list)
    execution_guidance: List[Dict[str, Any]] = field(default_factory=list)
    insights: List[str] = field(default_factory=list)

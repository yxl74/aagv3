from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class EvidenceSupport:
    artifact: str
    unit_ids: List[str]
    excerpt: Optional[str] = None


@dataclass
class Evidence:
    evidence_id: str
    claim: str
    severity: str
    supports: List[EvidenceSupport] = field(default_factory=list)
    seed_id: Optional[str] = None

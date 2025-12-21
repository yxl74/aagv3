from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ModelConfig:
    orchestrator: str
    recon: str
    tier1: str
    verifier: str
    tier2: str
    report: str

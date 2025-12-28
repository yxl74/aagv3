"""Deterministic confidence calculation for Tier1 output.

This module provides a deterministic formula for computing Tier1 confidence
instead of relying on LLM-generated values.

Fix 15: Deterministic confidence formula - NOT LLM-generated.
"""
from __future__ import annotations

from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from apk_analyzer.models.tier1_phases import (
        ExtractedStructure,
        ExtractionCoverage,
        Fact,
        InterpretedBehavior,
    )


# Weight constants for confidence formula
WEIGHT_COVERAGE = 0.3
WEIGHT_CLAIM_AVG = 0.4
WEIGHT_RESOLUTION = 0.3


def compute_tier1_confidence(
    extracted: "ExtractedStructure",
    interpreted: "InterpretedBehavior",
    facts: List["Fact"],
) -> float:
    """Compute Tier1 output confidence deterministically.

    Fix 15: Deterministic confidence formula - NOT LLM-generated.

    Factors:
    1. Extraction coverage (0.3 weight)
    2. Claim confidence average (0.4 weight)
    3. Unresolved ratio penalty (0.3 weight)

    Args:
        extracted: Phase 1A output.
        interpreted: Phase 1B output.
        facts: List of facts from Phase 1C.

    Returns:
        Confidence score between 0.0 and 1.0.
    """
    # Import here to avoid circular imports
    from apk_analyzer.models.tier1_phases import ExtractionCoverage

    # Factor 1: Extraction coverage
    coverage_scores = {
        ExtractionCoverage.COMPLETE: 1.0,
        ExtractionCoverage.PARTIAL: 0.7,
        ExtractionCoverage.MINIMAL: 0.3,
    }
    coverage_score = coverage_scores.get(extracted.extraction_coverage, 0.5)

    # Factor 2: Claim confidence average
    if interpreted.claims:
        claim_confidences = [c.confidence for c in interpreted.claims]
        avg_claim_confidence = sum(claim_confidences) / len(claim_confidences)
    else:
        avg_claim_confidence = 0.5  # No claims = medium confidence

    # Factor 3: Unresolved ratio penalty
    total_ambiguous = len(extracted.ambiguous_units)
    unresolved_count = len(interpreted.unresolved)
    if total_ambiguous > 0:
        unresolved_ratio = unresolved_count / total_ambiguous
        resolution_score = 1.0 - unresolved_ratio
    else:
        resolution_score = 1.0  # No ambiguity = full score

    # Weighted formula
    final_confidence = (
        WEIGHT_COVERAGE * coverage_score
        + WEIGHT_CLAIM_AVG * avg_claim_confidence
        + WEIGHT_RESOLUTION * resolution_score
    )

    return round(final_confidence, 2)


def compute_fact_confidence(
    fact: "Fact",
    interpreted: "InterpretedBehavior",
) -> float:
    """Compute confidence for a single fact.

    Args:
        fact: The fact to compute confidence for.
        interpreted: Phase 1B output for claim lookup.

    Returns:
        Confidence score between 0.0 and 1.0.
    """
    # Deterministic facts have high confidence
    if fact.from_deterministic:
        return 0.95

    # Behavioral facts inherit claim confidence
    if fact.claim_id:
        for claim in interpreted.claims:
            if claim.claim_id == fact.claim_id:
                return claim.confidence

    # No matching claim = low confidence
    return 0.3

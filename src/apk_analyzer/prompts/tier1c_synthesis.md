# Phase 1C: Evidence Synthesis

You are synthesizing the final Tier1 output from Phase 1A structural data and Phase 1B behavioral claims.

## Your Role

**Translation only** - you do NOT create new interpretations. You:
1. Populate structural fields from 1A deterministics
2. Translate behavioral claims from 1B to Tier1 output format
3. Maintain explicit claim lineage via claim_id

## Structural Fields (populate from 1A, no interpretation)

These fields come directly from Phase 1A deterministics:

### trigger_surface
Use `component_hints` from Phase 1A:
```json
{
  "component_name": "from component_hints.component_name",
  "component_name_source": "from component_hints.source",
  "component_type": "from component_hints.component_type",
  "component_type_source": "from component_hints.source",
  "entrypoint_method": "from component_hints.entrypoint_method",
  "entrypoint_method_source": "from component_hints.source"
}
```

### required_inputs (permissions)
Use `permissions` from Phase 1A (NOT component_hints):
```json
{
  "input_type": "permission",
  "name": "android.permission.RECORD_AUDIO",
  "scope": "inferred_from_api",  // or "global_manifest"
  "evidence_unit_ids": ["u123"]
}
```

## Behavioral Fields (translate from 1B claims ONLY)

These fields are derived ONLY from Phase 1B claims:

### path_constraints
Map from 1B claims with `tier1_field="path_constraints"` or `claim_type="constraint"`:
```json
{
  "constraint": "from claim.interpretation",
  "unit_ids": "from claim.source_unit_ids",
  "claim_id": "from claim.claim_id"  // REQUIRED for lineage
}
```

### observable_effects
Map from 1B claims with `tier1_field="observable_effects"` or `claim_type="effect"`:
```json
{
  "effect": "from claim.interpretation",
  "unit_ids": "from claim.source_unit_ids",
  "claim_id": "from claim.claim_id"  // REQUIRED for lineage
}
```

## Fact Construction

For each fact, you MUST:
1. Include `claim_id` from the 1B claim you're translating
2. Copy `source_unit_ids` from the claim
3. Set `from_deterministic: true` for structural facts (permissions, component type)
4. Set `from_deterministic: false` for behavioral facts

### Structural Facts (from 1A)
```json
{
  "statement": "Component type is Service",
  "support_unit_ids": [],
  "claim_id": null,
  "from_deterministic": true,
  "fact_category": "structural",
  "confidence": 0.95
}
```

### Behavioral Facts (from 1B)
```json
{
  "statement": "Records audio from microphone",
  "support_unit_ids": ["u5", "u6"],
  "claim_id": "c001",  // REQUIRED - explicit reference
  "from_deterministic": false,
  "fact_category": "behavioral",
  "confidence": 0.85
}
```

## FORBIDDEN

You must NOT:
- Create new behavioral interpretations not from 1B claims
- Add effects/constraints not traced to a claim_id
- Fabricate claim_id if no matching claim exists (move to uncertainties instead)
- Add permissions not in extracted.permissions
- Change the meaning of 1B claims during translation

## Output Format

```json
{
  "seed_id": "string",
  "function_summary": "Brief summary of main effects",
  "trigger_surface": { ... },
  "required_inputs": [ ... ],
  "path_constraints": [ ... ],
  "observable_effects": [ ... ],
  "facts": [ ... ],
  "uncertainties": ["list of uncertain items"],
  "confidence": 0.0-1.0,
  "phase_status": "ok|partial|failed",
  "extraction_coverage": "complete|partial|minimal"
}
```

## Confidence Calculation

Confidence is computed deterministically (NOT by you):
- 0.3 × coverage_score (complete=1.0, partial=0.7, minimal=0.3)
- 0.4 × average_claim_confidence
- 0.3 × resolution_score (1.0 - unresolved_ratio)

Just report the phase_status and extraction_coverage; confidence is calculated by code.

## Uncertainties

Include in uncertainties:
- Items from `extracted.flagged_for_review`
- Count of `interpreted.unresolved` units
- Count of `interpreted.unclaimed_apis`
- Claims with `needs_investigation: true`

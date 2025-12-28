# Phase 1A: Structural Extraction

You are validating and augmenting the deterministic extraction of code structure for a sensitive API callsite path.

## Your Task

Given pre-extracted structure from deterministic analysis, validate and augment the extraction:

1. **Validate API Calls**: Verify extracted API calls match the CFG
2. **Validate Control Guards**: Check branch conditions are correctly identified
3. **Identify Ambiguous Units**: Flag units that need semantic interpretation
4. **Sanity Check**: Compare extraction counts against CFG summary

## Input Data

You will receive:
- `seed_id`: Identifier for this sensitive callsite
- `caller_method`: Method signature containing the callsite
- `pre_extracted`: Deterministic extraction results including:
  - `api_calls`: List of extracted API callsites
  - `branch_conditions`: List of control flow guards
  - `ambiguous_units`: Units needing interpretation
- `cfg_summary`: CFG summary for sanity check

## Sanity Check (REQUIRED)

Before validating structure, cross-check counts:

1. Compare `pre_extracted.api_calls` count vs `cfg_summary.parsed_invoke_count`
2. Compare `pre_extracted.branch_conditions` count vs `cfg_summary.parsed_branch_count`

**Drift Detection Rules:**
- If mismatch > 30%:
  - Set `extraction_coverage = "partial"` (not minimal immediately)
  - Add to `flagged_for_review`: "Extractor drift detected: expected {X} callsites, extracted {Y}"
- This catches deterministic extractor bugs early

## Output Schema (STRICT)

Your output MUST conform to this JSON schema:

```json
{
  "seed_id": "string",
  "api_calls": [
    {
      "unit_id": "string",
      "signature": "string",
      "class_name": "string",
      "method_name": "string"
    }
  ],
  "control_guards": [
    {
      "unit_id": "string",
      "condition": "string",
      "guard_type": "permission_check|null_check|value_check|other"
    }
  ],
  "ambiguous_units": ["unit_id_1", "unit_id_2"],
  "flagged_for_review": ["reason_1", "reason_2"],
  "extraction_coverage": "complete|partial|minimal",
  "extraction_confidence": 0.0-1.0
}
```

## Coverage Rules

- **COMPLETE**: All heuristics pass, no ambiguous units
- **PARTIAL**: Default - some extraction issues or ambiguous units
- **MINIMAL**: Critical structure missing (no callsites AND no guards)

## Important Notes

1. Default to PARTIAL coverage if uncertain
2. Include sanity check results in flagged_for_review if drift detected
3. Mark units with magic numbers as ambiguous (e.g., `setAudioSource(1)`)
4. Do NOT interpret semantics - that's Phase 1B's job

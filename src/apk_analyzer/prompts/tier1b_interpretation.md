# Phase 1B: Semantic Interpretation

You are interpreting the behavioral semantics of sensitive API calls and resolving ambiguous code units.

## Your Task (Two Parts)

### Part 1: Behavioral Interpretation (REQUIRED for all API callsites)

For EVERY API callsite in `extracted.api_calls`:
- Interpret the behavioral effect (what does this API do?)
- Identify any constraints that must hold
- Produce an InterpretedClaim with proper tier1_field mapping

### Part 2: Ambiguity Resolution (if ambiguous_units present)

For each unit_id in `extracted.ambiguous_units`:
- Call read_java_source() or read_cfg_units()
- Resolve the constant/bytecode meaning
- Add to claims with resolved_by tracking

## STRICT REQUIREMENT: EFFECT Claim Per API Callsite

For EVERY API callsite in `extracted.api_calls`, produce at least one claim with:
- `claim_type: "effect"`
- `tier1_field: "observable_effects"`
- `unit_id`: the API callsite's unit_id

**The validator will REJECT outputs where ANY api_call lacks an EFFECT claim.**

## Claim Types Explained

- **EFFECT claims (REQUIRED for every API)**: What the API does
- **CONSTRAINT claims (optional)**: Conditions that must hold
- **INPUT claims (optional)**: Parameters/dependencies beyond permissions

## Output Schema (STRICT)

Your claims MUST conform to this JSON schema:

```json
{
  "claim_id": "c001",  // Format: c + 3 digits
  "claim_type": "effect|constraint|input",
  "tier1_field": "observable_effects|path_constraints|required_inputs",
  "unit_id": "string",
  "interpretation": "string (min 10 chars)",
  "source_unit_ids": ["unit_id"],  // Non-empty array
  "resolved_by": "jadx|cfg|heuristic|unresolved",
  "confidence": 0.0-1.0,
  "needs_investigation": false  // true for unknown APIs
}
```

## Full Output Format

```json
{
  "seed_id": "string",
  "claims": [InterpretedClaim, ...],
  "source_lookups": [
    {
      "unit_id": "string",
      "tool_used": "read_java_source|read_cfg_units|search_java_source",
      "tool_args": {},
      "success": true|false,
      "failure_reason": "string or null"
    }
  ],
  "unresolved": ["unit_id", ...]
}
```

## Resolution Strategy (in order)

1. TRY read_java_source() first
2. IF JADX fails → FALLBACK to read_cfg_units() for bytecode-level interpretation
3. IF both fail → mark resolved_by: "unresolved" with reason

Set `resolved_by` field to track how each claim was resolved.

## Unknown APIs

An API is **unknown** if it is sensitive but its behavior cannot be determined:
- Not in the catalog's behavior descriptions
- Ambiguous usage pattern
- Called with unresolvable arguments

For unknown APIs:
1. STILL produce an EFFECT claim (required)
2. Set `needs_investigation: true`
3. Set `confidence: 0.3`
4. Set `resolved_by: "heuristic"`
5. Use interpretation: "Unknown API effect: {signature} - requires investigation"

**Do NOT skip unknown APIs - they may be malicious or custom APIs.**

## Tool Coverage Tracking (REQUIRED)

For EVERY unit_id in ambiguous_units, you MUST:
1. Call a tool (read_java_source or read_cfg_units)
2. Add entry to source_lookups with success status
3. Then either: produce a claim OR add to unresolved with reason

## Checklist (Verify Before Returning)

- [ ] Every api_call.unit_id has at least one EFFECT claim
- [ ] Every ambiguous_unit has a source_lookup entry
- [ ] All claim_ids follow format "c001", "c002", etc.
- [ ] All source_unit_ids arrays are non-empty
- [ ] resolved_by is one of: jadx, cfg, heuristic, unresolved

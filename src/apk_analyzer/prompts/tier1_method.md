You are analyzing a single method from an Android application to understand its behavior.

## Method Signature
{method_sig}

## JADX Decompiled Source Code
```java
{jadx_source}
```

{% if cfg %}
## Control Flow Graph (CFG)
```json
{cfg}
```
{% endif %}

## Task
Analyze this method and extract the following information. Focus on what THIS method does, independent of how it might be called.

Return ONLY valid JSON (no markdown, no code fences, no extra text) with these fields:

```json
{
  "function_summary": "1-2 sentence description of what this method does",
  "path_constraints": [
    {
      "condition": "description of condition that must be true",
      "location_hint": "where in the code this appears",
      "required_state": "what state/value is needed"
    }
  ],
  "required_inputs": [
    {
      "type": "permission|intent_extra|system_setting|file|network|user_action|context",
      "name": "specific name (e.g., android.permission.READ_CONTACTS)",
      "value_hint": "description of expected value or format"
    }
  ],
  "data_flow": [
    "description of what data enters this method",
    "description of what data exits/is produced"
  ],
  "trigger_info": {
    "is_entrypoint": true/false,
    "is_command_handler": true/false,
    "dispatch_pattern": "description if this dispatches to other methods",
    "lifecycle_callback": "onCreate/onReceive/onAccessibilityEvent/etc if applicable"
  },
  "facts": [
    {
      "fact": "specific observation grounded in the code",
      "evidence": "code snippet or line reference supporting this"
    }
  ],
  "uncertainties": [
    "things that cannot be determined from this method alone"
  ],
  "confidence": 0.0-1.0
}
```

## Guidelines

1. **function_summary**: Be specific about what the method does. Mention:
   - What APIs it calls (ContentResolver.query, PackageManager, etc.)
   - What data it accesses (contacts, SMS, files, etc.)
   - What it does with the data (logs, sends, stores, etc.)

2. **path_constraints**: List conditions that must be satisfied for the method to execute fully:
   - Null checks
   - Permission checks
   - State validation
   - Feature flags

3. **required_inputs**: What does this method need to function?
   - Android permissions (READ_CONTACTS, INTERNET, etc.)
   - Intent extras it reads
   - Context requirements
   - Network connectivity

4. **data_flow**: Trace data movement:
   - Input: What parameters does it receive? What external data does it fetch?
   - Output: What does it return? What side effects (logging, network, storage)?

5. **trigger_info**: How is this method triggered?
   - Is it an Android lifecycle callback (onCreate, onReceive, onAccessibilityEvent)?
   - Is it a command handler that dispatches to other methods?
   - Does it match a C2 command-handler pattern (switch/case on commands)?

6. **facts**: Specific observations with evidence:
   - API calls made
   - Strings/URLs referenced
   - Data transformations performed

7. **uncertainties**: What can't be determined from this method alone?
   - Where data comes from (if parameter)
   - Where data goes (if passed to another method)
   - How this method is called

8. **confidence**: Rate your confidence in the analysis (0.0-1.0)
   - 1.0: Clear, readable code with obvious behavior
   - 0.5: Some obfuscation or complexity
   - 0.0: Cannot understand the method

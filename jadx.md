Below is a tightened, higher-leverage version of your plan, with emphasis on (a) making JADX output *more deterministic* (so your lookups stop failing in the first place), and (b) shifting from “method-name search” to “descriptor-aware, index-based extraction” (so synthetic constructs and overloads don’t break you).

---

## 1) Add a “JADX determinism” step before any extractor work

Right now you’re compensating in Python for transformations caused by JADX settings (inlining + moving inner classes + renaming). That’s inherently brittle, because the very constructs you’re trying to match may be removed/relocated.

**High-impact change:** run JADX in a configuration that preserves structural boundaries.

From JADX’s own troubleshooting guidance, the relevant knobs are: disable renaming, disable inlining (anonymous + methods), and disable “move inner classes into parent.” ([GitHub][1])

### Recommendation

In whatever code path produces `jadx_root`, ensure the CLI invocation includes (names per jadx-cli):

* `--rename-flags none` (avoid identifier renames that invalidate Soot/Jimple names) ([GitHub][1])
* `--no-inline-anonymous` (keeps `Outer$N` as its own class/file instead of inlining into instantiation site) ([GitHub][1])
* `--no-inline-methods` (prevents lambda bodies and other synthetic methods from being merged away) ([GitHub][1])
* `--no-move-inner-classes` (prevents `$` classes from being merged into the parent file) ([GitHub][1])

**Why this matters for “matching JADX code to CFG blocks”:**

* If a lambda method is inlined, you no longer have a stable 1:1 method body to attach CFG blocks to—your Python-side fallback can only provide context, not a faithful mapping.
* If anonymous classes are inlined or moved, class-to-file and method-to-text boundaries stop existing.

This one step usually yields a larger win than any heuristic extraction logic.

---

## 2) Upgrade your classification to be descriptor- and nesting-aware

Your `classify_method(sig)` is a good start, but it will misclassify or underclassify common cases that affect lookup:

### Add these classifications (minimal set)

* **STATIC_INITIALIZER** for `<clinit>` (JADX renders `static { ... }`)
* **CONSTRUCTOR** for `<init>` (JADX renders `ClassName(...) { ... }`)
* **NESTED_ANONYMOUS_INNER** for `Outer$12$1` etc. (you currently treat it as anonymous, but you lose the “path”)
* **SYNTHETIC_FORWARDER** (covers `access$NNN`, some lambda wrappers, and other “one hop” synthetic methods)

### Improve anonymous-inner parsing

Instead of only checking `parts[-1].isdigit()`, extract the full numeric suffix chain:

* `Outer$10` → index path `[10]`
* `Outer$12$1` → index path `[12, 1]`

That index path becomes a key you can store in `MethodClassification` and later use for locating the right inner class *or* the right instantiation occurrence (if you must fall back to inlined form).

---

## 3) Stop “search by name in file”; build a per-file method index once

Your current root cause statement is accurate: string-searching for `method_name` fails when:

* methods are renamed,
* overloads exist,
* constructors/static initializers are involved,
* synthetic headers include comments/modifiers in unexpected places.

### Replace `_extract_method_body(source, method_name, ...)` with an indexer

**New approach:**

1. For a given `.java` file, parse and index all “extractable blocks” once:

   * method declarations (including `/* synthetic */` / `/* bridge */` comment patterns),
   * constructors,
   * `static {}` initializers,
   * inner class bodies (optional, but useful).
2. Store entries keyed by:

   * `name` (`foo`, `<init>`, `<clinit>` mapped forms),
   * `arity` (param count),
   * *optional* normalized param type strings (best effort),
   * start/end offsets and/or start/end line numbers.

Then `extract_method_source_v2()` becomes:

* resolve file(s),
* query index using `(method_name, arity, maybe types)`,
* extract by offsets.

### Why this is critical for CFG matching

Basic blocks map to a specific DEX/Jimple method signature, not “whatever decompiler chose to print.” Indexing lets you:

* disambiguate overloads by arity/type,
* tolerate extra modifiers/comments,
* extract the exact decompiled method span reproducibly.

---

## 4) Treat synthetic wrappers as “delegates,” not always “skip”

I understand why you want to skip `$$ExternalSyntheticLambda` and `access$NNN`—they often look unhelpful. But for **control-flow-block matching**, skipping can be actively harmful:

* Your CFG may contain blocks for `$$ExternalSyntheticLambdaX.run()` or `accept()` etc.
* Even if it’s “just a forwarder,” you still need *some* representation to explain why those blocks exist and where they go.

### Upgrade from `skip_*` to `delegate_*`

Instead of:

* `skip_reason="Synthetic lambda - body available via lambda method"`

Prefer:

* `delegate_to="<host sig>"` when resolvable,
* and optionally emit a tiny stub source:

```java
// synthetic forwarder
public void run() { HostClass.lambda$foo$0(captured0, captured1); }
```

How to resolve `delegate_to` robustly:

* If you already have Soot/Jimple/CFG, inspect invoked targets in the method body:

  * if the method has exactly one invoke + return, treat it as a delegate.
  * store that in metadata.

This gives you **zero ambiguity** downstream:

* CFG blocks for the wrapper map to wrapper stub (or decompiled wrapper if present),
* analysis can jump to the real implementation via `delegate_to`.

---

## 5) Lambda method fallback: make it more precise than “host method”

Your current lambda fallback (“extract entire host method for LLM context”) is reasonable as a *last resort*, but it can mislead CFG-to-source matching because:

* the lambda CFG is not the host CFG,
* the lambda code may be duplicated or rearranged in the host method by the decompiler.

### Improve lambda extraction in tiers

**Tier 1: direct lambda method**

* search via index key `(lambda$… , arity)`.

**Tier 2: look for a renamed/synthetic header**
JADX sometimes wraps synthetic methods with comments like `/* synthetic */` (or emits renamed markers). Your indexer should treat comment-augmented declarations as valid matches.

**Tier 3: delegate resolution**
If the lambda method doesn’t exist in Java output (due to inlining), try resolving:

* which method contains the invoke site (host),
* then extract a tight “window” around the invoke site if you can locate it (even a heuristic window is better than full host method for relevance).

**Tier 4: host method fallback (your current approach)**
Keep it, but mark it clearly as *context-only*:

* `lookup_strategy="host_method_context_only"`
* and set something like `mapping_fidelity="low"` so downstream doesn’t treat it as exact.

---

## 6) Anonymous inner classes: prefer fixing the decompiler output over parsing inline blocks

Your proposed `_find_anonymous_class_defs(source)` + “Nth instantiation” heuristic is the exact type of logic that becomes unmaintainable quickly.

Given the jadx flags above, you should expect:

* `Outer$1.java`, `Outer$2.java`, … to exist as separate files (or at least separate class blocks), making extraction *regular* again. ([GitHub][1])

### Revised strategy for anonymous inners

**Primary:** locate the actual `Outer$N` class source file and extract method normally.

**Secondary (only if inlining still happened or flags can’t be used):**

* fall back to inline parsing, but base it on the **numeric index path** plus a brace-aware extraction of `new X() { ... }` blocks,
* return with low confidence + full metadata (so you can quantify how often you’re relying on this).

---

## 7) Expand `ExtractResult` and `MethodAnalysis` to support debugging + CFG alignment

You already plan to add `method_type`, `lookup_strategy`, `skip_reason`. I would add two more fields that dramatically improve traceability:

### Add:

* `source_file: str | None` (exact `.java` file used)
* `span: tuple[int,int] | None` (start_line, end_line) or byte offsets
* `delegate_to: str | None` (for synthetic forwarders)
* `confidence: float` (0–1), derived from strategy tier

This turns your method cache into something you can *audit*:

* “Which methods are low confidence?”
* “Which were delegated?”
* “What exact file/span did we extract?”

---

## 8) Adjust your “Expected Outcomes” to reflect the real win

With the jadx flags change alone, you should update your expectation model:

* **Anonymous inner**: should move from “1–2/3” to close to “3/3”, because the classes stop being inlined (assuming the APK isn’t doing something exotic). ([GitHub][1])
* **Lambda methods**: similarly, disabling method inlining should push lambda extraction higher than 50–80% in many apps. ([GitHub][1])

The remaining failures typically come from:

* aggressive obfuscation + name collisions,
* multidex / split APK resource layout issues,
* decompilation errors where JADX fails to render a method.

---

## 9) Concrete revised implementation order (minimal churn)

If you want the shortest path to measurable improvement:

1. **Add jadx CLI flags** (`--no-inline-anonymous`, `--no-inline-methods`, `--no-move-inner-classes`, `--rename-flags none`) at the point you generate `jadx_root`. ([GitHub][1])
2. Implement `MethodType` + `MethodClassification` upgrades:

   * handle `<init>`, `<clinit>`, nested anonymous index paths.
3. Implement **per-file method indexer** (brace-aware) and swap regular extraction to use it.
4. Implement constructor/static initializer extraction using the same indexer.
5. Implement synthetic forwarder handling:

   * first attempt normal extraction,
   * else resolve `delegate_to` using CFG/bytecode and emit stub.
6. Only then implement any “inline anonymous block” heuristic fallback (and mark low confidence).

---

## 10) Test plan upgrades (to avoid false confidence)

Your current tests are classification-only. Add two higher-value test tiers:

### A) Golden-file extraction tests

Keep small decompiled `.java` fixtures that include:

* `lambda$foo$0` with `/* synthetic */`
* constructor + static initializer
* `Outer$1` and `Outer$12$1` cases
* `access$100` forwarder

Assert:

* correct `source_file`
* correct extracted span boundaries
* correct `lookup_strategy`
* correct `delegate_to` when applicable

### B) “JADX options” regression test

A single integration test that runs jadx on a tiny sample with and without the flags and asserts:

* anonymous inner class file exists when flags enabled
* lambda method appears when `--no-inline-methods` enabled

This directly prevents someone from “refactoring” the jadx invocation and silently reintroducing your 44% failure mode.

---

## Summary of the main improvement

Your classification-first routing is good, but the highest ROI changes are:

1. **Make JADX stop deleting/relocating the very methods you’re trying to match** (disable inlining + moving + renaming). ([GitHub][1])
2. **Extract by indexed spans keyed by signature features (name/arity/types), not by naive name search.**
3. **Represent synthetic wrappers as delegates (with `delegate_to`) rather than “skip,”** so CFG-to-source alignment remains explainable.

If you want, paste (a) your current `extract_method_source()` implementation and (b) one example of a failing soot signature + the corresponding jadx output file(s); I can propose the exact indexing key and extraction regex/bracing logic that will work for your specific output format.

[1]: https://github.com/skylot/jadx/wiki/Troubleshooting-Q%26A?utm_source=chatgpt.com "Troubleshooting Q&A · skylot/jadx Wiki"

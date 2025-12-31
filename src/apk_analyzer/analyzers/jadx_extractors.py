from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _resolve_jadx(jadx_path: str | Path) -> Optional[Path]:
    path = Path(jadx_path)
    if path.exists():
        return path
    found = shutil.which(str(jadx_path))
    if found:
        return Path(found)
    return None


def run_jadx(
    apk_path: str | Path,
    out_dir: str | Path,
    jadx_path: str | Path = "jadx",
    timeout_sec: int = 600,
) -> Optional[Path]:
    """
    Run JADX to decompile an APK.

    Note: JADX often exits with code 1 due to minor decompilation errors
    (obfuscated code, etc.) but still produces useful output. We check for
    actual output rather than relying on exit code.
    """
    jadx_bin = _resolve_jadx(jadx_path)
    if not jadx_bin:
        return None
    apk_path = Path(apk_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Flags to preserve structural boundaries for accurate method extraction:
    # --no-inline-anonymous: Keep Outer$N as separate files (not inlined)
    # --no-inline-methods: Preserve lambda method bodies (not merged into host)
    # --no-move-inner-classes: Don't merge $ classes into parent file
    # --rename-flags none: Keep identifiers matching Soot/Jimple signatures
    jadx_flags = [
        "--no-inline-anonymous",
        "--no-inline-methods",
        "--no-move-inner-classes",
        "--rename-flags", "none",
    ]

    if jadx_bin.suffix == ".jar":
        cmd = ["java", "-jar", str(jadx_bin), "-d", str(out_dir)] + jadx_flags + [str(apk_path)]
    else:
        cmd = [str(jadx_bin), "-d", str(out_dir)] + jadx_flags + [str(apk_path)]

    try:
        # Don't use check=True - JADX returns exit code 1 even on partial success
        subprocess.run(cmd, timeout=timeout_sec, capture_output=True)
    except (subprocess.TimeoutExpired, OSError):
        return None

    # Verify JADX produced output (sources directory with .java files)
    sources_dir = out_dir / "sources"
    if sources_dir.is_dir() and any(sources_dir.rglob("*.java")):
        return out_dir
    return None


def find_jadx_manifest(jadx_root: str | Path) -> Optional[Path]:
    root = Path(jadx_root)
    candidates = [
        root / "resources" / "AndroidManifest.xml",
        root / "AndroidManifest.xml",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _parse_soot_signature(sig: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Parse a Soot method signature into components.

    Example: "<com.pkg.Class: void method(int,java.lang.String)>"
    Returns: ("com.pkg.Class", "method", "void")
    """
    match = re.match(r"<([^:]+):\s*(\S+)\s+([^(]+)\(", sig)
    if not match:
        return None, None, None
    class_name = match.group(1)
    return_type = match.group(2)
    method_name = match.group(3)
    return class_name, method_name, return_type


def _find_source_file(jadx_root: Path, class_name: str) -> Optional[Path]:
    """
    Map a class name to its .java file, handling inner classes.

    With --no-inline-anonymous flag, anonymous inner classes get their own files:
        com.pkg.Outer$1 -> sources/com/pkg/Outer$1.java (preferred)
        com.pkg.Outer$1 -> sources/com/pkg/Outer.java (fallback)

    Examples:
        com.pkg.Outer -> sources/com/pkg/Outer.java
        com.pkg.Outer$Inner -> sources/com/pkg/Outer$Inner.java or Outer.java
        com.pkg.Outer$1 -> sources/com/pkg/Outer$1.java or Outer.java
    """
    # First, try the exact class name (handles --no-inline-anonymous output)
    relative_path_exact = class_name.replace(".", "/") + ".java"
    source_path_exact = jadx_root / "sources" / relative_path_exact
    if source_path_exact.exists():
        return source_path_exact

    # Try without 'sources' subdirectory
    alt_path_exact = jadx_root / relative_path_exact
    if alt_path_exact.exists():
        return alt_path_exact

    # Fallback: try outer class file (for inline inner classes)
    if "$" in class_name:
        outer_class = class_name.split("$")[0]
        relative_path_outer = outer_class.replace(".", "/") + ".java"
        source_path_outer = jadx_root / "sources" / relative_path_outer
        if source_path_outer.exists():
            return source_path_outer

        alt_path_outer = jadx_root / relative_path_outer
        if alt_path_outer.exists():
            return alt_path_outer

    return None


def _extract_method_body(
    source: str,
    method_name: str,
    class_name: str,
    max_lines: int = 100,
    max_chars: int = 5000,
) -> Optional[str]:
    """
    Extract a method body from Java source using brace-counting.

    Handles inner classes by searching within the correct class context.
    """
    # For inner classes, we need the inner class name (after $)
    inner_class = None
    if "$" in class_name:
        inner_class = class_name.split("$")[-1]

    lines = source.split("\n")
    method_start = None
    class_depth = 0
    in_target_class = inner_class is None  # True if outer class (no inner)

    # First pass: find method start
    for i, line in enumerate(lines):
        stripped = line.strip()

        # Track class nesting for inner classes
        if inner_class:
            if re.match(rf"(public|private|protected|static|\s)*class\s+{re.escape(inner_class)}\b", stripped):
                in_target_class = True
                class_depth = 0
            if in_target_class:
                class_depth += line.count("{") - line.count("}")
                if class_depth < 0:
                    in_target_class = False
                    class_depth = 0

        if not in_target_class:
            continue

        # Look for method declaration
        # Match: modifiers + return_type + method_name + (
        method_pattern = rf"(public|private|protected|static|final|synchronized|native|\s)*\w+(\[\])?\s+{re.escape(method_name)}\s*\("
        if re.search(method_pattern, stripped):
            # Check if this line has the opening brace
            if "{" in line:
                method_start = i
                break
            # Opening brace might be on next line
            for j in range(i, min(i + 3, len(lines))):
                if "{" in lines[j]:
                    method_start = i
                    break
            if method_start is not None:
                break

    if method_start is None:
        return None

    # Second pass: extract method body using brace counting
    brace_count = 0
    method_lines = []
    started = False

    for i in range(method_start, len(lines)):
        line = lines[i]
        method_lines.append(line)

        # Count braces
        for char in line:
            if char == "{":
                brace_count += 1
                started = True
            elif char == "}":
                brace_count -= 1

        # Method complete when we return to 0 after starting
        if started and brace_count == 0:
            break

        # Safety limit
        if len(method_lines) > max_lines * 2:
            break

    if not method_lines:
        return None

    # Apply size limits
    result_lines = method_lines[:max_lines]
    if len(method_lines) > max_lines:
        result_lines.append("    // ... truncated")

    result = "\n".join(result_lines)
    if len(result) > max_chars:
        result = result[:max_chars] + "\n    // ... truncated"

    return result


def extract_method_source(
    jadx_root: Path,
    soot_method_sig: str,
    max_lines: int = 100,
    max_chars: int = 5000,
) -> Optional[str]:
    """
    Extract decompiled Java source for a specific method.

    Args:
        jadx_root: JADX output directory (contains sources/<pkg>/<Class>.java)
        soot_method_sig: Soot signature like "<com.pkg.Class: void method(int)>"
        max_lines: Maximum lines to return
        max_chars: Maximum characters

    Returns:
        Decompiled Java source or None if not found
    """
    class_name, method_name, _ = _parse_soot_signature(soot_method_sig)
    if not class_name or not method_name:
        return None

    source_file = _find_source_file(jadx_root, class_name)
    if not source_file:
        return None

    try:
        source = source_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    return _extract_method_body(source, method_name, class_name, max_lines, max_chars)


# =============================================================================
# Jimple IR Extraction (Layer 2 - 100% coverage backup)
# =============================================================================


def extract_jimple_ir(
    cfg_dir: Path,
    method_sig: str,
    max_units: int = 100,
) -> Optional[Dict[str, Any]]:
    """
    Extract Jimple IR from pre-computed CFG files.

    CFG files are generated by Soot during FlowDroid analysis and stored
    in graphs/cfg/{hash}.json. Each file contains Jimple statements for
    a single method.

    Args:
        cfg_dir: Path to graphs/cfg/ directory
        method_sig: Soot method signature like "<com.pkg.Class: void method(int)>"
        max_units: Maximum number of Jimple units to return

    Returns:
        Dict with Jimple IR info or None if CFG not found:
        {
            "statements": List[str],       # Jimple statements
            "invoked_methods": List[str],  # Method signatures from invoke statements
            "field_accesses": List[str],   # Field access statements
            "unit_count": int,             # Total units in method
            "truncated": bool,             # Whether output was truncated
        }
    """
    if not cfg_dir or not cfg_dir.exists():
        return None

    # CFG files are keyed by SHA1 hash of method signature
    method_hash = hashlib.sha1(method_sig.encode()).hexdigest()
    cfg_path = cfg_dir / f"{method_hash}.json"

    if not cfg_path.exists():
        return None

    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    units = cfg.get("units", [])
    total_units = len(units)
    units = units[:max_units]

    # Extract statements
    statements = [u.get("stmt", "") for u in units if u.get("stmt")]

    # Extract invoked methods from invoke statements
    invoked_methods = _extract_invoked_methods(statements)

    # Extract field accesses (assignments involving fields)
    field_accesses = [s for s in statements if ".<" in s and ": " in s]

    return {
        "statements": statements,
        "invoked_methods": invoked_methods,
        "field_accesses": field_accesses,
        "unit_count": total_units,
        "truncated": total_units > max_units,
    }


def _extract_invoked_methods(statements: List[str]) -> List[str]:
    """
    Extract method signatures from Jimple invoke statements.

    Jimple invoke format examples:
        virtualinvoke r1.<java.io.InputStream: int read()>()
        staticinvoke <com.pkg.Class: void method(int)>(r0)
        specialinvoke r0.<com.pkg.Class: void <init>()>()
    """
    invoked = []
    # Pattern to extract method signature from angle brackets
    pattern = re.compile(r"<([^>]+)>")

    for stmt in statements:
        if "invoke" in stmt:
            match = pattern.search(stmt)
            if match:
                invoked.append(match.group(1))

    return invoked


def format_jimple_for_llm(jimple_ir: Dict[str, Any], method_sig: str) -> str:
    """
    Format Jimple IR as readable text for LLM consumption.

    Args:
        jimple_ir: Dict from extract_jimple_ir()
        method_sig: Original method signature

    Returns:
        Formatted string suitable for LLM prompt
    """
    if not jimple_ir:
        return ""

    lines = [
        f"// Jimple IR for: {method_sig}",
        f"// Units: {jimple_ir['unit_count']}" + (" (truncated)" if jimple_ir.get("truncated") else ""),
        "",
    ]

    # Add statements
    for stmt in jimple_ir.get("statements", []):
        lines.append(f"    {stmt}")

    # Add summary of invoked methods
    invoked = jimple_ir.get("invoked_methods", [])
    if invoked:
        lines.append("")
        lines.append(f"// Invokes {len(invoked)} methods:")
        for m in invoked[:10]:  # Limit to first 10
            lines.append(f"//   - {m}")
        if len(invoked) > 10:
            lines.append(f"//   ... and {len(invoked) - 10} more")

    return "\n".join(lines)

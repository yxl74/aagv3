from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple


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

    if jadx_bin.suffix == ".jar":
        cmd = ["java", "-jar", str(jadx_bin), "-d", str(out_dir), str(apk_path)]
    else:
        cmd = [str(jadx_bin), "-d", str(out_dir), str(apk_path)]

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

    Examples:
        com.pkg.Outer -> sources/com/pkg/Outer.java
        com.pkg.Outer$Inner -> sources/com/pkg/Outer.java
    """
    # Handle inner classes - strip $Inner suffix
    outer_class = class_name.split("$")[0]

    # Convert package.Class to path
    relative_path = outer_class.replace(".", "/") + ".java"
    source_path = jadx_root / "sources" / relative_path

    if source_path.exists():
        return source_path

    # Try without 'sources' subdirectory (some JADX versions)
    alt_path = jadx_root / relative_path
    if alt_path.exists():
        return alt_path

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

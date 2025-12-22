from __future__ import annotations

import base64
import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List


_ANDROGUARD_IMPORT_ERROR: Exception | None = None


def _try_import_androguard():
    global _ANDROGUARD_IMPORT_ERROR
    try:
        from androguard.core.bytecodes.apk import APK  # type: ignore
    except Exception as exc:  # pragma: no cover - optional dependency
        _ANDROGUARD_IMPORT_ERROR = exc
        return None
    _ANDROGUARD_IMPORT_ERROR = None
    return APK


def extract_manifest(apk_path: str | Path) -> Dict[str, Any]:
    apk_path = Path(apk_path)
    APK = _try_import_androguard()
    if APK is None:
        detail = f": {_ANDROGUARD_IMPORT_ERROR}" if _ANDROGUARD_IMPORT_ERROR else ""
        raise RuntimeError(f"androguard is required for manifest extraction{detail}")
    apk = APK(str(apk_path))
    return {
        "package_name": apk.get_package(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "permissions": apk.get_permissions(),
        "activities": apk.get_activities(),
        "services": apk.get_services(),
        "receivers": apk.get_receivers(),
        "providers": apk.get_providers(),
        "min_sdk_version": apk.get_min_sdk_version(),
        "target_sdk_version": apk.get_target_sdk_version(),
        "application_label": apk.get_app_name(),
    }


_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{20,}={0,2})")

_SUSPICIOUS_KEYWORDS = {
    "dex",
    "payload",
    "update",
    "socket",
    "telegram",
    "c2",
    "command",
    "shell",
    "root",
    "accessibility",
    "overlay",
}


def _extract_ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    results = []
    current = bytearray()
    for b in data:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) >= min_len:
                results.append(current.decode("ascii", errors="ignore"))
            current = bytearray()
    if len(current) >= min_len:
        results.append(current.decode("ascii", errors="ignore"))
    return results


def extract_strings(apk_path: str | Path) -> Dict[str, Any]:
    apk_path = Path(apk_path)
    strings: List[str] = []
    with zipfile.ZipFile(apk_path, "r") as archive:
        for name in archive.namelist():
            if name.endswith(".dex"):
                strings.extend(_extract_ascii_strings(archive.read(name)))
            elif name.startswith("assets/") and not name.endswith("/"):
                data = archive.read(name)
                strings.extend(_extract_ascii_strings(data))
    urls = sorted(set(_URL_RE.findall("\n".join(strings))))
    ips = sorted(set(_IP_RE.findall("\n".join(strings))))
    domains = sorted(set(_DOMAIN_RE.findall("\n".join(strings))))
    base64_blobs = sorted(set([s for s in strings if _BASE64_RE.fullmatch(s)]))
    suspicious = sorted({s for s in strings if s.lower() in _SUSPICIOUS_KEYWORDS})
    return {
        "urls": urls,
        "domains": domains,
        "ips": ips,
        "base64_blobs_sample": base64_blobs[:50],
        "suspicious_keywords": suspicious,
        "string_count": len(strings),
        "string_sample": strings[:200],
    }


def extract_cert_info(apk_path: str | Path) -> Dict[str, Any]:
    apk_path = Path(apk_path)
    cert_files = []
    with zipfile.ZipFile(apk_path, "r") as archive:
        for name in archive.namelist():
            upper = name.upper()
            if upper.startswith("META-INF/") and (upper.endswith(".RSA") or upper.endswith(".DSA") or upper.endswith(".EC")):
                cert_files.append(name)
    cert_data = []
    with zipfile.ZipFile(apk_path, "r") as archive:
        for name in cert_files:
            blob = archive.read(name)
            cert_data.append({
                "file": name,
                "sha256": __import__("hashlib").sha256(blob).hexdigest(),
                "size": len(blob),
                "base64_prefix": base64.b64encode(blob[:64]).decode("ascii"),
            })
    return {
        "cert_files": cert_files,
        "certificates": cert_data,
    }

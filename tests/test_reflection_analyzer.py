from __future__ import annotations

import json
from pathlib import Path

from apk_analyzer.knowledge.api_catalog import ApiCatalog
from apk_analyzer.phase0.reflection_analyzer import (
    analyze_reflection_hits,
    build_sensitive_targets_from_catalog,
    filter_reflection_hits,
)


def _write_method_source(jadx_root: Path, class_name: str, method_name: str, body: str) -> None:
    parts = class_name.split(".")
    package = ".".join(parts[:-1])
    simple = parts[-1]
    source_dir = jadx_root / "sources" / Path(*parts[:-1])
    source_dir.mkdir(parents=True, exist_ok=True)
    source_path = source_dir / f"{simple}.java"
    source_path.write_text(
        "\n".join([
            f"package {package};" if package else "",
            f"public class {simple} {{",
            f"    public void {method_name}() {{",
            f"        {body}",
            "    }",
            "}",
        ]),
        encoding="utf-8",
    )


def _make_catalog(tmp_path: Path) -> ApiCatalog:
    payload = {
        "version": "test",
        "categories": {
            "EVASION_REFLECTION": {
                "priority": "MEDIUM",
                "description": "Reflection-based indirection",
                "weight": 0.55,
                "mitre": {"primary": "T1406", "aliases": []},
                "requires_slice": True,
                "pha_tags": ["BACKDOOR"],
                "permission_hints": [],
                "signatures": {
                    "methods": [
                        "<java.lang.Class: java.lang.Class forName(java.lang.String)>",
                        "<java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])>",
                        "<java.lang.Class: java.lang.reflect.Method getMethod(java.lang.String,java.lang.Class[])>",
                    ],
                    "fields": [],
                    "strings": [],
                },
            },
            "EVASION_CRYPTO_OBFUSCATION": {
                "priority": "MEDIUM",
                "description": "Crypto obfuscation",
                "weight": 0.45,
                "mitre": {"primary": "T1406", "aliases": []},
                "requires_slice": True,
                "pha_tags": ["TROJAN"],
                "permission_hints": [],
                "signatures": {
                    "methods": [
                        "<javax.crypto.Cipher: javax.crypto.Cipher getInstance(java.lang.String)>",
                    ],
                    "fields": [],
                    "strings": ["AES"],
                },
            },
            "COLLECTION_SMS_MESSAGES": {
                "priority": "CRITICAL",
                "description": "SMS collection",
                "weight": 1.0,
                "mitre": {"primary": "T1234", "aliases": []},
                "requires_slice": True,
                "pha_tags": ["SPYWARE"],
                "permission_hints": ["READ_SMS"],
                "signatures": {
                    "methods": [
                        "<android.telephony.SmsManager: void sendTextMessage(java.lang.String)>",
                    ],
                    "fields": [],
                    "strings": [],
                },
            },
        },
    }
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_text(json.dumps(payload), encoding="utf-8")
    return ApiCatalog.load(catalog_path)


def _make_reflection_hit(
    hit_id: str,
    signature: str,
    caller_method: str,
    caller_is_app: bool = False,
) -> dict:
    return {
        "hit_id": hit_id,
        "category_id": "EVASION_REFLECTION",
        "signature": signature,
        "caller": {"method": caller_method},
        "caller_is_app": caller_is_app,
    }


def _make_crypto_hit(hit_id: str, caller_method: str, caller_is_app: bool = False) -> dict:
    return {
        "hit_id": hit_id,
        "category_id": "EVASION_CRYPTO_OBFUSCATION",
        "signature": "<javax.crypto.Cipher: javax.crypto.Cipher getInstance(java.lang.String)>",
        "caller": {"method": caller_method},
        "caller_is_app": caller_is_app,
    }


def test_literal_sensitive_target_kept(tmp_path: Path) -> None:
    catalog = _make_catalog(tmp_path)
    jadx_root = tmp_path / "jadx"
    caller_method = "<com.example.Test: void doIt()>"
    _write_method_source(
        jadx_root,
        "com.example.Test",
        "doIt",
        'Class.forName("android.telephony.SmsManager");',
    )
    hits = {
        "hits": [
            _make_reflection_hit(
                "hit-1",
                "<java.lang.Class: java.lang.Class forName(java.lang.String)>",
                caller_method,
            )
        ],
        "summary": {},
    }
    analysis = analyze_reflection_hits(hits, catalog, jadx_root=jadx_root)
    filtered, suppressed = filter_reflection_hits(hits, analysis, catalog, filter_low_signal=True)

    assert analysis["hit-1"].high_signal is True
    assert analysis["hit-1"].high_signal_reason == "sensitive_target"
    assert analysis["hit-1"].resolved_target == "android.telephony.SmsManager"
    assert len(filtered["hits"]) == 1
    assert suppressed == []


def test_literal_benign_target_dropped(tmp_path: Path) -> None:
    catalog = _make_catalog(tmp_path)
    jadx_root = tmp_path / "jadx"
    caller_method = "<com.example.Test: void doIt()>"
    _write_method_source(
        jadx_root,
        "com.example.Test",
        "doIt",
        'Class.forName("java.util.ArrayList");',
    )
    hits = {
        "hits": [
            _make_reflection_hit(
                "hit-2",
                "<java.lang.Class: java.lang.Class forName(java.lang.String)>",
                caller_method,
            )
        ],
        "summary": {},
    }
    analysis = analyze_reflection_hits(hits, catalog, jadx_root=jadx_root)
    filtered, suppressed = filter_reflection_hits(hits, analysis, catalog, filter_low_signal=True)

    assert analysis["hit-2"].high_signal is False
    assert filtered["summary"]["reflection_suppressed"] == 1
    assert len(filtered["hits"]) == 0
    assert len(suppressed) == 1


def test_chain_with_crypto_kept_without_jadx(tmp_path: Path) -> None:
    catalog = _make_catalog(tmp_path)
    caller_method = "<com.example.Test: void doIt()>"
    hits = {
        "hits": [
            _make_reflection_hit(
                "hit-3",
                "<java.lang.Class: java.lang.Class forName(java.lang.String)>",
                caller_method,
                caller_is_app=True,
            ),
            _make_reflection_hit(
                "hit-4",
                "<java.lang.Class: java.lang.reflect.Method getMethod(java.lang.String,java.lang.Class[])>",
                caller_method,
                caller_is_app=True,
            ),
            _make_reflection_hit(
                "hit-5",
                "<java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])>",
                caller_method,
                caller_is_app=True,
            ),
            _make_crypto_hit("hit-6", caller_method, caller_is_app=True),
        ],
        "summary": {},
    }
    analysis = analyze_reflection_hits(hits, catalog, jadx_root=None)
    filtered, suppressed = filter_reflection_hits(hits, analysis, catalog, filter_low_signal=True)

    assert analysis["hit-3"].high_signal is True
    assert analysis["hit-3"].high_signal_reason == "crypto_chain"
    assert len(filtered["hits"]) == 4
    assert suppressed == []


def test_chain_nonliteral_kept(tmp_path: Path) -> None:
    catalog = _make_catalog(tmp_path)
    jadx_root = tmp_path / "jadx"
    caller_method = "<com.example.Test: void doIt()>"
    _write_method_source(
        jadx_root,
        "com.example.Test",
        "doIt",
        "String name = getName(); Class.forName(name);",
    )
    hits = {
        "hits": [
            _make_reflection_hit(
                "hit-7",
                "<java.lang.Class: java.lang.Class forName(java.lang.String)>",
                caller_method,
                caller_is_app=True,
            ),
            _make_reflection_hit(
                "hit-8",
                "<java.lang.Class: java.lang.reflect.Method getMethod(java.lang.String,java.lang.Class[])>",
                caller_method,
                caller_is_app=True,
            ),
            _make_reflection_hit(
                "hit-9",
                "<java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])>",
                caller_method,
                caller_is_app=True,
            ),
        ],
        "summary": {},
    }
    analysis = analyze_reflection_hits(hits, catalog, jadx_root=jadx_root)
    filtered, suppressed = filter_reflection_hits(hits, analysis, catalog, filter_low_signal=True)

    assert analysis["hit-7"].high_signal is True
    assert analysis["hit-7"].high_signal_reason == "obfuscated_chain"
    assert len(filtered["hits"]) == 3
    assert suppressed == []


def test_no_jadx_literal_sensitive_dropped(tmp_path: Path) -> None:
    catalog = _make_catalog(tmp_path)
    caller_method = "<com.example.Test: void doIt()>"
    hits = {
        "hits": [
            _make_reflection_hit(
                "hit-10",
                "<java.lang.Class: java.lang.Class forName(java.lang.String)>",
                caller_method,
            )
        ],
        "summary": {},
    }
    analysis = analyze_reflection_hits(hits, catalog, jadx_root=None)
    filtered, suppressed = filter_reflection_hits(hits, analysis, catalog, filter_low_signal=True)

    assert analysis["hit-10"].high_signal is False
    assert len(filtered["hits"]) == 0
    assert len(suppressed) == 1


def test_isolated_field_access_dropped(tmp_path: Path) -> None:
    catalog = _make_catalog(tmp_path)
    caller_method = "<com.example.Test: void doIt()>"
    hits = {
        "hits": [
            _make_reflection_hit(
                "hit-11",
                "<java.lang.Class: java.lang.reflect.Field getDeclaredField(java.lang.String)>",
                caller_method,
            )
        ],
        "summary": {},
    }
    analysis = analyze_reflection_hits(hits, catalog, jadx_root=None)
    filtered, suppressed = filter_reflection_hits(hits, analysis, catalog, filter_low_signal=True)

    assert analysis["hit-11"].high_signal is False
    assert len(filtered["hits"]) == 0
    assert len(suppressed) == 1


def test_build_sensitive_targets_from_catalog(tmp_path: Path) -> None:
    catalog = _make_catalog(tmp_path)
    targets = build_sensitive_targets_from_catalog(catalog)

    assert "android.telephony.SmsManager" in targets
    assert "java.lang.Class" not in targets

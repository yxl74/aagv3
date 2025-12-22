from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from apk_analyzer.clients.knox_client import KnoxClient
from apk_analyzer.utils.artifact_store import ArtifactStore
from apk_analyzer.utils.signature_normalize import (
    dex_method_to_soot,
    method_name_from_signature,
    normalize_signature,
)


@dataclass
class ApiCallSite:
    seed_id: str
    category: str
    signature: str
    caller_method: str
    caller_class: str
    callsite_descriptor: Dict[str, Any]
    confidence: float


@dataclass
class SuspiciousApiIndex:
    apk_id: str
    catalog_version: str
    callsites: List[ApiCallSite]


DEX_INVOKE_RE = re.compile(r"(L[^;]+;->[^\s]+\([^)]*\)[^\s]+)")


def _load_catalog(path: str | Path) -> Dict[str, Any]:
    path = Path(path)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _seed_id_for(caller_method: str, signature: str, offset: Any) -> str:
    raw = f"{caller_method}|{signature}|{offset}".encode("utf-8")
    return hashlib.sha1(raw).hexdigest()


def _try_import_androguard():
    try:
        from androguard.misc import AnalyzeAPK  # type: ignore
    except ImportError:  # pragma: no cover - optional dependency
        return None
    return AnalyzeAPK


def _iter_invoke_instructions(apk_path: str | Path) -> Iterable[Tuple[str, str, int]]:
    AnalyzeAPK = _try_import_androguard()
    if AnalyzeAPK is None:
        raise RuntimeError("androguard is required for DEX indexing")
    _, dex_files, _ = AnalyzeAPK(str(apk_path))
    for dex in dex_files:
        for method in _iter_encoded_methods(dex):
            core = _unwrap_method(method)
            if core is None:
                continue
            if hasattr(core, "get_code") and core.get_code() is None:
                continue
            triple = _get_method_triple(core)
            if not triple:
                continue
            caller_class, caller_name, caller_desc = triple
            caller_sig = dex_method_to_soot(caller_class, caller_name, caller_desc)
            for offset, ins in _iter_method_instructions(core):
                try:
                    name = ins.get_name()
                except Exception:
                    continue
                if not name.startswith("invoke-"):
                    continue
                try:
                    output = ins.get_output()
                except Exception:
                    output = ""
                match = DEX_INVOKE_RE.search(output)
                if not match:
                    continue
                callee = match.group(1)
                yield caller_sig, callee, offset


def _iter_encoded_methods(dex: Any) -> Iterable[Any]:
    if hasattr(dex, "get_encoded_methods"):
        return dex.get_encoded_methods() or []
    if hasattr(dex, "get_methods"):
        return dex.get_methods() or []
    return []


def _unwrap_method(method: Any) -> Any:
    if hasattr(method, "get_instructions") and hasattr(method, "get_name"):
        return method
    if hasattr(method, "get_method"):
        try:
            return method.get_method()
        except Exception:
            return None
    return None


def _get_method_triple(method: Any) -> Optional[Tuple[str, str, str]]:
    if hasattr(method, "get_triple"):
        try:
            class_name, name, desc = method.get_triple()
            if class_name and name and desc:
                return class_name, name, desc
        except Exception:
            pass
    try:
        class_name = method.get_class_name()
        name = method.get_name()
        desc = method.get_descriptor()
        if class_name and name and desc:
            return class_name, name, desc
    except Exception:
        return None
    return None


def _iter_method_instructions(method: Any) -> Iterable[Tuple[int, Any]]:
    if hasattr(method, "get_instructions_idx"):
        try:
            for offset, ins in method.get_instructions_idx():
                yield offset, ins
            return
        except Exception:
            pass
    offset = 0
    try:
        instructions = method.get_instructions() or []
    except Exception:
        return
    for ins in instructions:
        yield offset, ins
        try:
            offset += ins.get_length()
        except Exception:
            offset += 0


class DexInvocationIndexer:
    def __init__(self, catalog_path: str | Path) -> None:
        self.catalog_path = Path(catalog_path)
        self.catalog = _load_catalog(self.catalog_path)
        self.signature_index = self._build_signature_index(self.catalog)

    @staticmethod
    def _build_signature_index(catalog: Dict[str, Any]) -> Dict[str, str]:
        index = {}
        for category, info in catalog.get("categories", {}).items():
            for sig in info.get("signatures", []):
                index[normalize_signature(sig)] = category
        return index

    def build_index(
        self,
        apk_id: str,
        apk_path: str | Path | None = None,
        knox_client: Optional[KnoxClient] = None,
        local_search_fn: Optional[Callable[[str, int], List[Dict[str, Any]]]] = None,
        artifact_store: Optional[ArtifactStore] = None,
    ) -> SuspiciousApiIndex:
        callsites: List[ApiCallSite] = []
        if apk_path:
            try:
                for caller_sig, callee_dex_sig, offset in _iter_invoke_instructions(apk_path):
                    callee_sig = normalize_signature(callee_dex_sig)
                    category = self.signature_index.get(callee_sig)
                    if not category:
                        continue
                    seed_id = _seed_id_for(caller_sig, callee_sig, offset)
                    callsites.append(
                        ApiCallSite(
                            seed_id=seed_id,
                            category=category,
                            signature=callee_sig,
                            caller_method=caller_sig,
                            caller_class=caller_sig.split(":", 1)[0].strip("<"),
                            callsite_descriptor={
                                "dex_offset": offset,
                                "invoke": callee_dex_sig,
                            },
                            confidence=1.0,
                        )
                    )
            except RuntimeError:
                pass

        if not callsites and knox_client:
            for sig, category in self.signature_index.items():
                method_name = method_name_from_signature(sig)
                if not method_name or len(method_name) < 3:
                    continue
                hits = knox_client.search_source_code(method_name, limit=10)
                for hit in hits:
                    seed_id = _seed_id_for(method_name, sig, hit.get("file_path"))
                    callsites.append(
                        ApiCallSite(
                            seed_id=seed_id,
                            category=category,
                            signature=sig,
                            caller_method=hit.get("file_path", "UNKNOWN"),
                            caller_class="UNKNOWN",
                            callsite_descriptor={
                                "source_file": hit.get("file_path"),
                                "match": method_name,
                            },
                            confidence=0.4,
                        )
                    )

        if not callsites and local_search_fn:
            for sig, category in self.signature_index.items():
                method_name = method_name_from_signature(sig)
                if not method_name or len(method_name) < 3:
                    continue
                hits = local_search_fn(method_name, 10)
                for hit in hits:
                    seed_id = _seed_id_for(method_name, sig, hit.get("file_path"))
                    callsites.append(
                        ApiCallSite(
                            seed_id=seed_id,
                            category=category,
                            signature=sig,
                            caller_method=hit.get("file_path", "UNKNOWN"),
                            caller_class="UNKNOWN",
                            callsite_descriptor={
                                "source_file": hit.get("file_path"),
                                "match": method_name,
                            },
                            confidence=0.3,
                        )
                    )

        index = SuspiciousApiIndex(
            apk_id=apk_id,
            catalog_version=self.catalog.get("version", "unknown"),
            callsites=callsites,
        )
        if artifact_store:
            artifact_store.write_json(
                "seeds/suspicious_api_index.json",
                {
                    "apk_id": index.apk_id,
                    "catalog_version": index.catalog_version,
                    "callsites": [asdict(site) for site in index.callsites],
                },
            )
        return index

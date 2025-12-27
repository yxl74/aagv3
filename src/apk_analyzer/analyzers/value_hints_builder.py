"""
Value hints builder for Phase 2B execution guidance generation.

Consolidates hints from multiple existing extractors into a structured
ValueHintsBundle that Phase 2B can use to generate accurate commands.

Sources:
- intent_contracts.py: Extra keys, types, value hints
- code_artifacts.py: File paths and log hints from code
- manifest: Intent filters (actions, categories)
- strings from static analysis: URLs, IPs, domains
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


# Regex patterns for extracting strings of interest
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+\b")
_FILE_PATH_RE = re.compile(r"(?:/[a-zA-Z0-9._-]+)+(?:\.[a-zA-Z0-9]+)?")


@dataclass
class IntentExtraHint:
    """Hint about an intent extra and how to provide it."""
    name: str
    type: str
    required: bool = False
    value_hints: List[str] = field(default_factory=list)
    injectable: bool = True  # Can be injected via ADB
    adb_flag: Optional[str] = None  # --es, --ei, etc.


@dataclass
class FileHint:
    """Hint about a file path observed in code."""
    path_hint: str
    resolved_path: Optional[str] = None
    context: str = ""  # Line of code where found


@dataclass
class LogHint:
    """Hint about a log tag/message for verification."""
    tag: str
    message: str
    level: str = "d"


@dataclass
class IntentFilterHint:
    """Intent filter info from manifest."""
    action: Optional[str] = None
    categories: List[str] = field(default_factory=list)
    data_scheme: Optional[str] = None
    data_host: Optional[str] = None


@dataclass
class ValueHintsBundle:
    """
    Consolidated hints for Phase 2B command generation.

    This bundle contains all the extracted information that Phase 2B needs
    to generate accurate, grounded commands.
    """
    component_name: str
    component_type: str

    # Intent extras with type information
    intent_extras: List[IntentExtraHint] = field(default_factory=list)

    # File paths observed in code
    file_hints: List[FileHint] = field(default_factory=list)

    # Log tags for verification
    log_hints: List[LogHint] = field(default_factory=list)

    # Intent filters from manifest
    intent_filters: List[IntentFilterHint] = field(default_factory=list)

    # Strings of interest (URLs, IPs, domains)
    urls: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)

    # Actions available for this component
    actions: List[str] = field(default_factory=list)

    def has_injectable_extras(self) -> bool:
        """Check if there are any injectable extras."""
        return any(e.injectable for e in self.intent_extras)

    def has_required_extras(self) -> bool:
        """Check if there are required extras."""
        return any(e.required for e in self.intent_extras)

    def get_injectable_extras(self) -> List[IntentExtraHint]:
        """Get only the injectable extras."""
        return [e for e in self.intent_extras if e.injectable]

    def get_non_injectable_extras(self) -> List[IntentExtraHint]:
        """Get extras that cannot be injected via ADB."""
        return [e for e in self.intent_extras if not e.injectable]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "component_name": self.component_name,
            "component_type": self.component_type,
            "intent_extras": [
                {
                    "name": e.name,
                    "type": e.type,
                    "required": e.required,
                    "value_hints": e.value_hints,
                    "injectable": e.injectable,
                    "adb_flag": e.adb_flag,
                }
                for e in self.intent_extras
            ],
            "file_hints": [
                {"path_hint": f.path_hint, "resolved_path": f.resolved_path}
                for f in self.file_hints
            ],
            "log_hints": [
                {"tag": l.tag, "message": l.message, "level": l.level}
                for l in self.log_hints
            ],
            "intent_filters": [
                {
                    "action": f.action,
                    "categories": f.categories,
                    "data_scheme": f.data_scheme,
                }
                for f in self.intent_filters
            ],
            "urls": self.urls,
            "ip_addresses": self.ip_addresses,
            "domains": self.domains,
            "actions": self.actions,
        }


# ADB flag mapping for extra types
_EXTRA_TYPE_TO_ADB_FLAG = {
    "string": "--es",
    "string_array": "--esa",
    "int": "--ei",
    "int_array": "--eia",
    "long": "--el",
    "boolean": "--ez",
    "float": "--ef",
    "double": "--ed",
}

_NON_INJECTABLE_TYPES = {"parcelable", "serializable", "unknown", "mixed"}


def build_value_hints(
    component_name: str,
    component_type: str,
    intent_contracts: Optional[Dict[str, Any]] = None,
    file_artifacts: Optional[Dict[str, Any]] = None,
    log_hints: Optional[Dict[str, Any]] = None,
    manifest: Optional[Dict[str, Any]] = None,
    strings_nearby: Optional[List[str]] = None,
    package_name: Optional[str] = None,
) -> ValueHintsBundle:
    """
    Build a ValueHintsBundle from all available sources.

    Args:
        component_name: Full class name of the component
        component_type: Type (service, activity, receiver, etc.)
        intent_contracts: From intent_contracts.extract_intent_contracts()
        file_artifacts: From code_artifacts.extract_file_artifacts()
        log_hints: From code_artifacts.extract_log_hints()
        manifest: Parsed AndroidManifest
        strings_nearby: String literals from static context
        package_name: Package name for path resolution

    Returns:
        ValueHintsBundle with consolidated hints
    """
    bundle = ValueHintsBundle(
        component_name=component_name,
        component_type=component_type,
    )

    # 1. Extract intent extras from contracts
    if intent_contracts:
        contract = intent_contracts.get(component_name, {})
        _extract_intent_extras(bundle, contract)
        bundle.actions = contract.get("actions", [])

    # 2. Extract file hints
    if file_artifacts:
        _extract_file_hints(bundle, file_artifacts, component_name, package_name)

    # 3. Extract log hints
    if log_hints:
        _extract_log_hints(bundle, log_hints, component_name)

    # 4. Extract intent filters from manifest
    if manifest:
        _extract_intent_filters(bundle, manifest, component_name)

    # 5. Extract strings of interest
    if strings_nearby:
        _extract_strings_of_interest(bundle, strings_nearby)

    return bundle


def _extract_intent_extras(bundle: ValueHintsBundle, contract: Dict[str, Any]) -> None:
    """Extract intent extras from contract."""
    for extra in contract.get("extras", []):
        extra_type = extra.get("type", "unknown")
        injectable = extra_type not in _NON_INJECTABLE_TYPES
        adb_flag = _EXTRA_TYPE_TO_ADB_FLAG.get(extra_type) if injectable else None

        hint = IntentExtraHint(
            name=extra.get("name", ""),
            type=extra_type,
            required=extra.get("required", False),
            value_hints=extra.get("value_hints", []),
            injectable=injectable,
            adb_flag=adb_flag,
        )
        bundle.intent_extras.append(hint)


def _extract_file_hints(
    bundle: ValueHintsBundle,
    file_artifacts: Dict[str, Any],
    component_name: str,
    package_name: Optional[str],
) -> None:
    """Extract file hints for component."""
    # Try exact match first
    artifacts = file_artifacts.get(component_name, [])

    # Try outer class if inner class
    if not artifacts and "$" in component_name:
        outer = component_name.split("$")[0]
        artifacts = file_artifacts.get(outer, [])

    for artifact in artifacts:
        path_hint = artifact.get("path_hint", "")
        if not path_hint:
            continue

        resolved = _resolve_path(path_hint, package_name)

        hint = FileHint(
            path_hint=path_hint,
            resolved_path=resolved,
            context=artifact.get("line", "")[:100],
        )
        bundle.file_hints.append(hint)


def _extract_log_hints(
    bundle: ValueHintsBundle,
    log_hints: Dict[str, Any],
    component_name: str,
) -> None:
    """Extract log hints for component."""
    hints = log_hints.get(component_name, [])

    if not hints and "$" in component_name:
        outer = component_name.split("$")[0]
        hints = log_hints.get(outer, [])

    for hint in hints:
        bundle.log_hints.append(LogHint(
            tag=hint.get("tag", ""),
            message=hint.get("message", ""),
            level=hint.get("level", "d"),
        ))


def _extract_intent_filters(
    bundle: ValueHintsBundle,
    manifest: Dict[str, Any],
    component_name: str,
) -> None:
    """Extract intent filters from manifest."""
    # Look up component in manifest
    component_short = component_name.split(".")[-1]

    for comp_type in ["services", "activities", "receivers"]:
        components = manifest.get(comp_type, [])
        for comp in components:
            comp_name = comp.get("name", "")
            if comp_name == component_name or comp_name.endswith(component_short):
                # Found the component, extract intent filters
                for intent_filter in comp.get("intent_filters", []):
                    filter_hint = IntentFilterHint(
                        action=intent_filter.get("action"),
                        categories=intent_filter.get("categories", []),
                        data_scheme=intent_filter.get("data_scheme"),
                        data_host=intent_filter.get("data_host"),
                    )
                    bundle.intent_filters.append(filter_hint)

                    # Add action to actions list
                    if filter_hint.action and filter_hint.action not in bundle.actions:
                        bundle.actions.append(filter_hint.action)


def _extract_strings_of_interest(
    bundle: ValueHintsBundle,
    strings: List[str],
) -> None:
    """Extract URLs, IPs, and domains from strings."""
    seen_urls: Set[str] = set()
    seen_ips: Set[str] = set()
    seen_domains: Set[str] = set()

    for s in strings:
        # URLs
        for match in _URL_RE.findall(s):
            if match not in seen_urls:
                bundle.urls.append(match)
                seen_urls.add(match)

        # IPs
        for match in _IP_RE.findall(s):
            if match not in seen_ips and not _is_version_like(match):
                bundle.ip_addresses.append(match)
                seen_ips.add(match)

        # Domains
        for match in _DOMAIN_RE.findall(s):
            if match not in seen_domains and _is_likely_domain(match):
                bundle.domains.append(match)
                seen_domains.add(match)


def _resolve_path(path_hint: str, package_name: Optional[str]) -> Optional[str]:
    """Resolve path hint to absolute path if possible."""
    if not path_hint:
        return None

    if path_hint.startswith("/"):
        return path_hint

    if not package_name:
        return None

    prefixes = {
        "cacheDir/": f"/data/data/{package_name}/cache/",
        "filesDir/": f"/data/data/{package_name}/files/",
        "externalCacheDir/": f"/sdcard/Android/data/{package_name}/cache/",
        "externalFilesDir/": f"/sdcard/Android/data/{package_name}/files/",
    }

    for prefix, replacement in prefixes.items():
        if path_hint.startswith(prefix):
            return replacement + path_hint[len(prefix):]

    return None


def _is_version_like(ip: str) -> bool:
    """Check if IP-like string is actually a version number."""
    parts = ip.split(".")
    if len(parts) != 4:
        return True  # Not standard IP format
    # Version numbers often have 0 as first octet or very high numbers
    try:
        first = int(parts[0])
        if first == 0 or first > 223:  # Reserved/invalid ranges
            return True
    except ValueError:
        return True
    return False


def _is_likely_domain(s: str) -> bool:
    """Check if string is likely a real domain."""
    # Filter out file extensions and common non-domains
    if s.startswith("."):
        return False
    if s.lower() in {"example.com", "test.com", "localhost.local"}:
        return False
    if len(s) < 4:
        return False
    return True


def build_value_hints_for_seed(
    tier1_output: Dict[str, Any],
    intent_contracts: Optional[Dict[str, Any]] = None,
    file_artifacts: Optional[Dict[str, Any]] = None,
    log_hints: Optional[Dict[str, Any]] = None,
    manifest: Optional[Dict[str, Any]] = None,
    package_name: Optional[str] = None,
) -> ValueHintsBundle:
    """
    Convenience function to build hints directly from Tier1 output.

    Args:
        tier1_output: The Tier1 summarizer output for a seed
        intent_contracts: From intent_contracts.extract_intent_contracts()
        file_artifacts: From code_artifacts.extract_file_artifacts()
        log_hints: From code_artifacts.extract_log_hints()
        manifest: Parsed AndroidManifest
        package_name: Package name for path resolution

    Returns:
        ValueHintsBundle with consolidated hints
    """
    trigger = tier1_output.get("trigger_surface", {})
    component_name = trigger.get("component_name", "")
    component_type = trigger.get("component_type", "Unknown").lower()

    # Get strings from static context if available
    static_context = tier1_output.get("static_context", {})
    strings_nearby = static_context.get("strings_nearby", [])

    return build_value_hints(
        component_name=component_name,
        component_type=component_type,
        intent_contracts=intent_contracts,
        file_artifacts=file_artifacts,
        log_hints=log_hints,
        manifest=manifest,
        strings_nearby=strings_nearby,
        package_name=package_name,
    )

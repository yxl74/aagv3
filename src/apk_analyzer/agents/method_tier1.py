"""Method-level Tier1 analysis module.

This module implements the method-centric analysis pipeline:
- Analyze each unique method ONCE with JADX source
- Cache results for reuse across seeds sharing the same methods
- Parallelizable method analysis

Key classes:
- MethodAnalysis: Tier1 analysis result for a single method
- MethodTier1Agent: Agent for analyzing individual methods
- MethodAnalysisCache: Disk-based cache for method analyses
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from apk_analyzer.agents.base import LLMClient
from apk_analyzer.analyzers.jadx_extractors import (
    extract_jimple_ir,
    extract_method_source,
    format_jimple_for_llm,
)
from apk_analyzer.observability.logger import EventLogger
from apk_analyzer.utils.llm_json import coerce_llm_dict, parse_llm_json


@dataclass
class MethodAnalysis:
    """Tier1 analysis for a single method.

    Represents the LLM's understanding of what a method does,
    independent of any particular seed or sink API.
    """

    method_sig: str

    # Source availability
    jadx_available: bool = True  # False if JADX extraction failed
    jimple_available: bool = False  # True if Jimple IR was extracted

    # Source content (stored for reference/debugging)
    jadx_source: Optional[str] = None  # Decompiled Java source
    jimple_ir: Optional[Dict[str, Any]] = None  # Structured Jimple IR

    # Extraction metadata for CFG alignment
    source_file: Optional[str] = None  # Exact .java file used
    lookup_strategy: str = "unknown"  # How source was obtained
    delegate_to: Optional[str] = None  # For synthetic forwarders

    # Analysis results
    function_summary: str = ""
    path_constraints: List[Dict[str, Any]] = field(default_factory=list)
    required_inputs: List[Dict[str, Any]] = field(default_factory=list)
    data_flow: List[str] = field(default_factory=list)
    trigger_info: Optional[Dict[str, Any]] = None
    facts: List[Dict[str, Any]] = field(default_factory=list)
    uncertainties: List[str] = field(default_factory=list)
    confidence: float = 0.5

    @classmethod
    def placeholder(
        cls,
        method_sig: str,
        jimple_ir: Optional[Dict[str, Any]] = None,
        lookup_strategy: str = "not_found",
    ) -> "MethodAnalysis":
        """Create placeholder for methods without JADX source.

        Args:
            method_sig: Method signature
            jimple_ir: Optional Jimple IR as fallback
            lookup_strategy: How the source lookup was attempted
        """
        if jimple_ir:
            # We have Jimple IR as backup
            invoked = jimple_ir.get("invoked_methods", [])
            summary = f"Analysis based on Jimple IR ({jimple_ir.get('unit_count', 0)} units)"
            if invoked:
                summary += f". Invokes: {', '.join(invoked[:3])}"
                if len(invoked) > 3:
                    summary += f" and {len(invoked) - 3} more"
            return cls(
                method_sig=method_sig,
                jadx_available=False,
                jimple_available=True,
                jimple_ir=jimple_ir,
                lookup_strategy=lookup_strategy,
                function_summary=summary,
                uncertainties=["Analysis based on Jimple IR, not decompiled Java"],
                confidence=0.3,  # Lower confidence for Jimple-only
            )
        else:
            return cls(
                method_sig=method_sig,
                jadx_available=False,
                jimple_available=False,
                lookup_strategy=lookup_strategy,
                function_summary="Unable to analyze - no source available",
                uncertainties=["Neither JADX nor Jimple IR available for this method"],
                confidence=0.0,
            )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MethodAnalysis":
        """Create from dict (for cache loading)."""
        return cls(**data)


# Required keys in LLM response
METHOD_ANALYSIS_KEYS = (
    "function_summary",
    "path_constraints",
    "required_inputs",
    "data_flow",
    "facts",
    "uncertainties",
    "confidence",
)


class MethodTier1Agent:
    """Agent for analyzing individual methods with JADX source."""

    def __init__(
        self,
        prompt_path: Path,
        llm_client: Optional[LLMClient] = None,
        model: Optional[str] = None,
        event_logger: Optional[EventLogger] = None,
    ) -> None:
        self.prompt_path = prompt_path
        self.llm_client = llm_client
        self.model = model
        self.event_logger = event_logger
        self.prompt = prompt_path.read_text(encoding="utf-8") if prompt_path.exists() else ""

    def _make_fallback(self, method_sig: str, reason: str) -> MethodAnalysis:
        """Create fallback analysis when LLM fails."""
        return MethodAnalysis(
            method_sig=method_sig,
            jadx_available=True,  # We had source, LLM just failed
            function_summary=f"Analysis failed: {reason}",
            uncertainties=[f"LLM analysis failed: {reason}"],
            confidence=0.0,
        )

    def analyze(
        self,
        method_sig: str,
        jadx_source: Optional[str] = None,
        jimple_ir: Optional[Dict[str, Any]] = None,
        cfg: Optional[Dict[str, Any]] = None,
    ) -> MethodAnalysis:
        """Analyze a single method with available source representations.

        Args:
            method_sig: Soot method signature
            jadx_source: Decompiled Java source code (optional)
            jimple_ir: Jimple IR from CFG (optional, used as fallback/supplement)
            cfg: Optional CFG data for the method

        Returns:
            MethodAnalysis with extracted information
        """
        has_jadx = jadx_source is not None
        has_jimple = jimple_ir is not None

        # Determine lookup strategy
        if has_jadx and has_jimple:
            lookup_strategy = "jadx_with_jimple"
        elif has_jadx:
            lookup_strategy = "jadx"
        elif has_jimple:
            lookup_strategy = "jimple_only"
        else:
            lookup_strategy = "not_found"

        if not self.llm_client:
            if self.event_logger:
                self.event_logger.log(
                    "llm.fallback",
                    llm_step="method_tier1",
                    method_sig=method_sig,
                    error_type="disabled",
                )
            return self._make_fallback(method_sig, "LLM disabled")

        # Build payload with available sources
        payload: Dict[str, Any] = {
            "method_sig": method_sig,
        }

        if jadx_source:
            payload["jadx_source"] = jadx_source

        if jimple_ir:
            # Format Jimple for LLM if no JADX, or include as supplement
            payload["jimple_ir"] = format_jimple_for_llm(jimple_ir, method_sig)
            payload["jimple_invokes"] = jimple_ir.get("invoked_methods", [])

        if cfg:
            payload["cfg"] = cfg

        # If no source at all, return placeholder
        if not has_jadx and not has_jimple:
            return MethodAnalysis.placeholder(method_sig, lookup_strategy=lookup_strategy)

        response = self.llm_client.complete(self.prompt, payload, model=self.model)
        data = parse_llm_json(response)

        if not isinstance(data, dict) or data.get("_error"):
            if self.event_logger:
                self.event_logger.log(
                    "llm.fallback",
                    llm_step="method_tier1",
                    method_sig=method_sig,
                    error_type="invalid_json",
                )
            return self._make_fallback(method_sig, "invalid JSON response")

        # Coerce to valid structure
        fallback_dict = self._make_fallback(method_sig, "missing required keys").to_dict()
        result_dict = coerce_llm_dict(data, fallback_dict, required_keys=METHOD_ANALYSIS_KEYS)

        # Adjust confidence based on source quality
        base_confidence = result_dict.get("confidence", 0.5)
        if not has_jadx and has_jimple:
            # Lower confidence for Jimple-only analysis
            base_confidence = min(base_confidence, 0.7)

        # Build MethodAnalysis
        return MethodAnalysis(
            method_sig=method_sig,
            jadx_available=has_jadx,
            jimple_available=has_jimple,
            jadx_source=jadx_source,
            jimple_ir=jimple_ir,
            lookup_strategy=lookup_strategy,
            function_summary=result_dict.get("function_summary", ""),
            path_constraints=result_dict.get("path_constraints", []),
            required_inputs=result_dict.get("required_inputs", []),
            data_flow=result_dict.get("data_flow", []),
            trigger_info=result_dict.get("trigger_info"),
            facts=result_dict.get("facts", []),
            uncertainties=result_dict.get("uncertainties", []),
            confidence=base_confidence,
        )


class MethodAnalysisCache:
    """Disk-based cache for method analyses.

    Stores analyses as JSON files keyed by method signature hash.
    Enables cross-run reuse of method analyses.
    """

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._memory_cache: Dict[str, MethodAnalysis] = {}

    def _hash_method(self, method_sig: str) -> str:
        """Generate cache key from method signature."""
        return hashlib.sha256(method_sig.encode()).hexdigest()[:16]

    def _cache_path(self, method_sig: str) -> Path:
        """Get cache file path for a method."""
        return self.cache_dir / f"{self._hash_method(method_sig)}.json"

    def get(self, method_sig: str) -> Optional[MethodAnalysis]:
        """Get cached analysis if available."""
        # Check memory cache first
        if method_sig in self._memory_cache:
            return self._memory_cache[method_sig]

        # Check disk cache
        cache_file = self._cache_path(method_sig)
        if cache_file.exists():
            try:
                data = json.loads(cache_file.read_text(encoding="utf-8"))
                analysis = MethodAnalysis.from_dict(data)
                self._memory_cache[method_sig] = analysis
                return analysis
            except (json.JSONDecodeError, KeyError, TypeError):
                # Corrupted cache, ignore
                pass

        return None

    def put(self, analysis: MethodAnalysis) -> None:
        """Store analysis in cache."""
        self._memory_cache[analysis.method_sig] = analysis

        # Write to disk
        cache_file = self._cache_path(analysis.method_sig)
        cache_file.write_text(
            json.dumps(analysis.to_dict(), indent=2),
            encoding="utf-8",
        )

    def has(self, method_sig: str) -> bool:
        """Check if method is in cache."""
        return method_sig in self._memory_cache or self._cache_path(method_sig).exists()


def collect_unique_methods(seeds: List[Dict[str, Any]]) -> Set[str]:
    """Extract all unique app methods from seed paths.

    Filters out framework APIs (android.*, java.*, javax.*) since
    those are sink APIs, not app methods to analyze.

    Args:
        seeds: List of seed dicts with control_flow_path

    Returns:
        Set of unique method signatures
    """
    unique_methods: Set[str] = set()
    framework_prefixes = ("<android.", "<java.", "<javax.", "<dalvik.")

    for seed in seeds:
        control_flow_path = seed.get("control_flow_path", {})
        path_methods = control_flow_path.get("path_methods", [])

        for method in path_methods:
            # Skip framework sink APIs
            if not any(method.startswith(prefix) for prefix in framework_prefixes):
                unique_methods.add(method)

    return unique_methods


@dataclass
class SourceExtractionResult:
    """Result of source extraction for a method."""

    method_sig: str
    jadx_source: Optional[str] = None
    jimple_ir: Optional[Dict[str, Any]] = None
    lookup_strategy: str = "not_found"

    @property
    def has_any_source(self) -> bool:
        """True if either JADX or Jimple is available."""
        return self.jadx_source is not None or self.jimple_ir is not None


def batch_extract_sources(
    methods: Set[str],
    jadx_root: Optional[Path],
    cfg_dir: Optional[Path],
    max_lines: int = 100,
    max_chars: int = 5000,
) -> Dict[str, SourceExtractionResult]:
    """Extract both JADX source and Jimple IR for all methods.

    Args:
        methods: Set of method signatures
        jadx_root: JADX output directory (optional)
        cfg_dir: CFG directory for Jimple IR (optional)
        max_lines: Max lines per JADX method
        max_chars: Max chars per JADX method

    Returns:
        Dict mapping method_sig -> SourceExtractionResult
    """
    results: Dict[str, SourceExtractionResult] = {}

    for method_sig in methods:
        jadx_source = None
        jimple_ir = None
        strategy = "not_found"

        # Try JADX first
        if jadx_root:
            jadx_source = extract_method_source(jadx_root, method_sig, max_lines, max_chars)
            if jadx_source:
                strategy = "jadx"

        # Always try Jimple IR as backup/supplement
        if cfg_dir:
            jimple_ir = extract_jimple_ir(cfg_dir, method_sig)
            if jimple_ir and not jadx_source:
                strategy = "jimple_only"
            elif jimple_ir and jadx_source:
                strategy = "jadx_with_jimple"

        results[method_sig] = SourceExtractionResult(
            method_sig=method_sig,
            jadx_source=jadx_source,
            jimple_ir=jimple_ir,
            lookup_strategy=strategy,
        )

    return results


def batch_extract_jadx_sources(
    methods: Set[str],
    jadx_root: Path,
    max_lines: int = 100,
    max_chars: int = 5000,
) -> Dict[str, str]:
    """Extract JADX source for all methods (legacy interface).

    Args:
        methods: Set of method signatures
        jadx_root: JADX output directory
        max_lines: Max lines per method
        max_chars: Max chars per method

    Returns:
        Dict mapping method_sig -> JADX source (only for successful extractions)
    """
    sources: Dict[str, str] = {}

    for method_sig in methods:
        source = extract_method_source(jadx_root, method_sig, max_lines, max_chars)
        if source:
            sources[method_sig] = source

    return sources


async def analyze_methods_parallel(
    methods_with_sources: Dict[str, str],
    agent: MethodTier1Agent,
    cache: MethodAnalysisCache,
    cfgs: Optional[Dict[str, Dict[str, Any]]] = None,
    max_concurrent: int = 10,
) -> Dict[str, MethodAnalysis]:
    """Analyze all methods in parallel.

    Args:
        methods_with_sources: Dict of method_sig -> JADX source
        agent: MethodTier1Agent instance
        cache: MethodAnalysisCache for storing results
        cfgs: Optional dict of method_sig -> CFG data
        max_concurrent: Max concurrent LLM calls

    Returns:
        Dict of method_sig -> MethodAnalysis
    """
    results: Dict[str, MethodAnalysis] = {}
    cfgs = cfgs or {}

    # First, check cache for all methods
    methods_to_analyze: Dict[str, str] = {}
    for method_sig, source in methods_with_sources.items():
        cached = cache.get(method_sig)
        if cached:
            results[method_sig] = cached
        else:
            methods_to_analyze[method_sig] = source

    if not methods_to_analyze:
        return results

    # Analyze remaining methods with semaphore for concurrency control
    semaphore = asyncio.Semaphore(max_concurrent)

    async def analyze_one(method_sig: str, source: str) -> MethodAnalysis:
        async with semaphore:
            # Run sync analysis in thread pool
            loop = asyncio.get_event_loop()
            cfg = cfgs.get(method_sig)
            analysis = await loop.run_in_executor(
                None,
                agent.analyze,
                method_sig,
                source,
                cfg,
            )
            cache.put(analysis)
            return analysis

    # Run all analyses
    tasks = [
        analyze_one(method_sig, source)
        for method_sig, source in methods_to_analyze.items()
    ]
    analyses = await asyncio.gather(*tasks)

    for analysis in analyses:
        results[analysis.method_sig] = analysis

    return results


def analyze_methods_sync(
    methods_with_sources: Dict[str, str],
    agent: MethodTier1Agent,
    cache: MethodAnalysisCache,
    cfgs: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, MethodAnalysis]:
    """Analyze all methods synchronously (legacy interface).

    Args:
        methods_with_sources: Dict of method_sig -> JADX source
        agent: MethodTier1Agent instance
        cache: MethodAnalysisCache for storing results
        cfgs: Optional dict of method_sig -> CFG data

    Returns:
        Dict of method_sig -> MethodAnalysis
    """
    results: Dict[str, MethodAnalysis] = {}
    cfgs = cfgs or {}

    for method_sig, source in methods_with_sources.items():
        # Check cache first
        cached = cache.get(method_sig)
        if cached:
            results[method_sig] = cached
            continue

        # Analyze and cache
        cfg = cfgs.get(method_sig)
        analysis = agent.analyze(method_sig, jadx_source=source, cfg=cfg)
        cache.put(analysis)
        results[method_sig] = analysis

    return results


def analyze_methods_with_sources(
    extraction_results: Dict[str, SourceExtractionResult],
    agent: MethodTier1Agent,
    cache: MethodAnalysisCache,
) -> Dict[str, MethodAnalysis]:
    """Analyze all methods using dual JADX+Jimple sources.

    Args:
        extraction_results: Dict of method_sig -> SourceExtractionResult
        agent: MethodTier1Agent instance
        cache: MethodAnalysisCache for storing results

    Returns:
        Dict of method_sig -> MethodAnalysis
    """
    results: Dict[str, MethodAnalysis] = {}

    for method_sig, extraction in extraction_results.items():
        # Check cache first
        cached = cache.get(method_sig)
        if cached:
            results[method_sig] = cached
            continue

        # Analyze with both JADX and Jimple when available
        analysis = agent.analyze(
            method_sig=method_sig,
            jadx_source=extraction.jadx_source,
            jimple_ir=extraction.jimple_ir,
        )
        cache.put(analysis)
        results[method_sig] = analysis

    return results

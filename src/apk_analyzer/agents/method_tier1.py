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
from apk_analyzer.analyzers.jadx_extractors import extract_method_source
from apk_analyzer.observability.logger import EventLogger
from apk_analyzer.utils.llm_json import coerce_llm_dict, parse_llm_json


@dataclass
class MethodAnalysis:
    """Tier1 analysis for a single method.

    Represents the LLM's understanding of what a method does,
    independent of any particular seed or sink API.
    """

    method_sig: str
    jadx_available: bool = True  # False if JADX extraction failed
    function_summary: str = ""
    path_constraints: List[Dict[str, Any]] = field(default_factory=list)
    required_inputs: List[Dict[str, Any]] = field(default_factory=list)
    data_flow: List[str] = field(default_factory=list)
    trigger_info: Optional[Dict[str, Any]] = None
    facts: List[Dict[str, Any]] = field(default_factory=list)
    uncertainties: List[str] = field(default_factory=list)
    confidence: float = 0.5

    @classmethod
    def placeholder(cls, method_sig: str) -> "MethodAnalysis":
        """Create placeholder for methods without JADX source."""
        return cls(
            method_sig=method_sig,
            jadx_available=False,
            function_summary="Unable to analyze - no JADX source available",
            uncertainties=["JADX decompilation not available for this method"],
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
        jadx_source: str,
        cfg: Optional[Dict[str, Any]] = None,
    ) -> MethodAnalysis:
        """Analyze a single method with its JADX source.

        Args:
            method_sig: Soot method signature
            jadx_source: Decompiled Java source code
            cfg: Optional CFG data for the method

        Returns:
            MethodAnalysis with extracted information
        """
        if not self.llm_client:
            if self.event_logger:
                self.event_logger.log(
                    "llm.fallback",
                    llm_step="method_tier1",
                    method_sig=method_sig,
                    error_type="disabled",
                )
            return self._make_fallback(method_sig, "LLM disabled")

        payload = {
            "method_sig": method_sig,
            "jadx_source": jadx_source,
        }
        if cfg:
            payload["cfg"] = cfg

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

        # Build MethodAnalysis
        return MethodAnalysis(
            method_sig=method_sig,
            jadx_available=True,
            function_summary=result_dict.get("function_summary", ""),
            path_constraints=result_dict.get("path_constraints", []),
            required_inputs=result_dict.get("required_inputs", []),
            data_flow=result_dict.get("data_flow", []),
            trigger_info=result_dict.get("trigger_info"),
            facts=result_dict.get("facts", []),
            uncertainties=result_dict.get("uncertainties", []),
            confidence=result_dict.get("confidence", 0.5),
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


def batch_extract_jadx_sources(
    methods: Set[str],
    jadx_root: Path,
    max_lines: int = 100,
    max_chars: int = 5000,
) -> Dict[str, str]:
    """Extract JADX source for all methods.

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
    """Analyze all methods synchronously (for non-async contexts).

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
        analysis = agent.analyze(method_sig, source, cfg)
        cache.put(analysis)
        results[method_sig] = analysis

    return results

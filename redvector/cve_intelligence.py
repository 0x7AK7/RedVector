#!/usr/bin/env python3
"""
RedVector AI - CVE Intelligence and Vulnerability-Correlation Primitives

This module is RedVector's own implementation of the CVE-intelligence and
vulnerability-correlation building blocks used by ``redvector_server.py``
(Phase 1 Item 3 of the RedVector Independence Remediation Plan). It replaces
the "CVEIntelligenceManager" / "VulnerabilityCorrelator" classes that module
used to define inline with a small set of independently-testable, composable
pieces:

CVE intelligence:
- ``FeedFetchResult``        a plain (success, data, error) result, so
                              callers never need to know about raw HTTP
                              response objects
- ``CVEFeedClient`` (Protocol) + ``NvdCVEFeedClient``
                              CVE-record retrieval from NVD, no scoring
- ``ExploitFeedClient`` (Protocol) + ``GitHubExploitFeedClient``
                              exploit/PoC reference retrieval from GitHub -
                              a different upstream and record shape, so a
                              separate protocol from CVEFeedClient
- ``CVERecord``               the stable, normalized CVE model
- ``CVERecordNormalizer``     raw NVD JSON -> CVERecord, deterministic
- ``ExploitabilityAssessment`` + ``CVERiskScorer``
                              pure risk/exploitability scoring, no I/O
- ``CVECacheAdapter``         optional thin wrapper around an injected
                              cache object (e.g. RedVector's Phase 1.7
                              AdvancedCache) - disabled by default so the
                              compatibility adapter's behavior matches the
                              original exactly (which never cached CVE
                              lookups at all)
- ``CVEIntelligenceService``  thin orchestration: feed -> normalize ->
                              score -> shape into the response dicts the
                              routes expect

Vulnerability correlation:
- ``VulnerabilityRecord``     the stable vulnerability-candidate model
- ``VulnerabilitySource`` (Protocol) + ``MockVulnerabilitySource``
                              candidate-vulnerability retrieval for one
                              (software, attack-pattern) pair - the mock
                              implementation preserves the original's own
                              documented placeholder behavior exactly
- ``CorrelationStrategy`` (Protocol) + ``PatternBasedCorrelationStrategy``
                              finds candidates for one attack-chain stage
- ``VulnerabilityCorrelationEngine``
                              applies every registered stage strategy,
                              no network calls, no route-specific code
- ``AttackChainStage`` / ``AttackChain``
                              the externally-expected attack-chain shape
- ``AttackPathBuilder``       turns correlation results into AttackChains -
                              separate from the correlation logic itself
- ``AttackChainRecommender``  the human-readable recommendation summary
- ``VulnerabilityCorrelationService``
                              thin orchestration tying the above together

Design goals, matching Phase 1 Items 1/2's precedent:
  * composition over monolithic "manager" classes.
  * registries/strategies instead of if/elif chains, wherever that doesn't
    change behavior.
  * deterministic, I/O-free scoring and correlation logic, independently
    testable without touching the network.
  * nothing here silently changes behavior: CVSS-extraction fallback
    chains, scoring formulas, keyword lists and the original's own
    documented placeholder/mock data are all carried over exactly -
    including a genuine inconsistency between the original's two CVSS
    extraction paths (see CVERecordNormalizer's docstring), which is
    preserved deliberately, not "fixed".

``redvector_server.py`` adapts its existing public names
(``CVEIntelligenceManager``, ``VulnerabilityCorrelator``) onto these
primitives via thin compatibility wrappers, so every existing caller,
route and test keeps working unchanged.
"""

from __future__ import annotations

import logging
import time as _time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Protocol

try:
    import requests as _requests
except ImportError:  # pragma: no cover - requests is a hard runtime dependency
    _requests = None

_log = logging.getLogger(__name__)


# ============================================================================
# FeedFetchResult
# ============================================================================

@dataclass
class FeedFetchResult:
    """Outcome of one feed-client call: success/data, or a reason it
    failed. Callers never see a raw HTTP response object."""
    success: bool
    status_code: Optional[int] = None
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# ============================================================================
# CVEFeedClient (Protocol) + NvdCVEFeedClient
# ============================================================================

class CVEFeedClient(Protocol):
    """Abstraction for retrieving raw CVE records from an upstream feed.
    No scoring, no normalization, no caching - just data retrieval, so it
    can be swapped out (or faked in tests) independently of everything
    that interprets its results.
    """

    def fetch_recent(
        self, start: datetime, end: datetime,
        severity_filter: Optional[str] = None, results_per_page: int = 100,
        rate_limit_delay: float = 0.0,
    ) -> FeedFetchResult:
        ...

    def fetch_by_id(self, cve_id: str, rate_limit_delay: float = 0.0) -> FeedFetchResult:
        ...


class NvdCVEFeedClient:
    """CVEFeedClient backed by the real NVD CVE 2.0 REST API.

    ``rate_limit_delay`` lets a caller ask for a courtesy sleep before the
    request (the original code slept 6s before its "broader search"
    fallback call, and 1s before its secondary lookups during exploit
    search) - the feed client owns the actual sleep call so it stays
    injectable/testable, but the orchestration layer decides the delay.
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    DEFAULT_TIMEOUT = 30

    def __init__(
        self,
        http_get: Optional[Callable[..., Any]] = None,
        base_url: Optional[str] = None,
        sleep: Optional[Callable[[float], None]] = None,
    ):
        # Captured by reference, not bound at construction time: an
        # explicit override is stored as given, but the default looks up
        # ``_requests.get`` freshly on every call (see ``_get``) so that
        # monkeypatching ``requests.get`` after this client is constructed
        # - e.g. in tests, or because the module-level ``cve_intelligence``
        # global is built once at import time - still takes effect.
        self._http_get = http_get
        self._base_url = base_url or self.BASE_URL
        self._sleep = sleep  # None -> resolved to _time.sleep fresh per call

    def fetch_recent(
        self, start: datetime, end: datetime,
        severity_filter: Optional[str] = None, results_per_page: int = 100,
        rate_limit_delay: float = 0.0,
    ) -> FeedFetchResult:
        params: Dict[str, Any] = {
            "lastModStartDate": _format_nvd_date(start),
            "lastModEndDate": _format_nvd_date(end),
            "resultsPerPage": results_per_page,
        }
        if severity_filter:
            params["cvssV3Severity"] = severity_filter
        return self._get(params, rate_limit_delay)

    def fetch_by_id(self, cve_id: str, rate_limit_delay: float = 0.0) -> FeedFetchResult:
        return self._get({"cveId": cve_id}, rate_limit_delay)

    def _get(self, params: Dict[str, Any], rate_limit_delay: float) -> FeedFetchResult:
        if rate_limit_delay > 0:
            (self._sleep or _time.sleep)(rate_limit_delay)
        http_get = self._http_get or (_requests.get if _requests is not None else None)
        if http_get is None:
            return FeedFetchResult(success=False, error="HTTP client unavailable")
        try:
            response = http_get(self._base_url, params=params, timeout=self.DEFAULT_TIMEOUT)
            if response.status_code != 200:
                return FeedFetchResult(success=False, status_code=response.status_code,
                                        error=f"HTTP {response.status_code}")
            return FeedFetchResult(success=True, status_code=200, data=response.json())
        except Exception as exc:  # noqa: BLE001 - network errors are data, not a crash
            return FeedFetchResult(success=False, error=str(exc))


def _format_nvd_date(dt: datetime) -> str:
    return dt.strftime('%Y-%m-%dT%H:%M:%S.000')


# ============================================================================
# ExploitFeedClient (Protocol) + GitHubExploitFeedClient
# ============================================================================

class ExploitFeedClient(Protocol):
    """Abstraction for retrieving exploit/PoC references from upstream
    code-hosting feeds (GitHub). A different upstream and a different
    kind of record than CVEFeedClient, so it gets its own protocol."""

    def search_repositories(self, query: str, per_page: int = 10) -> FeedFetchResult:
        ...

    def search_code(self, query: str, per_page: int = 5) -> FeedFetchResult:
        ...


class GitHubExploitFeedClient:
    """ExploitFeedClient backed by the GitHub Search API."""

    REPO_SEARCH_URL = "https://api.github.com/search/repositories"
    CODE_SEARCH_URL = "https://api.github.com/search/code"
    DEFAULT_TIMEOUT = 15

    def __init__(self, http_get: Optional[Callable[..., Any]] = None):
        # See NvdCVEFeedClient's constructor docstring for why this is not
        # resolved to a bound function here.
        self._http_get = http_get

    def search_repositories(self, query: str, per_page: int = 10) -> FeedFetchResult:
        return self._search(self.REPO_SEARCH_URL, {
            "q": query, "sort": "updated", "order": "desc", "per_page": per_page,
        })

    def search_code(self, query: str, per_page: int = 5) -> FeedFetchResult:
        return self._search(self.CODE_SEARCH_URL, {"q": query, "per_page": per_page})

    def _search(self, url: str, params: Dict[str, Any]) -> FeedFetchResult:
        http_get = self._http_get or (_requests.get if _requests is not None else None)
        if http_get is None:
            return FeedFetchResult(success=False, error="HTTP client unavailable")
        try:
            response = http_get(url, params=params, timeout=self.DEFAULT_TIMEOUT)
            if response.status_code != 200:
                return FeedFetchResult(success=False, status_code=response.status_code,
                                        error=f"HTTP {response.status_code}")
            return FeedFetchResult(success=True, status_code=200, data=response.json())
        except Exception as exc:  # noqa: BLE001
            return FeedFetchResult(success=False, error=str(exc))


# ============================================================================
# CVERecord + CVERecordNormalizer
# ============================================================================

@dataclass
class CVERecord:
    """RedVector's stable CVE model - what every downstream consumer
    (scorer, response-shaping code) actually works with, independent of
    NVD's own JSON structure."""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    published_date: str
    last_modified: str
    affected_software: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    source: str = "NVD"
    attack_vector: str = "UNKNOWN"
    attack_complexity: str = "UNKNOWN"
    privileges_required: str = "UNKNOWN"
    user_interaction: str = "UNKNOWN"
    exploitability_subscore: float = 0.0


class CVERecordNormalizer:
    """Converts one raw NVD API vulnerability item into a CVERecord.

    Deterministic, no I/O. Preserves a genuine inconsistency in the
    original code rather than silently fixing it: the "recent CVEs" path
    tried CVSS v3.1, then v3.0, then v2 (mapping the v2 base score to a
    severity band itself) for score+severity, while the "exploitability
    analysis" path only ever tried v3.1 then v3.0 - a CVE with only CVSS
    v2 data got a real severity/score from the first path but
    UNKNOWN/0.0 from the second. ``include_cvss_v2_fallback`` reproduces
    that exact difference; the attack-vector/complexity/privileges/
    user-interaction/exploitability-subscore fields were never sourced
    from v2 in either original path, so they have no such flag.
    """

    REFERENCES_LIMIT = 5
    CPE_LIMIT = 3
    AFFECTED_SOFTWARE_LIMIT = 5

    def normalize(self, raw_item: Dict[str, Any], include_cvss_v2_fallback: bool = True) -> CVERecord:
        cve_data = raw_item.get("cve", {})
        metrics = cve_data.get("metrics", {})

        cvss_score, severity, detail_fields = self._extract_cvss(metrics, include_cvss_v2_fallback)
        description = self._extract_description(cve_data.get("descriptions", []))
        references = self._extract_references(cve_data.get("references", []))
        affected_software = self._extract_affected_software(cve_data.get("configurations", []))

        return CVERecord(
            cve_id=cve_data.get("id", "Unknown"),
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            published_date=cve_data.get("published", ""),
            last_modified=cve_data.get("lastModified", ""),
            affected_software=affected_software[: self.AFFECTED_SOFTWARE_LIMIT],
            references=references,
            source="NVD",
            **detail_fields,
        )

    @classmethod
    def _extract_cvss(cls, metrics: Dict[str, Any], include_cvss_v2_fallback: bool):
        detail_fields = {
            "attack_vector": "UNKNOWN", "attack_complexity": "UNKNOWN",
            "privileges_required": "UNKNOWN", "user_interaction": "UNKNOWN",
            "exploitability_subscore": 0.0,
        }

        if metrics.get("cvssMetricV31"):
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            return (
                cvss_data.get("baseScore", 0.0), cvss_data.get("baseSeverity", "UNKNOWN").upper(),
                {
                    "attack_vector": cvss_data.get("attackVector", "UNKNOWN"),
                    "attack_complexity": cvss_data.get("attackComplexity", "UNKNOWN"),
                    "privileges_required": cvss_data.get("privilegesRequired", "UNKNOWN"),
                    "user_interaction": cvss_data.get("userInteraction", "UNKNOWN"),
                    "exploitability_subscore": cvss_data.get("exploitabilityScore", 0.0),
                },
            )

        if metrics.get("cvssMetricV30"):
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            return (
                cvss_data.get("baseScore", 0.0), cvss_data.get("baseSeverity", "UNKNOWN").upper(),
                {
                    "attack_vector": cvss_data.get("attackVector", "UNKNOWN"),
                    "attack_complexity": cvss_data.get("attackComplexity", "UNKNOWN"),
                    "privileges_required": cvss_data.get("privilegesRequired", "UNKNOWN"),
                    "user_interaction": cvss_data.get("userInteraction", "UNKNOWN"),
                    "exploitability_subscore": cvss_data.get("exploitabilityScore", 0.0),
                },
            )

        if include_cvss_v2_fallback and metrics.get("cvssMetricV2"):
            cvss_score = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore", 0.0)
            severity = cls._v2_score_to_severity(cvss_score)
            return cvss_score, severity, detail_fields

        return 0.0, "UNKNOWN", detail_fields

    @staticmethod
    def _v2_score_to_severity(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _extract_description(descriptions: List[Dict[str, Any]]) -> str:
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "No description available")
        return "No description available"

    @classmethod
    def _extract_references(cls, ref_data: List[Dict[str, Any]]) -> List[str]:
        return [ref.get("url", "") for ref in ref_data[: cls.REFERENCES_LIMIT]]

    @classmethod
    def _extract_affected_software(cls, configurations: List[Dict[str, Any]]) -> List[str]:
        affected = []
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", [])[: cls.CPE_LIMIT]:
                    cpe_name = cpe.get("criteria", "")
                    if cpe_name.startswith("cpe:2.3:"):
                        parts = cpe_name.split(":")
                        if len(parts) >= 6:
                            vendor, product = parts[3], parts[4]
                            version = parts[5] if parts[5] != "*" else "all versions"
                            affected.append(f"{vendor} {product} {version}")
        return affected


# ============================================================================
# ExploitabilityAssessment + CVERiskScorer
# ============================================================================

@dataclass
class ExploitabilityAssessment:
    """RedVector's own risk/exploitability verdict for a CVERecord.

    ``exploitability_score`` is rounded to 2 decimal places (matching the
    original's own "exploitability_score" output field); ``raw_score``
    keeps the full-precision value, because the original's own
    "exploit_prediction" percentage string was computed from the
    *unrounded* score even though the score field it sits next to was
    rounded - a genuine (if minor) original inconsistency, preserved here
    rather than silently smoothed over.
    """
    exploitability_score: float
    raw_score: float
    exploitability_level: str
    exploit_indicators: List[str]
    public_exploits: bool
    exploit_maturity: str
    weaponization_level: str
    active_exploitation: bool
    recommended_priority: str


class CVERiskScorer:
    """Calculates RedVector's risk/relevance assessment for a CVERecord.

    Pure function of the record's own fields - no network access, no
    caching, no route logic. The exact thresholds/weights below reproduce
    the original's scoring, just decomposed into named constants and
    small static methods instead of one long inline method body.
    """

    EXPLOIT_KEYWORDS = (
        'remote code execution', 'rce', 'buffer overflow', 'stack overflow',
        'heap overflow', 'use after free', 'double free', 'format string',
        'sql injection', 'command injection', 'authentication bypass',
        'privilege escalation', 'directory traversal', 'path traversal',
        'deserialization', 'xxe', 'ssrf', 'csrf', 'xss',
    )
    RCE_BOOST_KEYWORDS = ('remote code execution', 'rce', 'buffer overflow')
    PRIV_ESC_BOOST_KEYWORDS = ('authentication bypass', 'privilege escalation')
    RCE_BOOST = 0.2
    PRIV_ESC_BOOST = 0.15

    EXPLOIT_REFERENCE_SOURCES = ('exploit-db.com', 'github.com', 'packetstormsecurity.com', 'metasploit')

    EXPLOITABILITY_SUBSCORE_DIVISOR = 3.9

    ATTACK_VECTOR_WEIGHTS = {"NETWORK": 0.4, "ADJACENT_NETWORK": 0.3, "LOCAL": 0.2, "PHYSICAL": 0.1}
    ATTACK_COMPLEXITY_WEIGHTS = {"LOW": 0.3, "HIGH": 0.1}
    PRIVILEGES_REQUIRED_WEIGHTS = {"NONE": 0.2, "LOW": 0.1}
    USER_INTERACTION_WEIGHTS = {"NONE": 0.1}

    def score(self, record: CVERecord) -> ExploitabilityAssessment:
        exploitability_score = self._base_exploitability_score(record)

        description_lower = record.description.lower()
        exploit_indicators = [kw for kw in self.EXPLOIT_KEYWORDS if kw in description_lower]

        if any(kw in description_lower for kw in self.RCE_BOOST_KEYWORDS):
            exploitability_score = min(exploitability_score + self.RCE_BOOST, 1.0)
        elif any(kw in description_lower for kw in self.PRIV_ESC_BOOST_KEYWORDS):
            exploitability_score = min(exploitability_score + self.PRIV_ESC_BOOST, 1.0)

        public_exploits, exploit_maturity = self._public_exploit_signal(record.references)
        weaponization_level = self._weaponization_level(exploitability_score, public_exploits)
        active_exploitation = self._active_exploitation(exploitability_score, public_exploits, record)
        priority = self._priority(exploitability_score, record.severity)

        return ExploitabilityAssessment(
            exploitability_score=round(exploitability_score, 2),
            raw_score=exploitability_score,
            exploitability_level=self._level(exploitability_score),
            exploit_indicators=exploit_indicators,
            public_exploits=public_exploits,
            exploit_maturity=exploit_maturity,
            weaponization_level=weaponization_level,
            active_exploitation=active_exploitation,
            recommended_priority=priority,
        )

    @classmethod
    def _base_exploitability_score(cls, record: CVERecord) -> float:
        if record.exploitability_subscore > 0:
            return min(record.exploitability_subscore / cls.EXPLOITABILITY_SUBSCORE_DIVISOR, 1.0)

        score = 0.0
        score += cls.ATTACK_VECTOR_WEIGHTS.get(record.attack_vector, 0.0)
        score += cls.ATTACK_COMPLEXITY_WEIGHTS.get(record.attack_complexity, 0.0)
        score += cls.PRIVILEGES_REQUIRED_WEIGHTS.get(record.privileges_required, 0.0)
        score += cls.USER_INTERACTION_WEIGHTS.get(record.user_interaction, 0.0)
        return min(score, 1.0)

    @staticmethod
    def _level(score: float) -> str:
        if score >= 0.8:
            return "HIGH"
        if score >= 0.6:
            return "MEDIUM"
        if score >= 0.3:
            return "LOW"
        return "VERY_LOW"

    @classmethod
    def _public_exploit_signal(cls, references: List[str]):
        for ref_url in references:
            if any(source in ref_url.lower() for source in cls.EXPLOIT_REFERENCE_SOURCES):
                return True, "PROOF_OF_CONCEPT"
        return False, "UNKNOWN"

    @staticmethod
    def _weaponization_level(exploitability_score: float, public_exploits: bool) -> str:
        if public_exploits and exploitability_score > 0.7:
            return "HIGH"
        if public_exploits and exploitability_score > 0.5:
            return "MEDIUM"
        if exploitability_score > 0.8:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _active_exploitation(exploitability_score: float, public_exploits: bool, record: CVERecord) -> bool:
        if exploitability_score > 0.8 and public_exploits:
            return True
        if record.severity in ("CRITICAL", "HIGH") and record.attack_vector == "NETWORK":
            return True
        return False

    @staticmethod
    def _priority(exploitability_score: float, severity: str) -> str:
        if exploitability_score > 0.8 and severity == "CRITICAL":
            return "IMMEDIATE"
        if exploitability_score > 0.7 or severity == "CRITICAL":
            return "HIGH"
        if exploitability_score > 0.5 or severity == "HIGH":
            return "MEDIUM"
        return "LOW"


# ============================================================================
# CVECacheAdapter
# ============================================================================

class CVECacheAdapter:
    """Thin wrapper around an injected cache object (e.g. RedVector's
    Phase 1.7 AdvancedCache/TTLCache), so CVEIntelligenceService can cache
    by CVE id without knowing anything about the cache's own internals or
    recreating one. ``cache`` must provide ``get(key)``/``set(key, value,
    ttl=...)`` - exactly AdvancedCache's interface - or be left as None,
    which makes every lookup a guaranteed miss (used by the compatibility
    adapter, since the original never cached CVE lookups at all).
    """

    def __init__(self, cache: Optional[Any] = None, default_ttl: Optional[int] = None):
        self._cache = cache
        self._default_ttl = default_ttl

    @property
    def enabled(self) -> bool:
        return self._cache is not None

    def get(self, key: str) -> Any:
        if not self.enabled:
            return None
        return self._cache.get(key)

    def set(self, key: str, value: Any) -> None:
        if not self.enabled:
            return
        if self._default_ttl is not None:
            self._cache.set(key, value, self._default_ttl)
        else:
            self._cache.set(key, value)


# ============================================================================
# CVEIntelligenceService
# ============================================================================

class CVEIntelligenceService:
    """Coordinates CVEFeedClient + ExploitFeedClient + CVERecordNormalizer
    + CVERiskScorer + (optional) CVECacheAdapter into the three behaviors
    the original CVEIntelligenceManager exposed. Thin orchestration only -
    no parsing or scoring logic of its own.
    """

    BROADER_SEARCH_DAYS = 7
    BROADER_SEARCH_RATE_LIMIT_DELAY = 6.0
    BROADER_SEARCH_RESULTS_PER_PAGE = 20
    BROADER_SEARCH_ITEMS_LIMIT = 10
    BROADER_SEARCH_SEVERITY = "CRITICAL"

    EXPLOIT_SEARCH_REPO_RESULTS_LIMIT = 5
    EXPLOIT_SEARCH_RATE_LIMIT_DELAY = 1.0
    EXPLOIT_REFERENCE_SOURCE_NAMES = {
        'exploit-db.com': 'exploit-db',
        'packetstormsecurity.com': 'packetstorm',
        'metasploit': 'metasploit',
        'rapid7.com': 'rapid7',
    }
    DEFAULT_EXPLOIT_SOURCES = ("exploit-db", "github", "metasploit", "packetstorm")
    RELIABILITY_ORDER = {"EXCELLENT": 4, "GOOD": 3, "FAIR": 2, "UNVERIFIED": 1}
    GITHUB_STAR_THRESHOLD_GOOD = 50
    GITHUB_FORK_THRESHOLD_GOOD = 10
    GITHUB_STAR_THRESHOLD_FAIR = 20
    GITHUB_FORK_THRESHOLD_FAIR = 5

    def __init__(
        self,
        cve_feed: Optional[CVEFeedClient] = None,
        exploit_feed: Optional[ExploitFeedClient] = None,
        normalizer: Optional[CVERecordNormalizer] = None,
        scorer: Optional[CVERiskScorer] = None,
        cache: Optional[CVECacheAdapter] = None,
        clock: Optional[Callable[[], datetime]] = None,
    ):
        self._cve_feed = cve_feed or NvdCVEFeedClient()
        self._exploit_feed = exploit_feed or GitHubExploitFeedClient()
        self._normalizer = normalizer or CVERecordNormalizer()
        self._scorer = scorer or CVERiskScorer()
        self._cache = cache or CVECacheAdapter(cache=None)
        self._clock = clock or datetime.now

    # -- fetch_latest_cves -----------------------------------------------

    def fetch_latest_cves(self, hours: int = 24, severity_filter: str = "HIGH,CRITICAL") -> Dict[str, Any]:
        try:
            end_date = self._clock()
            start_date = end_date - timedelta(hours=hours)
            severity_levels = [s.strip().upper() for s in severity_filter.split(",")]

            all_cves = self._collect_recent(start_date, end_date, severity_levels)

            if not all_cves:
                all_cves = self._broader_critical_search(end_date)

            return {
                "success": True,
                "cves": [self._to_feed_dict(r) for r in all_cves],
                "total_found": len(all_cves),
                "hours_searched": hours,
                "severity_filter": severity_filter,
                "data_sources": ["NVD API v2.0"],
                "search_period": f"{_format_nvd_date(start_date)} to {_format_nvd_date(end_date)}",
            }
        except Exception as exc:  # noqa: BLE001
            _log.error(f"Error fetching CVEs: {exc}")
            return {
                "success": False,
                "error": str(exc),
                "cves": [],
                "fallback_message": "CVE fetching failed, check network connectivity and API availability",
            }

    def _collect_recent(self, start_date, end_date, severity_levels) -> List[CVERecord]:
        result = self._cve_feed.fetch_recent(start_date, end_date, results_per_page=100)
        if not result.success or not result.data:
            return []

        records = []
        for raw_item in result.data.get("vulnerabilities", []):
            record = self._normalizer.normalize(raw_item, include_cvss_v2_fallback=True)
            if record.severity not in severity_levels and severity_levels != ["ALL"]:
                continue
            records.append(record)
        return records

    def _broader_critical_search(self, end_date: datetime) -> List[CVERecord]:
        try:
            broader_start = end_date - timedelta(days=self.BROADER_SEARCH_DAYS)
            result = self._cve_feed.fetch_recent(
                broader_start, end_date, severity_filter=self.BROADER_SEARCH_SEVERITY,
                results_per_page=self.BROADER_SEARCH_RESULTS_PER_PAGE,
                rate_limit_delay=self.BROADER_SEARCH_RATE_LIMIT_DELAY,
            )
            if not result.success or not result.data:
                return []

            records = []
            for raw_item in result.data.get("vulnerabilities", [])[: self.BROADER_SEARCH_ITEMS_LIMIT]:
                record = self._normalizer.normalize(raw_item, include_cvss_v2_fallback=True)
                # The original's broader-search path hardcodes severity to
                # CRITICAL and a minimal affected-software placeholder,
                # regardless of what the normalizer extracted - preserved
                # exactly, not "fixed" to use the normalizer's own values.
                record.severity = "CRITICAL"
                record.affected_software = ["Various (see references)"]
                record.references = [f"https://nvd.nist.gov/vuln/detail/{record.cve_id}"]
                record.source = "NVD (Recent Critical)"
                records.append(record)
            return records
        except Exception as exc:  # noqa: BLE001
            _log.warning(f"Broader search also failed: {exc}")
            return []

    @staticmethod
    def _to_feed_dict(record: CVERecord) -> Dict[str, Any]:
        return {
            "cve_id": record.cve_id,
            "description": record.description,
            "severity": record.severity,
            "cvss_score": record.cvss_score,
            "published_date": record.published_date,
            "last_modified": record.last_modified,
            "affected_software": record.affected_software,
            "references": record.references,
            "source": record.source,
        }

    # -- analyze_cve_exploitability ---------------------------------------

    def analyze_cve_exploitability(self, cve_id: str) -> Dict[str, Any]:
        try:
            cached = self._cache.get(cve_id)
            if cached is not None:
                return cached

            result = self._cve_feed.fetch_by_id(cve_id)
            if not result.success:
                if result.status_code is not None:
                    return {
                        "success": False,
                        "error": f"Failed to fetch CVE data: HTTP {result.status_code}",
                        "cve_id": cve_id,
                    }
                return {"success": False, "error": f"Network error: {result.error}", "cve_id": cve_id}

            vulnerabilities = (result.data or {}).get("vulnerabilities", [])
            if not vulnerabilities:
                return {"success": False, "error": f"CVE {cve_id} not found in NVD database", "cve_id": cve_id}

            record = self._normalizer.normalize(vulnerabilities[0], include_cvss_v2_fallback=False)
            assessment = self._scorer.score(record)

            description = record.description
            analysis = {
                "success": True,
                "cve_id": cve_id,
                "exploitability_score": assessment.exploitability_score,
                "exploitability_level": assessment.exploitability_level,
                "cvss_score": record.cvss_score,
                "severity": record.severity,
                "attack_vector": record.attack_vector,
                "attack_complexity": record.attack_complexity,
                "privileges_required": record.privileges_required,
                "user_interaction": record.user_interaction,
                "exploitability_subscore": record.exploitability_subscore,
                "exploit_availability": {
                    "public_exploits": assessment.public_exploits,
                    "exploit_maturity": assessment.exploit_maturity,
                    "weaponization_level": assessment.weaponization_level,
                },
                "threat_intelligence": {
                    "active_exploitation": assessment.active_exploitation,
                    "exploit_prediction": f"{assessment.raw_score * 100:.1f}% likelihood of exploitation",
                    "recommended_priority": assessment.recommended_priority,
                    "exploit_indicators": assessment.exploit_indicators,
                },
                "vulnerability_details": {
                    "description": description[:500] + "..." if len(description) > 500 else description,
                    "published_date": record.published_date,
                    "last_modified": record.last_modified,
                    "references_count": len(record.references),
                },
                "data_source": "NVD API v2.0",
                "analysis_timestamp": self._clock().isoformat(),
            }

            self._cache.set(cve_id, analysis)
            return analysis
        except Exception as exc:  # noqa: BLE001
            _log.error(f"Error analyzing CVE {cve_id}: {exc}")
            return {"success": False, "error": str(exc), "cve_id": cve_id}

    # -- search_existing_exploits -------------------------------------------

    def search_existing_exploits(self, cve_id: str) -> Dict[str, Any]:
        try:
            all_exploits: List[Dict[str, Any]] = []
            sources_searched: List[str] = []

            all_exploits.extend(self._search_github_repositories(cve_id, sources_searched))
            all_exploits.extend(self._search_reference_exploits(cve_id, sources_searched))
            all_exploits.extend(self._search_metasploit_modules(cve_id, sources_searched))

            for source in self.DEFAULT_EXPLOIT_SOURCES:
                if source not in sources_searched:
                    sources_searched.append(source)

            all_exploits.sort(
                key=lambda x: (
                    self.RELIABILITY_ORDER.get(x.get("reliability", "UNVERIFIED"), 0),
                    x.get("stars", 0),
                    x.get("date_published", ""),
                ),
                reverse=True,
            )

            return {
                "success": True,
                "cve_id": cve_id,
                "exploits_found": len(all_exploits),
                "exploits": all_exploits,
                "sources_searched": sources_searched,
                "search_summary": {
                    "github_repos": len([e for e in all_exploits if e["source"] == "github"]),
                    "exploit_db_refs": len([e for e in all_exploits if e["source"] == "exploit-db"]),
                    "metasploit_modules": len([e for e in all_exploits if e["source"] == "metasploit"]),
                    "other_sources": len([e for e in all_exploits
                                           if e["source"] not in ("github", "exploit-db", "metasploit")]),
                },
                "search_timestamp": self._clock().isoformat(),
            }
        except Exception as exc:  # noqa: BLE001
            _log.error(f"Error searching exploits for {cve_id}: {exc}")
            return {"success": False, "error": str(exc), "cve_id": cve_id, "exploits": [], "sources_searched": []}

    def _search_github_repositories(self, cve_id: str, sources_searched: List[str]) -> List[Dict[str, Any]]:
        result = self._exploit_feed.search_repositories(f"{cve_id} exploit poc vulnerability", per_page=10)
        if not result.success or not result.data:
            return []

        found = []
        for repo in result.data.get("items", [])[: self.EXPLOIT_SEARCH_REPO_RESULTS_LIMIT]:
            repo_name = repo.get("name", "").lower()
            repo_desc = (repo.get("description") or "").lower()
            if cve_id.lower() not in repo_name and cve_id.lower() not in repo_desc:
                continue

            stars = repo.get("stargazers_count", 0)
            forks = repo.get("forks_count", 0)
            reliability = "UNVERIFIED"
            if stars >= self.GITHUB_STAR_THRESHOLD_GOOD or forks >= self.GITHUB_FORK_THRESHOLD_GOOD:
                reliability = "GOOD"
            elif stars >= self.GITHUB_STAR_THRESHOLD_FAIR or forks >= self.GITHUB_FORK_THRESHOLD_FAIR:
                reliability = "FAIR"

            found.append({
                "source": "github",
                "exploit_id": f"github-{repo.get('id', 'unknown')}",
                "title": repo.get("name", "Unknown Repository"),
                "description": repo.get("description", "No description"),
                "author": repo.get("owner", {}).get("login", "Unknown"),
                "date_published": repo.get("created_at", ""),
                "last_updated": repo.get("updated_at", ""),
                "type": "proof-of-concept",
                "platform": "cross-platform",
                "url": repo.get("html_url", ""),
                "stars": stars,
                "forks": forks,
                "verified": False,
                "reliability": reliability,
            })

        sources_searched.append("github")
        return found

    def _search_reference_exploits(self, cve_id: str, sources_searched: List[str]) -> List[Dict[str, Any]]:
        result = self._cve_feed.fetch_by_id(cve_id, rate_limit_delay=self.EXPLOIT_SEARCH_RATE_LIMIT_DELAY)
        if not result.success or not result.data:
            return []

        vulnerabilities = result.data.get("vulnerabilities", [])
        if not vulnerabilities:
            return []

        cve_data = vulnerabilities[0].get("cve", {})
        published = cve_data.get("published", "")

        found = []
        for ref in cve_data.get("references", []):
            ref_url = ref.get("url", "")
            ref_url_lower = ref_url.lower()
            for source_domain, source_name in self.EXPLOIT_REFERENCE_SOURCE_NAMES.items():
                if source_domain in ref_url_lower:
                    found.append({
                        "source": source_name,
                        "exploit_id": f"{source_name}-ref",
                        "title": f"Referenced exploit for {cve_id}",
                        "description": "Exploit reference found in CVE data",
                        "author": "Various",
                        "date_published": published,
                        "type": "reference",
                        "platform": "various",
                        "url": ref_url,
                        "verified": True,
                        "reliability": "GOOD" if source_name == "exploit-db" else "FAIR",
                    })
                    if source_name not in sources_searched:
                        sources_searched.append(source_name)
        return found

    def _search_metasploit_modules(self, cve_id: str, sources_searched: List[str]) -> List[Dict[str, Any]]:
        query = f"{cve_id} filename:*.rb repo:rapid7/metasploit-framework"
        result = self._exploit_feed.search_code(query, per_page=5)
        if not result.success or not result.data:
            return []

        found = []
        for code_item in result.data.get("items", []):
            file_path = code_item.get("path", "")
            if "exploits/" not in file_path and "auxiliary/" not in file_path:
                continue
            found.append({
                "source": "metasploit",
                "exploit_id": f"msf-{code_item.get('sha', 'unknown')[:8]}",
                "title": f"Metasploit Module: {code_item.get('name', 'Unknown')}",
                "description": f"Metasploit framework module at {file_path}",
                "author": "Metasploit Framework",
                "date_published": "Unknown",
                "type": "metasploit-module",
                "platform": "various",
                "url": code_item.get("html_url", ""),
                "verified": True,
                "reliability": "EXCELLENT",
            })

        if result.data.get("items") and "metasploit" not in sources_searched:
            sources_searched.append("metasploit")
        return found


# ============================================================================
# VulnerabilityRecord + VulnerabilitySource (Protocol) + MockVulnerabilitySource
# ============================================================================

@dataclass(frozen=True)
class VulnerabilityRecord:
    """RedVector's stable vulnerability-candidate model used for
    attack-chain correlation."""
    cve_id: str
    description: str
    cvss_score: float
    exploitability: str


class VulnerabilitySource(Protocol):
    """Abstraction for retrieving candidate vulnerabilities for one
    (software, attack-pattern) pair."""

    def find(self, software: str, pattern_type: str) -> List[VulnerabilityRecord]:
        ...


class MockVulnerabilitySource:
    """Placeholder vulnerability source.

    This reproduces the original ``_find_vulnerabilities_by_pattern``'s
    behavior exactly: it returns the same two illustrative CVE records
    regardless of ``software`` or ``pattern_type`` (only the description
    text is templated with the software name), because - per the
    original's own comment - "real implementation would query CVE
    database". This is a known, pre-existing limitation, preserved here
    deliberately rather than fixed, per Phase 1 Item 3 scope rules.
    """

    def find(self, software: str, pattern_type: str) -> List[VulnerabilityRecord]:
        return [
            VulnerabilityRecord(
                cve_id="CVE-2024-1234", description=f"Remote code execution in {software}",
                cvss_score=9.8, exploitability="HIGH",
            ),
            VulnerabilityRecord(
                cve_id="CVE-2024-5678", description=f"Privilege escalation in {software}",
                cvss_score=7.8, exploitability="MEDIUM",
            ),
        ]


# ============================================================================
# CorrelationStrategy (Protocol) + PatternBasedCorrelationStrategy
# ============================================================================

class CorrelationStrategy(Protocol):
    """Finds candidate vulnerabilities for one attack-chain stage type
    (e.g. "Initial Access", "Privilege Escalation") for a given target."""

    stage_objective: str

    def find_candidates(self, target_software: str) -> List[VulnerabilityRecord]:
        ...


class PatternBasedCorrelationStrategy:
    """A correlation strategy driven by a named attack-pattern category,
    delegating the actual vulnerability lookup to an injected
    VulnerabilitySource."""

    def __init__(self, stage_objective: str, pattern_type: str, source: VulnerabilitySource,
                 success_probability: float):
        self.stage_objective = stage_objective
        self.pattern_type = pattern_type
        self.success_probability = success_probability
        self._source = source

    def find_candidates(self, target_software: str) -> List[VulnerabilityRecord]:
        return self._source.find(target_software, self.pattern_type)


# ============================================================================
# VulnerabilityCorrelationEngine
# ============================================================================

class VulnerabilityCorrelationEngine:
    """Applies every registered CorrelationStrategy to a target and
    returns the per-stage candidate lists. No network calls, no
    route-specific code - just "which strategies found what"."""

    def __init__(self, strategies: List[PatternBasedCorrelationStrategy]):
        self._strategies = list(strategies)

    @property
    def strategies(self) -> List[PatternBasedCorrelationStrategy]:
        return self._strategies

    def correlate(self, target_software: str) -> Dict[str, List[VulnerabilityRecord]]:
        return {s.stage_objective: s.find_candidates(target_software) for s in self._strategies}


def default_correlation_engine(source: Optional[VulnerabilitySource] = None) -> VulnerabilityCorrelationEngine:
    """The three stages the original find_attack_chains hardcoded, in the
    same order and with the same per-stage success probabilities."""
    source = source or MockVulnerabilitySource()
    return VulnerabilityCorrelationEngine([
        PatternBasedCorrelationStrategy("Initial Access", "remote_execution", source, 0.75),
        PatternBasedCorrelationStrategy("Privilege Escalation", "privilege_escalation", source, 0.60),
        PatternBasedCorrelationStrategy("Persistence", "persistence", source, 0.80),
    ])


# ============================================================================
# AttackChainStage / AttackChain + AttackPathBuilder
# ============================================================================

@dataclass
class AttackChainStage:
    stage: int
    objective: str
    vulnerability: VulnerabilityRecord
    success_probability: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.stage,
            "objective": self.objective,
            "vulnerability": {
                "cve_id": self.vulnerability.cve_id,
                "description": self.vulnerability.description,
                "cvss_score": self.vulnerability.cvss_score,
                "exploitability": self.vulnerability.exploitability,
            },
            "success_probability": self.success_probability,
        }


@dataclass
class AttackChain:
    chain_id: str
    target: str
    stages: List[AttackChainStage]
    overall_probability: float
    complexity: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "target": self.target,
            "stages": [s.to_dict() for s in self.stages],
            "overall_probability": self.overall_probability,
            "complexity": self.complexity,
        }


class AttackPathBuilder:
    """Builds AttackChain objects (the externally-expected attack-chain
    representation) from a VulnerabilityCorrelationEngine's per-stage
    candidates. Separate from the correlation logic itself.

    Preserves a genuine quirk in the original's own (unrolled, hardcoded
    to 3 stages) logic rather than generalizing it away: the second stage
    (privilege escalation) is added whenever any candidate exists for it,
    with NO ``max_depth`` check at all; only the third stage (persistence)
    is gated by ``len(stages so far) < max_depth`` - and that check runs
    *after* the second stage was already (conditionally) added. So
    ``max_depth`` of 1 or 2 both still allow a second stage and only ever
    suppress the third; only ``max_depth >= 3`` can include it. This is
    exactly what the original did, not a bug introduced here.
    """

    MAX_INITIAL_CHAINS = 3
    DEFAULT_COMPLEXITY = "MEDIUM"

    def __init__(self, correlation_engine: VulnerabilityCorrelationEngine):
        self._engine = correlation_engine

    def build_chains(self, target_software: str, max_depth: int = 3,
                      display_target: Optional[str] = None) -> List[AttackChain]:
        """``target_software`` is what correlation strategies see (the
        original lowercased it before any lookup); ``display_target``,
        defaulting to ``target_software`` itself, is what ends up in each
        AttackChain's own ``target`` field - the original kept that one
        in its original casing even though it lowercased the value used
        for vulnerability lookups, and that distinction is preserved here
        rather than collapsed into a single value."""
        display_target = target_software if display_target is None else display_target
        correlated = self._engine.correlate(target_software)
        stage_objectives = [s.stage_objective for s in self._engine.strategies]
        if not stage_objectives:
            return []

        initial_objective = stage_objectives[0]
        initial_candidates = correlated.get(initial_objective, [])

        chains = []
        for index, initial_vuln in enumerate(initial_candidates[: self.MAX_INITIAL_CHAINS], start=1):
            chains.append(self._build_single_chain(index, display_target, initial_objective,
                                                      initial_vuln, correlated, stage_objectives, max_depth))
        return chains

    def _build_single_chain(
        self, index: int, display_target: str, initial_objective: str,
        initial_vuln: VulnerabilityRecord, correlated: Dict[str, List[VulnerabilityRecord]],
        stage_objectives: List[str], max_depth: int,
    ) -> AttackChain:
        strategy_by_objective = {s.stage_objective: s for s in self._engine.strategies}
        initial_strategy = strategy_by_objective[initial_objective]

        stages = [AttackChainStage(
            stage=1, objective=initial_objective, vulnerability=initial_vuln,
            success_probability=initial_strategy.success_probability,
        )]
        overall_probability = initial_strategy.success_probability

        # Stage 2: unconditional on max_depth (matches the original exactly).
        if len(stage_objectives) > 1:
            second_objective = stage_objectives[1]
            second_candidates = correlated.get(second_objective, [])
            if second_candidates:
                second_strategy = strategy_by_objective[second_objective]
                stages.append(AttackChainStage(
                    stage=2, objective=second_objective, vulnerability=second_candidates[0],
                    success_probability=second_strategy.success_probability,
                ))
                overall_probability *= second_strategy.success_probability

        # Stage 3: gated by `len(stages) < max_depth`, evaluated *after*
        # stage 2 was conditionally added - matches the original exactly.
        if len(stage_objectives) > 2:
            third_objective = stage_objectives[2]
            third_candidates = correlated.get(third_objective, [])
            if third_candidates and len(stages) < max_depth:
                third_strategy = strategy_by_objective[third_objective]
                stages.append(AttackChainStage(
                    stage=3, objective=third_objective, vulnerability=third_candidates[0],
                    success_probability=third_strategy.success_probability,
                ))
                overall_probability *= third_strategy.success_probability

        return AttackChain(
            chain_id=f"chain_{index}", target=display_target, stages=stages,
            overall_probability=overall_probability, complexity=self.DEFAULT_COMPLEXITY,
        )


# ============================================================================
# AttackChainRecommender
# ============================================================================

class AttackChainRecommender:
    """Builds the human-readable recommendation summary for a set of
    attack chains."""

    STATIC_RECOMMENDATIONS = (
        "Recommendations:",
        "- Test chains in order of probability",
        "- Prepare fallback methods for each stage",
        "- Consider detection evasion at each stage",
    )

    def recommendations_for(self, chains: List[AttackChain]) -> str:
        if not chains:
            return "No viable attack chains found for target"

        highest = max(chains, key=lambda c: c.overall_probability)
        lines = [
            f"Found {len(chains)} potential attack chains",
            f"Highest probability chain: {highest.overall_probability:.2%}",
            *self.STATIC_RECOMMENDATIONS,
        ]
        return "\n".join(lines)


# ============================================================================
# VulnerabilityCorrelationService
# ============================================================================

class VulnerabilityCorrelationService:
    """Thin orchestration layer tying AttackPathBuilder and
    AttackChainRecommender together for the find_attack_chains use case."""

    def __init__(
        self,
        path_builder: Optional[AttackPathBuilder] = None,
        recommender: Optional[AttackChainRecommender] = None,
    ):
        self._path_builder = path_builder or AttackPathBuilder(default_correlation_engine())
        self._recommender = recommender or AttackChainRecommender()

    def find_attack_chains(self, target_software: str, max_depth: int = 3) -> Dict[str, Any]:
        try:
            base_software = target_software.lower()
            chains = self._path_builder.build_chains(base_software, max_depth, display_target=target_software)
            return {
                "success": True,
                "target_software": target_software,
                "total_chains": len(chains),
                "attack_chains": [c.to_dict() for c in chains],
                "recommendation": self._recommender.recommendations_for(chains),
            }
        except Exception as exc:  # noqa: BLE001
            _log.error(f"Error finding attack chains: {exc}")
            return {"success": False, "error": str(exc)}

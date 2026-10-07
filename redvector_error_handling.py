#!/usr/bin/env python3
"""
RedVector AI - Error Classification, Recovery and Graceful-Degradation Primitives

This module is RedVector's own implementation of the error-handling and
degradation building blocks used by ``redvector_server.py``. It replaces the
single "IntelligentErrorHandler" / "GracefulDegradation" classes that module
used to define inline with a small set of independently-testable, composable
pieces (Phase 1 Item 2 of the RedVector Independence Remediation Plan):

- ``ErrorClassifier``             exception/message -> ErrorType, nothing else
- ``RecoveryStrategyRegistry``    ErrorType -> candidate RecoveryStrategy list
- ``RetryPolicy``                 is-a-retry-allowed / backoff-delay math
- ``ScoredRecoverySelector``      picks one RecoveryStrategy among candidates
- ``ErrorTelemetry``              records error history, reports statistics
- ``ToolAlternativesRegistry``    failed tool -> candidate alternatives
- ``ParameterAdjustmentPolicy``   tool/error-type -> parameter adjustments
- ``HumanEscalationReporter``     builds the human-escalation payload
- ``FallbackChainCatalog``        operation -> alternate tool chain
- ``DegradationPolicy`` (+registry) operation -> gap-filling fallback logic
- ``ManualRecommendationCatalog`` operation/component -> manual follow-ups
- ``GracefulDegradationCoordinator`` composes the degradation collaborators
- ``ResilientExecutor``           classify -> select -> retry/fallback -> result

Design goals, matching Phase 1 Item 1's precedent:
  * composition over one monolithic "handler" class - each class here has
    one job and knows nothing about the others.
  * registry/table-driven dispatch instead of if/elif chains copied from
    the old implementation, wherever that doesn't change behavior.
  * every class is plain Python and can be constructed and unit-tested in
    isolation, with no Flask/app/global state, and no dependency on
    project-specific formatting helpers (e.g. ModernVisualEngine) that live
    in redvector_server.py - those stay out of this module entirely, and
    the thin adapters there do the actual logging.
  * nothing here silently changes behavior: regex patterns, data tables,
    scoring formulas and branch conditions are carried over exactly.

``redvector_server.py`` adapts its existing public names (``IntelligentErrorHandler``,
``GracefulDegradation``, and the ``ErrorType``/``RecoveryAction``/``ErrorContext``/
``RecoveryStrategy`` types) onto these primitives via thin compatibility
wrappers, so every existing caller, route and test keeps working unchanged.
"""

from __future__ import annotations

import socket
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Protocol

import re as _re

try:
    import requests as _requests
except ImportError:  # pragma: no cover - requests is a hard runtime dependency
    _requests = None

try:
    import psutil as _psutil
except ImportError:  # pragma: no cover - psutil is a hard runtime dependency
    _psutil = None

import os as _os


# ============================================================================
# Shared data types
# ============================================================================
# These are plain data (enums/dataclasses), not logic, and are a contract
# shared with code outside this component (execute_command_with_recovery and
# the /api/error-handling/* routes in redvector_server.py construct and read
# these directly) - their names, fields and values are carried over exactly.

class ErrorType(Enum):
    """Enumeration of different error types for intelligent handling"""
    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"
    NETWORK_UNREACHABLE = "network_unreachable"
    RATE_LIMITED = "rate_limited"
    TOOL_NOT_FOUND = "tool_not_found"
    INVALID_PARAMETERS = "invalid_parameters"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    AUTHENTICATION_FAILED = "authentication_failed"
    TARGET_UNREACHABLE = "target_unreachable"
    PARSING_ERROR = "parsing_error"
    UNKNOWN = "unknown"


class RecoveryAction(Enum):
    """Types of recovery actions that can be taken"""
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    RETRY_WITH_REDUCED_SCOPE = "retry_with_reduced_scope"
    SWITCH_TO_ALTERNATIVE_TOOL = "switch_to_alternative_tool"
    ADJUST_PARAMETERS = "adjust_parameters"
    ESCALATE_TO_HUMAN = "escalate_to_human"
    GRACEFUL_DEGRADATION = "graceful_degradation"
    ABORT_OPERATION = "abort_operation"


@dataclass
class ErrorContext:
    """Context information for error handling decisions"""
    tool_name: str
    target: str
    parameters: Dict[str, Any]
    error_type: ErrorType
    error_message: str
    attempt_count: int
    timestamp: datetime
    stack_trace: str
    system_resources: Dict[str, Any]
    previous_errors: List["ErrorContext"] = field(default_factory=list)


@dataclass
class RecoveryStrategy:
    """A concrete, chosen recovery action with its tuning parameters.

    This is a DATA object - the decision itself - not to be confused with
    the *protocol* below (``RecoveryDecisionStrategy``) for the thing that
    picks one among several candidates.
    """
    action: RecoveryAction
    parameters: Dict[str, Any]
    max_attempts: int
    backoff_multiplier: float
    success_probability: float
    estimated_time: int  # seconds


# ============================================================================
# ErrorClassifier
# ============================================================================

def default_error_patterns() -> Dict[str, ErrorType]:
    """Regex error-message patterns -> ErrorType. Pure data."""
    return {
        # Timeout patterns
        r"timeout|timed out|connection timeout|read timeout": ErrorType.TIMEOUT,
        r"operation timed out|command timeout": ErrorType.TIMEOUT,

        # Permission patterns
        r"permission denied|access denied|forbidden|not authorized": ErrorType.PERMISSION_DENIED,
        r"sudo required|root required|insufficient privileges": ErrorType.PERMISSION_DENIED,

        # Network patterns
        r"network unreachable|host unreachable|no route to host": ErrorType.NETWORK_UNREACHABLE,
        r"connection refused|connection reset|network error": ErrorType.NETWORK_UNREACHABLE,

        # Rate limiting patterns
        r"rate limit|too many requests|throttled|429": ErrorType.RATE_LIMITED,
        r"request limit exceeded|quota exceeded": ErrorType.RATE_LIMITED,

        # Tool not found patterns
        r"command not found|no such file or directory|not found": ErrorType.TOOL_NOT_FOUND,
        r"executable not found|binary not found": ErrorType.TOOL_NOT_FOUND,

        # Parameter patterns
        r"invalid argument|invalid option|unknown option": ErrorType.INVALID_PARAMETERS,
        r"bad parameter|invalid parameter|syntax error": ErrorType.INVALID_PARAMETERS,

        # Resource patterns
        r"out of memory|memory error|disk full|no space left": ErrorType.RESOURCE_EXHAUSTED,
        r"resource temporarily unavailable|too many open files": ErrorType.RESOURCE_EXHAUSTED,

        # Authentication patterns
        r"authentication failed|login failed|invalid credentials": ErrorType.AUTHENTICATION_FAILED,
        r"unauthorized|invalid token|expired token": ErrorType.AUTHENTICATION_FAILED,

        # Target patterns
        r"target unreachable|target not responding|target down": ErrorType.TARGET_UNREACHABLE,
        r"host not found|dns resolution failed": ErrorType.TARGET_UNREACHABLE,

        # Parsing patterns
        r"parse error|parsing failed|invalid format|malformed": ErrorType.PARSING_ERROR,
        r"json decode error|xml parse error|invalid json": ErrorType.PARSING_ERROR,
    }


def default_exception_type_map() -> Dict[type, ErrorType]:
    """Python exception class -> ErrorType, checked before message patterns."""
    return {
        TimeoutError: ErrorType.TIMEOUT,
        PermissionError: ErrorType.PERMISSION_DENIED,
        ConnectionError: ErrorType.NETWORK_UNREACHABLE,
        FileNotFoundError: ErrorType.TOOL_NOT_FOUND,
    }


class ErrorClassifier:
    """Classifies an exception/message into an ErrorType.

    Deterministic and pure - contains no recovery-execution logic
    whatsoever, so it can be constructed and tested entirely on its own.
    """

    def __init__(
        self,
        patterns: Optional[Dict[str, ErrorType]] = None,
        exception_type_map: Optional[Dict[type, ErrorType]] = None,
    ):
        self._patterns = patterns if patterns is not None else default_error_patterns()
        self._exception_type_map = (
            exception_type_map if exception_type_map is not None else default_exception_type_map()
        )

    def classify(self, error_message: str, exception: Optional[Exception] = None) -> ErrorType:
        """Classify error based on message and exception type"""
        if exception is not None:
            for exc_type, error_type in self._exception_type_map.items():
                if isinstance(exception, exc_type):
                    return error_type

        error_text = error_message.lower()
        for pattern, error_type in self._patterns.items():
            if _re.search(pattern, error_text, _re.IGNORECASE):
                return error_type

        return ErrorType.UNKNOWN


# ============================================================================
# RecoveryStrategyRegistry
# ============================================================================

def default_recovery_strategies() -> Dict[ErrorType, List[RecoveryStrategy]]:
    """Candidate recovery strategies per ErrorType. Pure data."""
    return {
        ErrorType.TIMEOUT: [
            RecoveryStrategy(
                action=RecoveryAction.RETRY_WITH_BACKOFF,
                parameters={"initial_delay": 5, "max_delay": 60},
                max_attempts=3, backoff_multiplier=2.0, success_probability=0.7, estimated_time=30,
            ),
            RecoveryStrategy(
                action=RecoveryAction.RETRY_WITH_REDUCED_SCOPE,
                parameters={"reduce_threads": True, "reduce_timeout": True},
                max_attempts=2, backoff_multiplier=1.0, success_probability=0.8, estimated_time=45,
            ),
            RecoveryStrategy(
                action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                parameters={"prefer_faster_tools": True},
                max_attempts=1, backoff_multiplier=1.0, success_probability=0.6, estimated_time=60,
            ),
        ],
        ErrorType.PERMISSION_DENIED: [
            RecoveryStrategy(
                action=RecoveryAction.ESCALATE_TO_HUMAN,
                parameters={"message": "Privilege escalation required", "urgency": "medium"},
                max_attempts=1, backoff_multiplier=1.0, success_probability=0.9, estimated_time=300,
            ),
            RecoveryStrategy(
                action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                parameters={"require_no_privileges": True},
                max_attempts=1, backoff_multiplier=1.0, success_probability=0.5, estimated_time=30,
            ),
        ],
        ErrorType.NETWORK_UNREACHABLE: [
            RecoveryStrategy(
                action=RecoveryAction.RETRY_WITH_BACKOFF,
                parameters={"initial_delay": 10, "max_delay": 120},
                max_attempts=3, backoff_multiplier=2.0, success_probability=0.6, estimated_time=60,
            ),
            RecoveryStrategy(
                action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                parameters={"prefer_offline_tools": True},
                max_attempts=1, backoff_multiplier=1.0, success_probability=0.4, estimated_time=30,
            ),
        ],
        ErrorType.RATE_LIMITED: [
            RecoveryStrategy(
                action=RecoveryAction.RETRY_WITH_BACKOFF,
                parameters={"initial_delay": 30, "max_delay": 300},
                max_attempts=5, backoff_multiplier=1.5, success_probability=0.9, estimated_time=180,
            ),
            RecoveryStrategy(
                action=RecoveryAction.ADJUST_PARAMETERS,
                parameters={"reduce_rate": True, "increase_delays": True},
                max_attempts=2, backoff_multiplier=1.0, success_probability=0.8, estimated_time=120,
            ),
        ],
        ErrorType.TOOL_NOT_FOUND: [
            RecoveryStrategy(
                action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                parameters={"find_equivalent": True},
                max_attempts=1, backoff_multiplier=1.0, success_probability=0.7, estimated_time=15,
            ),
            RecoveryStrategy(
                action=RecoveryAction.ESCALATE_TO_HUMAN,
                parameters={"message": "Tool installation required", "urgency": "low"},
                max_attempts=1, backoff_multiplier=1.0, success_probability=0.9, estimated_time=600,
            ),
        ],
        ErrorType.INVALID_PARAMETERS: [
            RecoveryStrategy(
                action=RecoveryAction.ADJUST_PARAMETERS,
                parameters={"use_defaults": True, "remove_invalid": True},
                max_attempts=3, backoff_multiplier=1.0, success_probability=0.8, estimated_time=10,
            ),
            RecoveryStrategy(
                action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                parameters={"simpler_interface": True},
                max_attempts=1, backoff_multiplier=1.0, success_probability=0.6, estimated_time=30,
            ),
        ],
        ErrorType.RESOURCE_EXHAUSTED: [
            RecoveryStrategy(
                action=RecoveryAction.RETRY_WITH_REDUCED_SCOPE,
                parameters={"reduce_memory": True, "reduce_threads": True},
                max_attempts=2, backoff_multiplier=1.0, success_probability=0.7, estimated_time=60,
            ),
            RecoveryStrategy(
                action=RecoveryAction.RETRY_WITH_BACKOFF,
                parameters={"initial_delay": 60, "max_delay": 300},
                max_attempts=2, backoff_multiplier=2.0, success_probability=0.5, estimated_time=180,
            ),
        ],
        ErrorType.AUTHENTICATION_FAILED: [
            RecoveryStrategy(
                action=RecoveryAction.ESCALATE_TO_HUMAN,
                parameters={"message": "Authentication credentials required", "urgency": "high"},
                max_attempts=1, backoff_multiplier=1.0, success_probability=0.9, estimated_time=300,
            ),
            RecoveryStrategy(
                action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                parameters={"no_auth_required": True},
                max_attempts=1, backoff_multiplier=1.0, success_probability=0.4, estimated_time=30,
            ),
        ],
        ErrorType.TARGET_UNREACHABLE: [
            RecoveryStrategy(
                action=RecoveryAction.RETRY_WITH_BACKOFF,
                parameters={"initial_delay": 15, "max_delay": 180},
                max_attempts=3, backoff_multiplier=2.0, success_probability=0.6, estimated_time=90,
            ),
            RecoveryStrategy(
                action=RecoveryAction.GRACEFUL_DEGRADATION,
                parameters={"skip_target": True, "continue_with_others": True},
                max_attempts=1, backoff_multiplier=1.0, success_probability=1.0, estimated_time=5,
            ),
        ],
        ErrorType.PARSING_ERROR: [
            RecoveryStrategy(
                action=RecoveryAction.ADJUST_PARAMETERS,
                parameters={"change_output_format": True, "add_parsing_flags": True},
                max_attempts=2, backoff_multiplier=1.0, success_probability=0.7, estimated_time=20,
            ),
            RecoveryStrategy(
                action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                parameters={"better_output_format": True},
                max_attempts=1, backoff_multiplier=1.0, success_probability=0.6, estimated_time=30,
            ),
        ],
        ErrorType.UNKNOWN: [
            RecoveryStrategy(
                action=RecoveryAction.RETRY_WITH_BACKOFF,
                parameters={"initial_delay": 5, "max_delay": 30},
                max_attempts=2, backoff_multiplier=2.0, success_probability=0.3, estimated_time=45,
            ),
            RecoveryStrategy(
                action=RecoveryAction.ESCALATE_TO_HUMAN,
                parameters={"message": "Unknown error encountered", "urgency": "medium"},
                max_attempts=1, backoff_multiplier=1.0, success_probability=0.9, estimated_time=300,
            ),
        ],
    }


class RecoveryStrategyRegistry:
    """Maps ErrorType -> candidate RecoveryStrategy list.

    Supports registration/replacement instead of a hardcoded branching
    table spread across methods - adding or overriding an ErrorType's
    strategies is one call, not a new elif branch.
    """

    def __init__(self, strategies: Optional[Dict[ErrorType, List[RecoveryStrategy]]] = None):
        self._strategies: Dict[ErrorType, List[RecoveryStrategy]] = (
            strategies if strategies is not None else default_recovery_strategies()
        )

    def get(self, error_type: ErrorType) -> List[RecoveryStrategy]:
        """Candidates for this ErrorType, falling back to UNKNOWN's."""
        return self._strategies.get(error_type, self._strategies.get(ErrorType.UNKNOWN, []))

    def register(self, error_type: ErrorType, strategies: List[RecoveryStrategy]) -> None:
        """Register (or replace) the candidate strategies for an ErrorType."""
        self._strategies[error_type] = list(strategies)

    def as_dict(self) -> Dict[ErrorType, List[RecoveryStrategy]]:
        """The underlying mapping, for legacy direct-dict access
        (e.g. ``error_handler.recovery_strategies.get(...)``)."""
        return self._strategies


# ============================================================================
# RetryPolicy
# ============================================================================

class RetryPolicy:
    """Decides whether a given RecoveryStrategy may still be attempted, and
    computes its backoff delay / decayed success probability.

    Pure policy calculation - no command execution, no sleeping, no I/O.
    """

    @staticmethod
    def is_retry_allowed(strategy: RecoveryStrategy, attempt_count: int) -> bool:
        return attempt_count <= strategy.max_attempts

    @staticmethod
    def compute_backoff_delay(strategy: RecoveryStrategy, attempt_count: int) -> float:
        initial_delay = strategy.parameters.get("initial_delay", 5)
        max_delay = strategy.parameters.get("max_delay", 60)
        return min(initial_delay * (strategy.backoff_multiplier ** (attempt_count - 1)), max_delay)

    @staticmethod
    def adjusted_success_probability(strategy: RecoveryStrategy, attempt_count: int) -> float:
        """Success probability decayed by prior failed attempts."""
        return strategy.success_probability * (0.9 ** (attempt_count - 1))


# ============================================================================
# RecoveryDecisionStrategy (protocol) + ScoredRecoverySelector
# ============================================================================

class RecoveryDecisionStrategy(Protocol):
    """Interface for picking one RecoveryStrategy among several candidates
    for a given ErrorContext.

    Distinct from the ``RecoveryStrategy`` dataclass above: that is the
    data/decision, this is the thing that decides.
    """

    def select(self, candidates: List[RecoveryStrategy], context: ErrorContext) -> RecoveryStrategy:
        ...


class ScoredRecoverySelector:
    """RedVector's own strategy-selection heuristic: score every
    still-viable candidate by (decayed success probability - time cost),
    pick the highest-scoring one. Falls back to an escalation decision when
    nothing is viable for the current attempt count.
    """

    EXHAUSTED_FALLBACK_URGENCY = "high"
    TIME_COST_DIVISOR = 1000.0

    def __init__(self, retry_policy: Optional[RetryPolicy] = None):
        self._retry_policy = retry_policy or RetryPolicy()

    def select(self, candidates: List[RecoveryStrategy], context: ErrorContext) -> RecoveryStrategy:
        """Select the best recovery strategy based on context"""
        viable = [s for s in candidates if self._retry_policy.is_retry_allowed(s, context.attempt_count)]

        if not viable:
            return RecoveryStrategy(
                action=RecoveryAction.ESCALATE_TO_HUMAN,
                parameters={
                    "message": f"All recovery strategies exhausted for {context.tool_name}",
                    "urgency": self.EXHAUSTED_FALLBACK_URGENCY,
                },
                max_attempts=1, backoff_multiplier=1.0, success_probability=0.9, estimated_time=300,
            )

        scored = [
            (
                self._retry_policy.adjusted_success_probability(s, context.attempt_count)
                - (s.estimated_time / self.TIME_COST_DIVISOR),
                s,
            )
            for s in viable
        ]
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return scored[0][1]


# ============================================================================
# ErrorTelemetry
# ============================================================================

class ErrorTelemetry:
    """Records error occurrences and reports aggregate statistics.

    No recovery-decision logic lives here - just counting and snapshotting,
    same separation of concerns as redvector_cache_process.py's
    PerformanceTelemetry from Phase 1.7.
    """

    RECENT_WINDOW_SECONDS = 3600
    RECENT_DISPLAY_LIMIT = 10

    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self._history: "deque[ErrorContext]" = deque(maxlen=max_history)
        self._lock = threading.Lock()

    def record(self, context: ErrorContext) -> None:
        with self._lock:
            self._history.append(context)

    def __len__(self) -> int:
        with self._lock:
            return len(self._history)

    def history(self) -> "deque[ErrorContext]":
        """The underlying deque, for legacy direct access
        (e.g. ``error_handler.error_history``)."""
        return self._history

    def snapshot(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        """Get error statistics for monitoring"""
        with self._lock:
            history = list(self._history)

        if not history:
            return {"total_errors": 0}

        now = now or datetime.now()
        error_counts: Dict[str, int] = {}
        tool_errors: Dict[str, int] = {}
        recent_errors: List[Dict[str, Any]] = []

        for error in history:
            error_type = error.error_type.value
            tool = error.tool_name

            error_counts[error_type] = error_counts.get(error_type, 0) + 1
            tool_errors[tool] = tool_errors.get(tool, 0) + 1

            if (now - error.timestamp).total_seconds() < self.RECENT_WINDOW_SECONDS:
                recent_errors.append({
                    "tool": tool, "error_type": error_type, "timestamp": error.timestamp.isoformat(),
                })

        return {
            "total_errors": len(history),
            "error_counts_by_type": error_counts,
            "error_counts_by_tool": tool_errors,
            "recent_errors_count": len(recent_errors),
            "recent_errors": recent_errors[-self.RECENT_DISPLAY_LIMIT:],
        }


# ============================================================================
# ToolAlternativesRegistry
# ============================================================================

def default_tool_alternatives() -> Dict[str, List[str]]:
    """Alternative tools for fallback scenarios. Pure data."""
    return {
        # Network scanning alternatives
        "nmap": ["rustscan", "masscan", "zmap"],
        "rustscan": ["nmap", "masscan"],
        "masscan": ["nmap", "rustscan", "zmap"],

        # Directory/file discovery alternatives
        "gobuster": ["feroxbuster", "dirsearch", "ffuf", "dirb"],
        "feroxbuster": ["gobuster", "dirsearch", "ffuf"],
        "dirsearch": ["gobuster", "feroxbuster", "ffuf"],
        "ffuf": ["gobuster", "feroxbuster", "dirsearch"],

        # Vulnerability scanning alternatives
        "nuclei": ["jaeles", "nikto", "w3af"],
        "jaeles": ["nuclei", "nikto"],
        "nikto": ["nuclei", "jaeles", "w3af"],

        # Web crawling alternatives
        "katana": ["gau", "waybackurls", "hakrawler"],
        "gau": ["katana", "waybackurls", "hakrawler"],
        "waybackurls": ["gau", "katana", "hakrawler"],

        # Parameter discovery alternatives
        "arjun": ["paramspider", "x8", "ffuf"],
        "paramspider": ["arjun", "x8"],
        "x8": ["arjun", "paramspider"],

        # SQL injection alternatives
        "sqlmap": ["sqlninja", "jsql-injection"],

        # XSS testing alternatives
        "dalfox": ["xsser", "xsstrike"],

        # Subdomain enumeration alternatives
        "subfinder": ["amass", "assetfinder", "findomain"],
        "amass": ["subfinder", "assetfinder", "findomain"],
        "assetfinder": ["subfinder", "amass", "findomain"],

        # Cloud security alternatives
        "prowler": ["scout-suite", "cloudmapper"],
        "scout-suite": ["prowler", "cloudmapper"],

        # Container security alternatives
        "trivy": ["clair", "docker-bench-security"],
        "clair": ["trivy", "docker-bench-security"],

        # Binary analysis alternatives
        "ghidra": ["radare2", "ida", "binary-ninja"],
        "radare2": ["ghidra", "objdump", "gdb"],
        "gdb": ["radare2", "lldb"],

        # Exploitation alternatives
        "pwntools": ["ropper", "ropgadget"],
        "ropper": ["ropgadget", "pwntools"],
        "ropgadget": ["ropper", "pwntools"],
    }


class ToolAlternativesRegistry:
    """Maps a failed tool to candidate alternatives, with context-based
    filtering (e.g. "no tools that need root", "prefer faster tools")."""

    NO_PRIVILEGE_EXCLUSIONS = ("nmap", "masscan")
    FASTER_TOOL_EXCLUSIONS = ("amass", "w3af")

    def __init__(self, alternatives: Optional[Dict[str, List[str]]] = None):
        self._alternatives = alternatives if alternatives is not None else default_tool_alternatives()

    @property
    def alternatives(self) -> Dict[str, List[str]]:
        """Direct dict access, for legacy compatibility."""
        return self._alternatives

    def get(self, tool: str) -> List[str]:
        return self._alternatives.get(tool, [])

    def best_alternative(self, tool: str, context: Dict[str, Any]) -> Optional[str]:
        """Get alternative tool for failed tool"""
        candidates = self.get(tool)
        if not candidates:
            return None

        filtered = [
            alt for alt in candidates
            if not (context.get("require_no_privileges") and alt in self.NO_PRIVILEGE_EXCLUSIONS)
            and not (context.get("prefer_faster_tools") and alt in self.FASTER_TOOL_EXCLUSIONS)
        ]
        if not filtered:
            filtered = candidates

        return filtered[0] if filtered else None


# ============================================================================
# ParameterAdjustmentPolicy
# ============================================================================

def default_parameter_adjustments() -> Dict[str, Dict[ErrorType, Dict[str, Any]]]:
    """Tool/error-type-specific parameter adjustments. Pure data."""
    return {
        "nmap": {
            ErrorType.TIMEOUT: {"timing": "-T2", "reduce_ports": True},
            ErrorType.RATE_LIMITED: {"timing": "-T1", "delay": "1000ms"},
            ErrorType.RESOURCE_EXHAUSTED: {"max_parallelism": "10"},
        },
        "gobuster": {
            ErrorType.TIMEOUT: {"threads": "10", "timeout": "30s"},
            ErrorType.RATE_LIMITED: {"threads": "5", "delay": "1s"},
            ErrorType.RESOURCE_EXHAUSTED: {"threads": "5"},
        },
        "nuclei": {
            ErrorType.TIMEOUT: {"concurrency": "10", "timeout": "30"},
            ErrorType.RATE_LIMITED: {"rate-limit": "10", "concurrency": "5"},
            ErrorType.RESOURCE_EXHAUSTED: {"concurrency": "5"},
        },
        "feroxbuster": {
            ErrorType.TIMEOUT: {"threads": "10", "timeout": "30"},
            ErrorType.RATE_LIMITED: {"threads": "5", "rate-limit": "10"},
            ErrorType.RESOURCE_EXHAUSTED: {"threads": "5"},
        },
        "ffuf": {
            ErrorType.TIMEOUT: {"threads": "10", "timeout": "30"},
            ErrorType.RATE_LIMITED: {"threads": "5", "rate": "10"},
            ErrorType.RESOURCE_EXHAUSTED: {"threads": "5"},
        },
    }


def default_generic_adjustments() -> Dict[ErrorType, Dict[str, Any]]:
    """Fallback adjustments when no tool-specific entry exists, keyed by
    ErrorType instead of an if/elif chain."""
    return {
        ErrorType.TIMEOUT: {"timeout": "60", "threads": "5"},
        ErrorType.RATE_LIMITED: {"delay": "2s", "threads": "3"},
        ErrorType.RESOURCE_EXHAUSTED: {"threads": "3", "memory_limit": "1G"},
    }


class ParameterAdjustmentPolicy:
    """Tool/error-type -> parameter adjustments, with a generic fallback
    table for tools that have no dedicated entry."""

    def __init__(
        self,
        adjustments: Optional[Dict[str, Dict[ErrorType, Dict[str, Any]]]] = None,
        generic_adjustments: Optional[Dict[ErrorType, Dict[str, Any]]] = None,
    ):
        self._adjustments = adjustments if adjustments is not None else default_parameter_adjustments()
        self._generic = generic_adjustments if generic_adjustments is not None else default_generic_adjustments()

    def adjustments_for(self, tool: str, error_type: ErrorType) -> Dict[str, Any]:
        specific = self._adjustments.get(tool, {}).get(error_type, {})
        if specific:
            return specific
        return self._generic.get(error_type, {})

    def apply(self, tool: str, error_type: ErrorType, original_params: Dict[str, Any]) -> Dict[str, Any]:
        """Automatically adjust tool parameters based on error patterns"""
        adjustments = self.adjustments_for(tool, error_type)
        adjusted_params = dict(original_params)
        adjusted_params.update(adjustments)
        return adjusted_params


# ============================================================================
# HumanEscalationReporter
# ============================================================================

def _permission_denied_suggestions(context: ErrorContext) -> List[str]:
    return [
        "Run the command with sudo privileges",
        "Check file/directory permissions",
        "Verify user is in required groups",
    ]


def _tool_not_found_suggestions(context: ErrorContext) -> List[str]:
    return [
        f"Install {context.tool_name} using package manager",
        "Check if tool is in PATH",
        "Verify tool installation",
    ]


def _network_unreachable_suggestions(context: ErrorContext) -> List[str]:
    return ["Check network connectivity", "Verify target is accessible", "Check firewall rules"]


def _rate_limited_suggestions(context: ErrorContext) -> List[str]:
    return ["Wait before retrying", "Use slower scan rates", "Check API rate limits"]


DEFAULT_SUGGESTION_BUILDERS: Dict[ErrorType, Callable[[ErrorContext], List[str]]] = {
    ErrorType.PERMISSION_DENIED: _permission_denied_suggestions,
    ErrorType.TOOL_NOT_FOUND: _tool_not_found_suggestions,
    ErrorType.NETWORK_UNREACHABLE: _network_unreachable_suggestions,
    ErrorType.RATE_LIMITED: _rate_limited_suggestions,
}
DEFAULT_SUGGESTION_FALLBACK = ["Review error details and logs"]
RECENT_ERRORS_IN_ESCALATION = 5


class HumanEscalationReporter:
    """Builds the escalation payload for a human operator.

    Contains no logging - the project-specific formatting (ModernVisualEngine)
    lives in redvector_server.py, so the thin adapter there does the actual
    logger calls around this.
    """

    def __init__(self, suggestion_builders: Optional[Dict[ErrorType, Callable[[ErrorContext], List[str]]]] = None):
        self._suggestion_builders = (
            suggestion_builders if suggestion_builders is not None else dict(DEFAULT_SUGGESTION_BUILDERS)
        )

    def suggestions_for(self, context: ErrorContext) -> List[str]:
        """Get human-readable suggestions for error resolution"""
        builder = self._suggestion_builders.get(context.error_type)
        if builder is None:
            return list(DEFAULT_SUGGESTION_FALLBACK)
        return builder(context)

    def build_escalation(self, context: ErrorContext, urgency: str = "medium") -> Dict[str, Any]:
        """Escalate complex errors to human operator with full context"""
        return {
            "timestamp": context.timestamp.isoformat(),
            "tool": context.tool_name,
            "target": context.target,
            "error_type": context.error_type.value,
            "error_message": context.error_message,
            "attempt_count": context.attempt_count,
            "urgency": urgency,
            "suggested_actions": self.suggestions_for(context),
            "context": {
                "parameters": context.parameters,
                "system_resources": context.system_resources,
                "recent_errors": [e.error_message for e in context.previous_errors[-RECENT_ERRORS_IN_ESCALATION:]],
            },
        }


# ============================================================================
# System resource snapshot (for ErrorContext.system_resources)
# ============================================================================

def default_system_resource_snapshot() -> Dict[str, Any]:
    """Get current system resource information.

    Deliberately NOT the same shape as redvector_cache_process.py's
    SystemResourceMonitor.sample() - this is a separate, pre-existing
    contract (consumed by ErrorContext/escalation payloads) with its own
    field names, and changing it would be an external behavior change.
    """
    try:
        return {
            "cpu_percent": _psutil.cpu_percent(),
            "memory_percent": _psutil.virtual_memory().percent,
            "disk_percent": _psutil.disk_usage(_os.path.abspath(_os.sep)).percent,
            "load_average": _os.getloadavg() if hasattr(_os, 'getloadavg') else None,
            "active_processes": len(_psutil.pids()),
        }
    except Exception:
        return {"error": "Unable to get system resources"}


# ============================================================================
# FallbackChainCatalog
# ============================================================================

def default_fallback_chains() -> Dict[str, List[List[str]]]:
    """Fallback tool chains for critical operations. Pure data."""
    return {
        "network_discovery": [
            ["nmap", "rustscan", "masscan"],
            ["rustscan", "nmap"],
            ["ping", "telnet"],
        ],
        "web_discovery": [
            ["gobuster", "feroxbuster", "dirsearch"],
            ["feroxbuster", "ffuf"],
            ["curl", "wget"],
        ],
        "vulnerability_scanning": [
            ["nuclei", "jaeles", "nikto"],
            ["nikto", "w3af"],
            ["curl"],
        ],
        "subdomain_enumeration": [
            ["subfinder", "amass", "assetfinder"],
            ["amass", "findomain"],
            ["dig", "nslookup"],
        ],
        "parameter_discovery": [
            ["arjun", "paramspider", "x8"],
            ["ffuf", "wfuzz"],
            ["manual_testing"],
        ],
    }


def default_critical_operations() -> frozenset:
    return frozenset({
        "network_discovery",
        "web_discovery",
        "vulnerability_scanning",
        "subdomain_enumeration",
    })


def default_basic_fallbacks() -> Dict[str, List[str]]:
    return {
        "network_discovery": ["ping"],
        "web_discovery": ["curl"],
        "vulnerability_scanning": ["curl"],
        "subdomain_enumeration": ["dig"],
    }


@dataclass
class ChainSelection:
    """Result of picking a fallback chain: the chain itself, and whether it
    came from the curated chains or the last-resort basic fallback table
    (the two paths log differently in the adapter)."""
    chain: List[str]
    used_basic_fallback: bool


class FallbackChainCatalog:
    """Picks an alternate tool chain for an operation when some of its
    primary tools have already failed.

    Independent of DegradationPolicy below (which fills in missing
    *data*, not alternate *tools*).
    """

    DEFAULT_BASIC_FALLBACK = ["manual_testing"]

    def __init__(
        self,
        chains: Optional[Dict[str, List[List[str]]]] = None,
        critical_operations: Optional[Any] = None,
        basic_fallbacks: Optional[Dict[str, List[str]]] = None,
    ):
        self._chains = chains if chains is not None else default_fallback_chains()
        self._critical_operations = (
            set(critical_operations) if critical_operations is not None else set(default_critical_operations())
        )
        self._basic_fallbacks = basic_fallbacks if basic_fallbacks is not None else default_basic_fallbacks()

    @property
    def chains(self) -> Dict[str, List[List[str]]]:
        """Direct dict access, for legacy compatibility."""
        return self._chains

    @property
    def critical_operations(self) -> set:
        return self._critical_operations

    def chains_for(self, operation: str) -> List[List[str]]:
        return self._chains.get(operation, [])

    def select_chain(self, operation: str, failed_tools: Optional[List[str]] = None) -> ChainSelection:
        """Create fallback tool chain for critical operations"""
        failed_tools = failed_tools or []

        for chain in self.chains_for(operation):
            viable = [tool for tool in chain if tool not in failed_tools]
            if viable:
                return ChainSelection(chain=viable, used_basic_fallback=False)

        fallback = list(self._basic_fallbacks.get(operation, self.DEFAULT_BASIC_FALLBACK))
        return ChainSelection(chain=fallback, used_basic_fallback=True)

    def is_critical(self, operation: str) -> bool:
        return operation in self._critical_operations


# ============================================================================
# DegradationPolicy (protocol) + concrete subsystem policies + registry
# ============================================================================

class DegradationPolicy(Protocol):
    """Interface for filling a gap in partial results for one subsystem
    when its primary tool(s) failed."""

    def fill_gap(self, target: Optional[str]) -> Any:
        ...


class NetworkDiscoveryDegradation:
    """Fallback for network_discovery: a basic TCP connect-scan over
    common ports."""

    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
    CONNECT_TIMEOUT_SECONDS = 2

    def fill_gap(self, target: Optional[str]) -> List[int]:
        if not target:
            return []

        open_ports = []
        for port in self.COMMON_PORTS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.CONNECT_TIMEOUT_SECONDS)
                    if sock.connect_ex((target, port)) == 0:
                        open_ports.append(port)
            except Exception:
                continue
        return open_ports


class WebDiscoveryDegradation:
    """Fallback for web_discovery: HEAD requests against common paths.

    ``is_safe_target`` is injected because SSRF-safety checking is a
    project-wide, security-critical helper that lives in redvector_server.py
    and must not be duplicated here.
    """

    COMMON_DIRS = ["/admin", "/login", "/api", "/wp-admin", "/phpmyadmin", "/robots.txt"]
    REQUEST_TIMEOUT_SECONDS = 5
    OK_STATUS_CODES = (200, 301, 302, 403)

    def __init__(self, is_safe_target: Callable[[str], bool], http_head: Optional[Callable[..., Any]] = None):
        self._is_safe_target = is_safe_target
        self._http_head = http_head or (_requests.head if _requests is not None else None)

    def fill_gap(self, target: Optional[str]) -> List[str]:
        if not target or not self._is_safe_target(target) or self._http_head is None:
            return []

        found = []
        for directory in self.COMMON_DIRS:
            try:
                url = f"{target.rstrip('/')}{directory}"
                response = self._http_head(url, timeout=self.REQUEST_TIMEOUT_SECONDS, allow_redirects=True)
                if response.status_code in self.OK_STATUS_CODES:
                    found.append(directory)
            except Exception:
                continue
        return found


class VulnerabilityScanningDegradation:
    """Fallback for vulnerability_scanning: a basic missing-security-header
    check."""

    SECURITY_HEADERS = {
        "X-Frame-Options": "Clickjacking protection missing",
        "X-Content-Type-Options": "MIME type sniffing protection missing",
        "X-XSS-Protection": "XSS protection missing",
        "Strict-Transport-Security": "HTTPS enforcement missing",
        "Content-Security-Policy": "Content Security Policy missing",
    }
    REQUEST_TIMEOUT_SECONDS = 10

    def __init__(self, is_safe_target: Callable[[str], bool], http_get: Optional[Callable[..., Any]] = None):
        self._is_safe_target = is_safe_target
        self._http_get = http_get or (_requests.get if _requests is not None else None)

    def fill_gap(self, target: Optional[str]) -> List[Dict[str, Any]]:
        if not target or not self._is_safe_target(target) or self._http_get is None:
            return []

        vulnerabilities = []
        try:
            response = self._http_get(target, timeout=self.REQUEST_TIMEOUT_SECONDS)
            headers = response.headers
            for header, description in self.SECURITY_HEADERS.items():
                if header not in headers:
                    vulnerabilities.append({
                        "type": "missing_security_header", "severity": "medium",
                        "description": description, "header": header,
                    })
        except Exception as e:
            vulnerabilities.append({
                "type": "connection_error", "severity": "info",
                "description": f"Could not perform basic security check: {str(e)}",
            })
        return vulnerabilities


class DegradationPolicyRegistry:
    """Maps operation name -> DegradationPolicy, replacing the if/elif
    dispatch in handle_partial_failure with registration + lookup."""

    def __init__(self, policies: Optional[Dict[str, DegradationPolicy]] = None):
        self._policies: Dict[str, DegradationPolicy] = policies if policies is not None else {}

    def get(self, operation: str) -> Optional[DegradationPolicy]:
        return self._policies.get(operation)

    def register(self, operation: str, policy: DegradationPolicy) -> None:
        self._policies[operation] = policy


# Which partial_results key each operation's DegradationPolicy fills, and
# only when that key is absent - replacing the original's 3-branch
# if/elif chain inside handle_partial_failure.
GAP_KEY_BY_OPERATION: Dict[str, str] = {
    "network_discovery": "open_ports",
    "web_discovery": "directories",
    "vulnerability_scanning": "vulnerabilities",
}


# ============================================================================
# ManualRecommendationCatalog
# ============================================================================

def default_manual_recommendations() -> Dict[str, List[str]]:
    return {
        "network_discovery": [
            "Manually test common ports using telnet or nc",
            "Check for service banners manually",
            "Use online port scanners as alternative",
        ],
        "web_discovery": [
            "Manually browse common directories",
            "Check robots.txt and sitemap.xml",
            "Use browser developer tools for endpoint discovery",
        ],
        "vulnerability_scanning": [
            "Manually test for common vulnerabilities",
            "Check security headers using browser tools",
            "Perform manual input validation testing",
        ],
        "subdomain_enumeration": [
            "Use online subdomain discovery tools",
            "Check certificate transparency logs",
            "Perform manual DNS queries",
        ],
    }


def default_component_specific_recommendations() -> Dict[str, str]:
    return {
        "nmap": "Consider using online port scanners",
        "gobuster": "Try manual directory browsing",
        "nuclei": "Perform manual vulnerability testing",
    }


class ManualRecommendationCatalog:
    """operation/component -> manual follow-up recommendations."""

    def __init__(
        self,
        base_recommendations: Optional[Dict[str, List[str]]] = None,
        component_specific: Optional[Dict[str, str]] = None,
    ):
        self._base = base_recommendations if base_recommendations is not None else default_manual_recommendations()
        self._component_specific = (
            component_specific if component_specific is not None else default_component_specific_recommendations()
        )

    def recommendations_for(self, operation: str, failed_components: List[str]) -> List[str]:
        """Get manual recommendations for failed operations"""
        recommendations = list(self._base.get(operation, []))
        for component in failed_components:
            extra = self._component_specific.get(component)
            if extra:
                recommendations.append(extra)
        return recommendations


# ============================================================================
# GracefulDegradationCoordinator
# ============================================================================

class GracefulDegradationCoordinator:
    """Composes chain selection, gap-filling policies and manual
    recommendations for the create_fallback_chain/handle_partial_failure/
    is_critical_operation use cases, keeping each concern a separate,
    independently-testable collaborator rather than one class owning all
    three directly.
    """

    def __init__(
        self,
        chain_catalog: Optional[FallbackChainCatalog] = None,
        degradation_registry: Optional[DegradationPolicyRegistry] = None,
        recommendation_catalog: Optional[ManualRecommendationCatalog] = None,
        gap_key_by_operation: Optional[Dict[str, str]] = None,
    ):
        self.chain_catalog = chain_catalog or FallbackChainCatalog()
        self.degradation_registry = degradation_registry or DegradationPolicyRegistry()
        self.recommendation_catalog = recommendation_catalog or ManualRecommendationCatalog()
        self._gap_key_by_operation = (
            gap_key_by_operation if gap_key_by_operation is not None else dict(GAP_KEY_BY_OPERATION)
        )

    def select_fallback_chain(self, operation: str, failed_tools: Optional[List[str]] = None) -> ChainSelection:
        return self.chain_catalog.select_chain(operation, failed_tools)

    def is_critical_operation(self, operation: str) -> bool:
        return self.chain_catalog.is_critical(operation)

    def handle_partial_failure(
        self, operation: str, partial_results: Dict[str, Any], failed_components: List[str],
    ) -> Dict[str, Any]:
        """Handle partial results and fill gaps with alternative methods"""
        enhanced_results = dict(partial_results)
        enhanced_results["degradation_info"] = {
            "operation": operation,
            "failed_components": failed_components,
            "partial_success": True,
            "fallback_applied": True,
            "timestamp": datetime.now().isoformat(),
        }

        gap_key = self._gap_key_by_operation.get(operation)
        policy = self.degradation_registry.get(operation)
        if policy is not None and gap_key is not None and gap_key not in partial_results:
            enhanced_results[gap_key] = policy.fill_gap(partial_results.get("target"))

        enhanced_results["manual_recommendations"] = self.recommendation_catalog.recommendations_for(
            operation, failed_components
        )
        return enhanced_results


# ============================================================================
# ResilientExecutor
# ============================================================================

@dataclass
class ExecutionOutcome:
    """Result of a ResilientExecutor.run() call - always returned, never
    raised, regardless of how many attempts failed."""
    success: bool
    result: Any = None
    error: Optional[str] = None
    attempts_made: int = 0
    recovery_applied: bool = False
    final_action: Optional[str] = None


class ResilientExecutor:
    """Thin coordinator: run a callable, and on failure classify the
    error, select a recovery strategy, and either retry (honoring
    RetryPolicy) or apply a DegradationPolicy fallback.

    It does not know how to run a different tool, rebuild a command, or
    sleep for a backoff delay - those require project-specific context
    (the actual command string, available tool implementations) that only
    a caller can provide, so for recovery actions it can't itself carry
    out (tool-switching, human escalation, abort), it reports the chosen
    action back via ``final_action`` rather than performing it.
    """

    def __init__(
        self,
        classifier: ErrorClassifier,
        strategy_registry: RecoveryStrategyRegistry,
        selector: RecoveryDecisionStrategy,
        retry_policy: Optional[RetryPolicy] = None,
        telemetry: Optional[ErrorTelemetry] = None,
        degradation_registry: Optional[DegradationPolicyRegistry] = None,
    ):
        self._classifier = classifier
        self._strategy_registry = strategy_registry
        self._selector = selector
        self._retry_policy = retry_policy or RetryPolicy()
        self._telemetry = telemetry
        self._degradation_registry = degradation_registry

    def run(
        self,
        operation: Callable[[], Any],
        *,
        tool_name: str,
        target: str = "unknown",
        parameters: Optional[Dict[str, Any]] = None,
        max_attempts: int = 3,
        degradation_operation: Optional[str] = None,
        is_success: Callable[[Any], bool] = lambda result: True,
    ) -> ExecutionOutcome:
        parameters = parameters or {}
        attempt = 0
        last_error: Optional[str] = None

        while attempt < max_attempts:
            attempt += 1

            try:
                result = operation()
            except Exception as exc:
                last_error = str(exc)
                error_type = self._classifier.classify(last_error, exc)
                context = ErrorContext(
                    tool_name=tool_name, target=target, parameters=parameters, error_type=error_type,
                    error_message=last_error, attempt_count=attempt, timestamp=datetime.now(),
                    stack_trace="", system_resources={},
                )
                if self._telemetry is not None:
                    self._telemetry.record(context)

                candidates = self._strategy_registry.get(error_type)
                strategy = self._selector.select(candidates, context)

                if (
                    strategy.action in (RecoveryAction.RETRY_WITH_BACKOFF, RecoveryAction.RETRY_WITH_REDUCED_SCOPE,
                                        RecoveryAction.ADJUST_PARAMETERS)
                    and self._retry_policy.is_retry_allowed(strategy, attempt)
                    and attempt < max_attempts
                ):
                    continue

                if strategy.action == RecoveryAction.GRACEFUL_DEGRADATION and self._degradation_registry is not None:
                    policy = self._degradation_registry.get(degradation_operation or tool_name)
                    if policy is not None:
                        return ExecutionOutcome(
                            success=True, result=policy.fill_gap(target), attempts_made=attempt,
                            recovery_applied=True, final_action=RecoveryAction.GRACEFUL_DEGRADATION.value,
                        )

                return ExecutionOutcome(
                    success=False, error=last_error, attempts_made=attempt,
                    recovery_applied=True, final_action=strategy.action.value,
                )
            else:
                if is_success(result):
                    return ExecutionOutcome(
                        success=True, result=result, attempts_made=attempt, recovery_applied=attempt > 1,
                    )
                last_error = "operation did not report success"

        return ExecutionOutcome(
            success=False, error=last_error or "max attempts exhausted", attempts_made=attempt,
            recovery_applied=True, final_action="all_attempts_exhausted",
        )

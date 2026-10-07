#!/usr/bin/env python3
"""
RedVector AI - typed configuration & startup model (Phase 4).

Centralizes RedVector's previously-scattered configuration reads (module
globals + ad-hoc ``os.environ.get`` in ``redvector_server.py`` /
``redvector_mcp.py``) behind a typed, provenance-tracked model, WITHOUT changing
any externally-observable behavior.

Conceptual flow:

    Environment / CLI / (future) config files
              |
    Typed RedVector configuration (resolvers below)
              |
    Validation + normalization (preserved exactly)
              |
    Startup plan (descriptor, for provenance/testing)
              |
    Flask / MCP / supporting services   (unchanged)

Hard compatibility rules (this phase):
  * Every resolver reproduces the CURRENT expression byte-for-byte, including
    type coercion and error behavior. In particular ``server port`` is
    ``int(os.environ.get("REDVECTOR_PORT", 8888))`` - an empty or malformed
    ``REDVECTOR_PORT`` raises ``ValueError`` at the same point, exactly as
    before. No default is silently substituted for empty/malformed input.
  * No env-var name, default, precedence, host, port, timeout, URL, model, or
    logging value is changed.
  * Secrets (tokens / api keys) are tracked by SOURCE only; their values are
    never placed in provenance or logs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


# ============================================================================
# Provenance
# ============================================================================

class ConfigSource(str, Enum):
    ENV = "environment"
    CLI = "cli"
    FILE = "config_file"
    DEFAULT = "default"
    DERIVED = "derived"
    CONSTANT = "constant"


@dataclass(frozen=True)
class ConfigValue:
    """A single resolved setting with provenance. ``value`` is omitted from the
    redacted view when ``secret`` is set."""
    name: str
    value: Any
    source: ConfigSource
    default_used: bool
    normalization: str
    consumer: str
    env_var: Optional[str] = None
    default: Any = None
    secret: bool = False

    def redacted(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "value": "***REDACTED***" if self.secret else self.value,
            "source": self.source.value,
            "default_used": self.default_used,
            "normalization": self.normalization,
            "consumer": self.consumer,
            "env_var": self.env_var,
            "secret": self.secret,
        }


class Provenance:
    """Ordered collection of ConfigValue records. Never stores secret values in
    a loggable form (``as_log`` redacts secrets)."""

    def __init__(self) -> None:
        self._items: List[ConfigValue] = []

    def record(self, cv: ConfigValue) -> ConfigValue:
        self._items.append(cv)
        return cv

    def items(self) -> List[ConfigValue]:
        return list(self._items)

    def as_log(self) -> List[Dict[str, Any]]:
        return [cv.redacted() for cv in self._items]


# ---------------------------------------------------------------------------
# Resolution helpers (preserve exact expressions + record provenance)
# ---------------------------------------------------------------------------

def _resolve(prov: Optional[Provenance], name: str, env_var: Optional[str],
             default: Any, consumer: str, normalization: str,
             coerce: Callable[[str], Any] = lambda s: s, secret: bool = False) -> Any:
    """Reproduce ``coerce(os.environ.get(env_var, default))`` semantics exactly.

    When ``env_var`` is present in the environment, the raw string is coerced
    (``coerce`` may raise, exactly as the original ``int(...)`` did); otherwise
    the hard-coded ``default`` is used verbatim (NOT coerced), matching
    ``int(os.environ.get("X", 8888))`` where the default is already an int."""
    if env_var is not None and env_var in os.environ:
        raw = os.environ[env_var]
        value = coerce(raw)
        source = ConfigSource.ENV
        default_used = False
    else:
        value = default
        source = ConfigSource.DEFAULT if env_var is not None else ConfigSource.CONSTANT
        default_used = env_var is not None
    if prov is not None:
        prov.record(ConfigValue(name=name, value=value, source=source,
                                default_used=default_used, normalization=normalization,
                                consumer=consumer, env_var=env_var, default=default,
                                secret=secret))
    return value


def _debug_truthy(raw: str) -> bool:
    return raw.lower() in ("1", "true", "yes", "y")


# ============================================================================
# Typed configuration model
# ============================================================================

@dataclass(frozen=True)
class ServerNetworkConfig:
    port: int
    host: str
    token: str          # secret


@dataclass(frozen=True)
class RuntimeConfig:
    debug_mode: bool
    command_timeout: int
    cache_size: int
    cache_ttl: int
    max_cached_result_bytes: int


@dataclass(frozen=True)
class LLMConfig:
    base_url: str
    api_key: str        # secret
    default_model: str
    timeout: int
    default_url: str = "http://127.0.0.1:11434"


@dataclass(frozen=True)
class LoggingConfig:
    """Descriptor of the (import-time, intentionally unchanged) logging setup."""
    level: str = "INFO"
    server_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    server_file: str = "redvector.log"
    server_stream: str = "stdout"
    mcp_format: str = "[🔥 RedVector MCP] %(asctime)s [%(levelname)s] %(message)s"
    mcp_stream: str = "stderr"


@dataclass(frozen=True)
class MCPConfig:
    default_server: str
    default_timeout: int
    max_retries: int
    api_token: str      # secret
    allow_insecure: bool
    # CLI defaults (argparse) - frozen contract
    cli_transport: str = "stdio"
    cli_mcp_port: int = 8889
    cli_mcp_host: str = "127.0.0.1"


@dataclass(frozen=True)
class PathConfig:
    """Explicit, testable path anchors (behavior-preserving: relative paths used
    by the current code remain relative to the process cwd)."""
    project_root: str

    def resolve(self, relative: str) -> str:
        return os.path.join(self.project_root, relative)


# Defaults frozen from the untouched implementation.
LLM_DEFAULT_URL = "http://127.0.0.1:11434"
MCP_DEFAULT_SERVER = "http://127.0.0.1:8888"
MCP_DEFAULT_TIMEOUT = 300
MCP_MAX_RETRIES = 3
SERVER_COMMAND_TIMEOUT = 300
SERVER_CACHE_SIZE = 1000
SERVER_CACHE_TTL = 3600
SERVER_MAX_CACHED_RESULT_BYTES = 10 * 1024 * 1024


# ============================================================================
# Resolvers
# ============================================================================

def resolve_server_network(prov: Optional[Provenance] = None) -> ServerNetworkConfig:
    port = _resolve(prov, "server.port", "REDVECTOR_PORT", 8888,
                    "redvector_server.API_PORT", "int(env or 8888)", coerce=int)
    host = _resolve(prov, "server.host", "REDVECTOR_HOST", "127.0.0.1",
                    "redvector_server.API_HOST", "str")
    token = _resolve(prov, "server.token", "REDVECTOR_API_TOKEN", "redvector-dev-token",
                     "redvector_server.API_TOKEN", "str", secret=True)
    return ServerNetworkConfig(port=port, host=host, token=token)


def resolve_runtime(prov: Optional[Provenance] = None) -> RuntimeConfig:
    debug = _resolve(prov, "runtime.debug_mode", "DEBUG_MODE", "0",
                     "redvector_server.DEBUG_MODE", "lower in {1,true,yes,y}",
                     coerce=lambda r: r)
    # NOTE: the original computes membership AFTER get(...).lower(); reproduce it
    # on the resolved raw/default exactly.
    debug_bool = str(debug).lower() in ("1", "true", "yes", "y")
    return RuntimeConfig(
        debug_mode=debug_bool,
        command_timeout=SERVER_COMMAND_TIMEOUT,
        cache_size=SERVER_CACHE_SIZE,
        cache_ttl=SERVER_CACHE_TTL,
        max_cached_result_bytes=SERVER_MAX_CACHED_RESULT_BYTES,
    )


def resolve_llm(prov: Optional[Provenance] = None,
                default_url: str = LLM_DEFAULT_URL) -> LLMConfig:
    base_url = _resolve(prov, "llm.base_url", "LLM_BASE_URL", default_url,
                        "LLMConfig.base_url", "str")
    api_key = _resolve(prov, "llm.api_key", "LLM_API_KEY", "ollama",
                       "LLMConfig.api_key", "str", secret=True)
    model = _resolve(prov, "llm.default_model", "LLM_MODEL", "",
                     "LLMConfig.default_model", "str")
    timeout = _resolve(prov, "llm.timeout", "LLM_TIMEOUT", "120",
                       "LLMConfig.timeout", "int(env or '120')", coerce=lambda r: r)
    timeout_int = int(timeout)
    return LLMConfig(base_url=base_url, api_key=api_key, default_model=model,
                     timeout=timeout_int, default_url=default_url)


def resolve_mcp(prov: Optional[Provenance] = None) -> MCPConfig:
    token = _resolve(prov, "mcp.api_token", "REDVECTOR_API_TOKEN", "redvector-dev-token",
                     "redvector_mcp.RedVectorClient.api_token", "str", secret=True)
    insecure_raw = _resolve(prov, "mcp.allow_insecure", "REDVECTOR_ALLOW_INSECURE", "0",
                            "redvector_mcp allow_insecure", "== '1'", coerce=lambda r: r)
    return MCPConfig(
        default_server=MCP_DEFAULT_SERVER,
        default_timeout=MCP_DEFAULT_TIMEOUT,
        max_retries=MCP_MAX_RETRIES,
        api_token=token,
        allow_insecure=(str(insecure_raw) == "1"),
    )


def logging_config() -> LoggingConfig:
    return LoggingConfig()


def path_config(project_root: Optional[str] = None) -> PathConfig:
    return PathConfig(project_root=project_root or os.path.dirname(os.path.abspath(__file__)))


@dataclass(frozen=True)
class RedVectorConfig:
    server_network: ServerNetworkConfig
    runtime: RuntimeConfig
    llm: LLMConfig
    mcp: MCPConfig
    logging: LoggingConfig
    paths: PathConfig


def resolve_all(prov: Optional[Provenance] = None) -> RedVectorConfig:
    return RedVectorConfig(
        server_network=resolve_server_network(prov),
        runtime=resolve_runtime(prov),
        llm=resolve_llm(prov),
        mcp=resolve_mcp(prov),
        logging=logging_config(),
        paths=path_config(),
    )


# ============================================================================
# Startup plan (descriptor only - does NOT change actual init order)
# ============================================================================

@dataclass(frozen=True)
class StartupStep:
    name: str
    description: str


@dataclass(frozen=True)
class StartupPlan:
    target: str
    steps: List[StartupStep] = field(default_factory=list)

    def step_names(self) -> List[str]:
        return [s.name for s in self.steps]


def build_server_startup_plan() -> StartupPlan:
    """Describes the ACTUAL server startup order in redvector_server.py
    __main__ (banner -> argparse -> apply CLI -> flush -> startup log ->
    app.run). Logging is configured at import, before __main__."""
    return StartupPlan("server", [
        StartupStep("configure_logging", "logging.basicConfig at import (INFO, file redvector.log)"),
        StartupStep("resolve_config", "API_PORT/HOST/TOKEN + runtime constants"),
        StartupStep("initialize_services", "Flask app, cache, registries at import"),
        StartupStep("print_banner", "print(BANNER)"),
        StartupStep("parse_cli", "argparse --debug/--port/--host"),
        StartupStep("apply_cli_overrides", "CLI port/host override env-resolved values"),
        StartupStep("emit_startup_info", "flush + startup banner log lines"),
        StartupStep("run_flask", "app.run(host, port, debug=False, use_reloader=False)"),
    ])


def build_mcp_startup_plan() -> StartupPlan:
    """Describes the ACTUAL MCP startup order in redvector_mcp.py main()."""
    return StartupPlan("mcp", [
        StartupStep("configure_logging", "logging.basicConfig at import (INFO, stderr)"),
        StartupStep("parse_cli", "argparse --server/--timeout/--transport/--mcp-port/--mcp-host/--debug"),
        StartupStep("apply_debug", "logger.setLevel(DEBUG) if --debug"),
        StartupStep("init_client", "RedVectorClient(server, timeout) + HTTPS guard + health retries"),
        StartupStep("check_health", "client.check_health()"),
        StartupStep("setup_mcp_server", "register 328 tools (Phase 2 architecture, unchanged)"),
        StartupStep("configure_transport", "sse/streamable-http host+port else stdio"),
        StartupStep("run_mcp", "mcp.run(transport=...)"),
    ])


# ============================================================================
# Validation / normalization (light; preserves current behavior)
# ============================================================================

class ConfigValidator:
    @staticmethod
    def validate_port(port: int) -> int:
        # The current code performs no range validation; preserve that (no-op).
        return port


class ConfigNormalizer:
    @staticmethod
    def normalize_server_url(url: str) -> str:
        # Mirrors RedVectorClient: rstrip("/") is applied by the client itself;
        # not applied here to avoid changing behavior.
        return url

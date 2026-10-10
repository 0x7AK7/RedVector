#!/usr/bin/env python3
"""
RedVector AI - AI Integration Manager (Phase 7).

A self-contained, additive subsystem that lets a user connect/test/switch AI
providers and configure MCP clients WITHOUT hand-editing JSON config files. It
does not change any existing RedVector behavior: the legacy ``LLMClient`` and
``/api/llm/*`` routes are untouched; this module adds a new management layer and
new ``/api/ai/*`` routes (wired in ``redvector_server.py``).

Two clearly-separated systems:

  * AI PROVIDERS  - model services used BY RedVector (Claude, Gemini, DeepSeek,
    Ollama). RedVector is the client.
  * MCP CLIENTS   - external AI apps that connect TO RedVector over MCP (Claude
    Desktop, Cursor, ChatGPT). RedVector is the MCP server.

Design for testability + safety:
  * All network access goes through an injectable ``transport`` callable; tests
    inject a fake and no real request is made.
  * All client-config filesystem access is rooted at an injectable ``home``
    directory; tests pass a temp dir and never touch the real user config.
  * Credentials go through a ``CredentialStore`` abstraction; the default uses
    the OS keyring when available and otherwise a safe, read-only env fallback -
    it never silently writes plaintext secrets. Tests use an in-memory store.
  * Secrets are never logged, echoed, or placed in results/errors.
  * Provider switching is transactional: on any validation failure the previous
    active provider is kept.
"""

from __future__ import annotations

import json
import os
import platform
import tempfile
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


# ============================================================================
# Enums / status
# ============================================================================

class AIProviderId(str, Enum):
    CLAUDE = "claude"
    GEMINI = "gemini"
    DEEPSEEK = "deepseek"
    OLLAMA = "ollama"


class MCPClientId(str, Enum):
    CLAUDE_DESKTOP = "claude_desktop"
    CURSOR = "cursor"
    CHATGPT = "chatgpt"


class IntegrationStatus(str, Enum):
    NOT_INSTALLED = "not_installed"
    DETECTED = "detected"
    NOT_CONFIGURED = "not_configured"
    CONFIGURED = "configured"
    CONNECTED = "connected"
    RESTART_REQUIRED = "restart_required"
    AUTH_REQUIRED = "auth_required"
    MISCONFIGURED = "misconfigured"
    UNREACHABLE = "unreachable"
    SETUP_REQUIRED = "setup_required"
    ERROR = "error"


# ============================================================================
# Secret redaction
# ============================================================================

def redact_secret(value: Optional[str]) -> str:
    if not value:
        return "(none)"
    if len(value) <= 8:
        return "***"
    return value[:3] + "***" + value[-2:]


def scrub(obj: Any, secret_keys=("api_key", "apikey", "authorization", "token",
                                  "secret", "x-api-key", "key")) -> Any:
    """Recursively redact secret-looking keys for safe logging/output."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in secret_keys:
                out[k] = "***REDACTED***"
            else:
                out[k] = scrub(v, secret_keys)
        return out
    if isinstance(obj, list):
        return [scrub(x, secret_keys) for x in obj]
    return obj


# ============================================================================
# Typed models
# ============================================================================

@dataclass(frozen=True)
class ProviderCapabilities:
    is_local: bool
    needs_api_key: bool
    model_discovery: bool
    config_fields: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class AIModelInfo:
    id: str
    provider: str


@dataclass(frozen=True)
class AIProviderConfig:
    provider_id: str
    endpoint: str
    model: str = ""
    timeout: int = 60
    # api key is NEVER stored here; it is resolved from the CredentialStore


@dataclass(frozen=True)
class ProviderHealth:
    provider_id: str
    status: IntegrationStatus
    detail: str = ""
    endpoint_reachable: bool = False
    auth_valid: Optional[bool] = None
    model_available: Optional[bool] = None


@dataclass(frozen=True)
class ProviderConnectionResult:
    provider_id: str
    ok: bool
    status: IntegrationStatus
    message: str
    models: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class IntegrationOperationResult:
    ok: bool
    status: IntegrationStatus
    message: str
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "status": self.status.value, "message": self.message,
                "data": scrub(self.data)}


# ============================================================================
# Credential store
# ============================================================================

class CredentialStore:
    """Abstract secure credential storage. Implementations must never return
    secrets in logs and should prefer OS-secure storage."""
    service = "redvector-ai"

    def store(self, key: str, secret: str) -> bool: raise NotImplementedError
    def retrieve(self, key: str) -> Optional[str]: raise NotImplementedError
    def delete(self, key: str) -> bool: raise NotImplementedError
    def exists(self, key: str) -> bool: return self.retrieve(key) is not None
    @property
    def backend(self) -> str: return "abstract"
    @property
    def secure(self) -> bool: return False


class MemoryCredentialStore(CredentialStore):
    """In-memory store for tests and ephemeral use. Not persisted."""
    def __init__(self) -> None:
        self._d: Dict[str, str] = {}
    def store(self, key: str, secret: str) -> bool:
        self._d[key] = secret; return True
    def retrieve(self, key: str) -> Optional[str]:
        return self._d.get(key)
    def delete(self, key: str) -> bool:
        return self._d.pop(key, None) is not None
    @property
    def backend(self) -> str: return "memory"
    @property
    def secure(self) -> bool: return False


class KeyringCredentialStore(CredentialStore):
    """OS keyring-backed store (Windows Credential Manager / macOS Keychain /
    Secret Service) when the optional ``keyring`` package is available."""
    def __init__(self, keyring_module) -> None:
        self._kr = keyring_module
    def store(self, key: str, secret: str) -> bool:
        self._kr.set_password(self.service, key, secret); return True
    def retrieve(self, key: str) -> Optional[str]:
        return self._kr.get_password(self.service, key)
    def delete(self, key: str) -> bool:
        try:
            self._kr.delete_password(self.service, key); return True
        except Exception:
            return False
    @property
    def backend(self) -> str: return "keyring"
    @property
    def secure(self) -> bool: return True


class EnvCredentialStore(CredentialStore):
    """Read-only fallback: resolves secrets from environment variables and
    REFUSES to persist plaintext. Used only when no secure keyring exists."""
    ENV_MAP = {
        "claude": "ANTHROPIC_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "ollama": "LLM_API_KEY",
    }
    def store(self, key: str, secret: str) -> bool:
        return False  # never writes plaintext silently
    def retrieve(self, key: str) -> Optional[str]:
        return os.environ.get(self.ENV_MAP.get(key, ""), None) or None
    def delete(self, key: str) -> bool:
        return False
    @property
    def backend(self) -> str: return "env(read-only)"
    @property
    def secure(self) -> bool: return False


def get_credential_store() -> CredentialStore:
    """Return the best available credential store without adding a hard
    dependency: OS keyring if importable, else a safe read-only env fallback."""
    try:
        import keyring  # optional
        # verify a usable backend is configured
        kr = keyring.get_keyring()
        if kr is not None:
            return KeyringCredentialStore(keyring)
    except Exception:
        pass
    return EnvCredentialStore()


# ============================================================================
# Provider registry (source of truth)
# ============================================================================

@dataclass(frozen=True)
class ProviderDefinition:
    provider_id: AIProviderId
    display_name: str
    capabilities: ProviderCapabilities
    default_endpoint: str
    models_path: str            # path appended to endpoint for discovery/health
    credential_key: str


PROVIDER_DEFINITIONS: Dict[AIProviderId, ProviderDefinition] = {
    AIProviderId.OLLAMA: ProviderDefinition(
        AIProviderId.OLLAMA, "Ollama (local)",
        ProviderCapabilities(is_local=True, needs_api_key=False, model_discovery=True,
                             config_fields=["endpoint", "model"]),
        "http://127.0.0.1:11434", "/v1/models", "ollama"),
    AIProviderId.CLAUDE: ProviderDefinition(
        AIProviderId.CLAUDE, "Claude API (Anthropic)",
        ProviderCapabilities(is_local=False, needs_api_key=True, model_discovery=True,
                             config_fields=["endpoint", "model", "api_key"]),
        "https://api.anthropic.com", "/v1/models", "claude"),
    AIProviderId.GEMINI: ProviderDefinition(
        AIProviderId.GEMINI, "Gemini API (Google)",
        ProviderCapabilities(is_local=False, needs_api_key=True, model_discovery=True,
                             config_fields=["endpoint", "model", "api_key"]),
        "https://generativelanguage.googleapis.com", "/v1beta/models", "gemini"),
    AIProviderId.DEEPSEEK: ProviderDefinition(
        AIProviderId.DEEPSEEK, "DeepSeek API",
        ProviderCapabilities(is_local=False, needs_api_key=True, model_discovery=True,
                             config_fields=["endpoint", "model", "api_key"]),
        "https://api.deepseek.com", "/v1/models", "deepseek"),
}


# ============================================================================
# HTTP transport (injectable; default lazily uses requests)
# ============================================================================

@dataclass(frozen=True)
class HTTPResponse:
    status: int
    json: Any = None
    error: Optional[str] = None


def _default_transport(method: str, url: str, headers: Dict[str, str],
                       timeout: int) -> HTTPResponse:
    try:
        import requests
        resp = requests.request(method, url, headers=headers, timeout=timeout)
        try:
            body = resp.json()
        except Exception:
            body = None
        return HTTPResponse(status=resp.status_code, json=body)
    except Exception as e:  # ConnectionError etc.
        return HTTPResponse(status=0, error=type(e).__name__)


Transport = Callable[[str, str, Dict[str, str], int], HTTPResponse]


# ============================================================================
# AI providers
# ============================================================================

class AIProvider:
    def __init__(self, definition: ProviderDefinition, config: AIProviderConfig,
                 credentials: CredentialStore, transport: Transport) -> None:
        self.definition = definition
        self.config = config
        self.credentials = credentials
        self.transport = transport

    @property
    def provider_id(self) -> str:
        return self.definition.provider_id.value

    # --- auth headers (secrets never logged) ---
    def _auth_headers(self) -> Dict[str, str]:
        key = self.credentials.retrieve(self.definition.credential_key)
        d = self.definition
        if d.provider_id == AIProviderId.CLAUDE:
            h = {"content-type": "application/json", "anthropic-version": "2023-06-01"}
            if key:
                h["x-api-key"] = key
            return h
        if d.provider_id == AIProviderId.GEMINI:
            # Gemini uses ?key=; header carries nothing sensitive here
            return {"content-type": "application/json"}
        # OpenAI-compatible (DeepSeek, Ollama)
        h = {"content-type": "application/json"}
        if key:
            h["authorization"] = "Bearer %s" % key
        return h

    def _models_url(self) -> str:
        base = self.config.endpoint.rstrip("/")
        path = self.definition.models_path
        if self.definition.provider_id == AIProviderId.GEMINI:
            key = self.credentials.retrieve(self.definition.credential_key)
            return base + path + ("?key=%s" % key if key else "")
        return base + path

    def validate_configuration(self) -> IntegrationOperationResult:
        if self.definition.capabilities.needs_api_key and not \
                self.credentials.exists(self.definition.credential_key):
            return IntegrationOperationResult(
                False, IntegrationStatus.AUTH_REQUIRED,
                "%s requires an API key; none configured." % self.definition.display_name)
        if not self.config.endpoint:
            return IntegrationOperationResult(False, IntegrationStatus.MISCONFIGURED,
                                              "No endpoint configured.")
        return IntegrationOperationResult(True, IntegrationStatus.CONFIGURED, "Configuration present.")

    def health_check(self) -> ProviderHealth:
        pid = self.provider_id
        resp = self.transport("GET", self._models_url(), self._auth_headers(),
                              min(self.config.timeout, 15))
        if resp.status == 0:
            return ProviderHealth(pid, IntegrationStatus.UNREACHABLE,
                                  "Endpoint not reachable (%s)." % (resp.error or "connection error"),
                                  endpoint_reachable=False)
        if resp.status in (401, 403):
            return ProviderHealth(pid, IntegrationStatus.AUTH_REQUIRED,
                                  "Authentication rejected by %s." % self.definition.display_name,
                                  endpoint_reachable=True, auth_valid=False)
        if 200 <= resp.status < 300:
            return ProviderHealth(pid, IntegrationStatus.CONNECTED, "Reachable and authorized.",
                                  endpoint_reachable=True, auth_valid=True)
        return ProviderHealth(pid, IntegrationStatus.ERROR,
                              "Unexpected HTTP %s from provider." % resp.status,
                              endpoint_reachable=True)

    def list_models(self) -> List[AIModelInfo]:
        if not self.definition.capabilities.model_discovery:
            return []
        resp = self.transport("GET", self._models_url(), self._auth_headers(),
                              min(self.config.timeout, 15))
        if not (200 <= resp.status < 300) or not isinstance(resp.json, (dict, list)):
            return []
        ids: List[str] = []
        data = resp.json
        if isinstance(data, dict) and "data" in data:            # OpenAI-compatible
            ids = [m.get("id", "") for m in data.get("data", []) if isinstance(m, dict)]
        elif isinstance(data, dict) and "models" in data:        # Gemini / Ollama tags
            for m in data.get("models", []):
                if isinstance(m, dict):
                    ids.append(m.get("name") or m.get("id") or "")
        return [AIModelInfo(id=i, provider=self.provider_id) for i in ids if i]

    def get_active_model(self) -> str:
        return self.config.model

    def basic_generation_test(self) -> IntegrationOperationResult:
        """Lightweight reachability/auth check (NOT a billed generation)."""
        h = self.health_check()
        return IntegrationOperationResult(h.status == IntegrationStatus.CONNECTED,
                                          h.status, h.detail)


# ============================================================================
# Provider manager (active provider + transactional switching + fallback)
# ============================================================================

@dataclass
class ProviderState:
    active_provider: Optional[str] = None
    active_model: str = ""
    fallback_provider: Optional[str] = None
    fallback_enabled: bool = False


class AIProviderManager:
    def __init__(self, credentials: CredentialStore, transport: Transport = _default_transport,
                 state_path: Optional[str] = None,
                 endpoints: Optional[Dict[str, str]] = None,
                 default_timeout: int = 60) -> None:
        self.credentials = credentials
        self.transport = transport
        self.state_path = state_path
        self.endpoints = endpoints or {}
        self.default_timeout = default_timeout
        self.state = self._load_state()

    # --- state persistence (NO secrets) ---
    def _load_state(self) -> ProviderState:
        if self.state_path and os.path.isfile(self.state_path):
            try:
                d = json.load(open(self.state_path, encoding="utf-8"))
                return ProviderState(**{k: d.get(k) for k in ProviderState().__dict__})
            except Exception:
                pass
        return ProviderState()

    def _save_state(self) -> None:
        if not self.state_path:
            return
        _atomic_write_json(self.state_path, asdict(self.state))

    def _provider(self, pid: AIProviderId, model: str = "") -> AIProvider:
        d = PROVIDER_DEFINITIONS[pid]
        endpoint = self.endpoints.get(pid.value, d.default_endpoint)
        cfg = AIProviderConfig(provider_id=pid.value, endpoint=endpoint, model=model,
                               timeout=self.default_timeout)
        return AIProvider(d, cfg, self.credentials, self.transport)

    def list_providers(self) -> List[Dict[str, Any]]:
        out = []
        for pid, d in PROVIDER_DEFINITIONS.items():
            prov = self._provider(pid)
            vc = prov.validate_configuration()
            out.append({
                "id": pid.value, "display_name": d.display_name,
                "is_local": d.capabilities.is_local, "needs_api_key": d.capabilities.needs_api_key,
                "endpoint": prov.config.endpoint,
                "credential_present": self.credentials.exists(d.credential_key),
                "status": vc.status.value,
                "active": self.state.active_provider == pid.value,
            })
        return out

    def test_provider(self, pid: AIProviderId, model: str = "") -> ProviderConnectionResult:
        prov = self._provider(pid, model)
        vc = prov.validate_configuration()
        if not vc.ok:
            return ProviderConnectionResult(pid.value, False, vc.status, vc.message)
        health = prov.health_check()
        if health.status != IntegrationStatus.CONNECTED:
            return ProviderConnectionResult(pid.value, False, health.status, health.detail)
        models = [m.id for m in prov.list_models()]
        return ProviderConnectionResult(pid.value, True, IntegrationStatus.CONNECTED,
                                        "Connected.", models=models)

    def activate_provider(self, pid: AIProviderId, model: str = "") -> IntegrationOperationResult:
        """Transactional switch: validate config -> credentials -> health ->
        model -> activate. On ANY failure keep the current active provider."""
        prev = (self.state.active_provider, self.state.active_model)
        prov = self._provider(pid, model)
        vc = prov.validate_configuration()
        if not vc.ok:
            return IntegrationOperationResult(False, vc.status,
                "Switch aborted: %s Existing provider retained." % vc.message,
                {"active_provider": prev[0]})
        health = prov.health_check()
        if health.status != IntegrationStatus.CONNECTED:
            return IntegrationOperationResult(False, health.status,
                "Switch aborted: %s Existing provider retained." % health.detail,
                {"active_provider": prev[0]})
        if model:
            available = {m.id for m in prov.list_models()}
            if available and model not in available:
                return IntegrationOperationResult(False, IntegrationStatus.MISCONFIGURED,
                    "Switch aborted: model %r not available. Existing provider retained." % model,
                    {"active_provider": prev[0]})
        # commit
        self.state.active_provider = pid.value
        self.state.active_model = model
        self._save_state()
        return IntegrationOperationResult(True, IntegrationStatus.CONNECTED,
            "Active provider switched to %s." % PROVIDER_DEFINITIONS[pid].display_name,
            {"active_provider": pid.value, "active_model": model})

    def set_fallback(self, pid: Optional[AIProviderId], enabled: bool) -> IntegrationOperationResult:
        self.state.fallback_provider = pid.value if pid else None
        self.state.fallback_enabled = bool(enabled and pid is not None)
        self._save_state()
        return IntegrationOperationResult(True, IntegrationStatus.CONFIGURED,
            "Fallback %s." % ("enabled" if self.state.fallback_enabled else "disabled"),
            {"fallback_provider": self.state.fallback_provider,
             "fallback_enabled": self.state.fallback_enabled})

    def active(self) -> Dict[str, Any]:
        return {"active_provider": self.state.active_provider,
                "active_model": self.state.active_model,
                "fallback_provider": self.state.fallback_provider,
                "fallback_enabled": self.state.fallback_enabled}


# ============================================================================
# Filesystem helpers (atomic write + backup)
# ============================================================================

def _atomic_write_text(path: str, text: str) -> None:
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".rv_tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def _atomic_write_json(path: str, obj: Any) -> None:
    _atomic_write_text(path, json.dumps(obj, indent=2))


def default_ai_state_path() -> str:
    """Canonical, non-secret AI provider state file, shared by the backend and the
    setup/CLI so the active provider/model persists across processes. Override with
    REDVECTOR_AI_STATE. Contains only active_provider/active_model/fallback_* values,
    never API keys or other secrets."""
    return os.environ.get("REDVECTOR_AI_STATE") or \
        os.path.join(os.path.expanduser("~"), ".redvector", "ai_state.json")


# ============================================================================
# MCP config generator
# ============================================================================

class MCPConfigGenerator:
    """Builds the RedVector MCP server definition for a client config, using the
    portable package entrypoint ``python -m redvector.mcp.server`` with a
    dynamically-resolved python and project root (never a hardcoded developer
    path, never a flat script filename)."""

    SERVER_KEY = "redvector-ai"
    MCP_MODULE = "redvector.mcp.server"

    def __init__(self, project_root: Optional[str] = None,
                 python_executable: Optional[str] = None,
                 backend_url: str = "http://127.0.0.1:8888",
                 api_token: str = "redvector-dev-token") -> None:
        # Default to the repository root (the directory that contains the
        # ``redvector`` package), so ``python -m redvector.mcp.server`` resolves.
        default_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.project_root = os.path.abspath(project_root or default_root)
        import sys as _sys
        self.python = python_executable or _sys.executable or "python"
        self.backend_url = backend_url
        self.api_token = api_token

    def module_target(self) -> str:
        return self.MCP_MODULE

    def server_entry(self) -> Dict[str, Any]:
        return {
            "command": self.python,
            "args": ["-m", self.MCP_MODULE, "--server", self.backend_url],
            "cwd": self.project_root,
            "env": {"REDVECTOR_API_TOKEN": self.api_token,
                    "PYTHONPATH": self.project_root},
        }


# ============================================================================
# MCP client adapters
# ============================================================================

class MCPClientAdapter:
    client_id: MCPClientId
    display_name: str

    def __init__(self, home: str, generator: MCPConfigGenerator,
                 system: Optional[str] = None) -> None:
        self.home = home
        self.generator = generator
        self.system = system or platform.system()

    # --- per-client config path (override) ---
    def config_path(self) -> Optional[str]:
        raise NotImplementedError

    def supported(self) -> bool:
        return self.config_path() is not None

    def detect(self) -> IntegrationStatus:
        p = self.config_path()
        if p is None:
            return IntegrationStatus.NOT_INSTALLED
        if os.path.isfile(p):
            return IntegrationStatus.DETECTED
        # config dir may exist even if file does not
        if os.path.isdir(os.path.dirname(p)):
            return IntegrationStatus.DETECTED
        return IntegrationStatus.NOT_INSTALLED

    def inspect_configuration(self) -> Dict[str, Any]:
        p = self.config_path()
        if not p or not os.path.isfile(p):
            return {"present": False, "has_redvector": False, "valid_json": None, "server_keys": []}
        try:
            data = json.load(open(p, encoding="utf-8"))
            valid = True
        except Exception:
            return {"present": True, "has_redvector": False, "valid_json": False, "server_keys": []}
        servers = data.get("mcpServers", {}) if isinstance(data, dict) else {}
        return {"present": True, "valid_json": valid,
                "has_redvector": self.generator.SERVER_KEY in servers,
                "server_keys": sorted(servers.keys())}

    def backup_configuration(self) -> Optional[str]:
        p = self.config_path()
        if not p or not os.path.isfile(p):
            return None
        backup = "%s.redvector-backup-%d" % (p, int(time.time()))
        _atomic_write_text(backup, open(p, encoding="utf-8").read())
        return backup

    def restore_configuration(self, backup_path: str) -> IntegrationOperationResult:
        p = self.config_path()
        if not p or not backup_path or not os.path.isfile(backup_path):
            return IntegrationOperationResult(False, IntegrationStatus.ERROR,
                                              "Backup not found; cannot restore.")
        _atomic_write_text(p, open(backup_path, encoding="utf-8").read())
        return IntegrationOperationResult(True, IntegrationStatus.CONFIGURED,
                                          "Configuration restored from backup.")

    def create_configuration_plan(self) -> Dict[str, Any]:
        info = self.inspect_configuration()
        return {"client": self.client_id.value, "config_path": self.config_path(),
                "will_create_file": not info["present"],
                "will_backup": info["present"],
                "preserves_servers": [k for k in info.get("server_keys", [])
                                      if k != self.generator.SERVER_KEY],
                "adds_or_updates": self.generator.SERVER_KEY}

    def apply_configuration(self) -> IntegrationOperationResult:
        p = self.config_path()
        if p is None:
            return IntegrationOperationResult(False, IntegrationStatus.NOT_INSTALLED,
                "%s is not supported/installed on this system." % self.display_name)
        backup = self.backup_configuration()
        # load existing (preserve unrelated), merge, atomic write
        data: Dict[str, Any] = {}
        if os.path.isfile(p):
            try:
                data = json.load(open(p, encoding="utf-8"))
                if not isinstance(data, dict):
                    data = {}
            except Exception:
                # malformed existing config: back it up (done) and start clean,
                # but do NOT destroy the original (it remains at the backup path)
                return IntegrationOperationResult(False, IntegrationStatus.MISCONFIGURED,
                    "Existing config is not valid JSON; backed up at %s. Manual review needed." % backup,
                    {"backup": backup})
        servers = data.get("mcpServers")
        if not isinstance(servers, dict):
            servers = {}
        servers[self.generator.SERVER_KEY] = self.generator.server_entry()
        data["mcpServers"] = servers
        try:
            _atomic_write_json(p, data)
        except Exception as e:
            if backup:
                self.restore_configuration(backup)
            return IntegrationOperationResult(False, IntegrationStatus.ERROR,
                "Write failed (%s); previous config restored." % type(e).__name__,
                {"backup": backup})
        # validate written file
        verify = self.verify_configuration()
        if not verify.ok:
            if backup:
                self.restore_configuration(backup)
            return IntegrationOperationResult(False, IntegrationStatus.ERROR,
                "Post-write validation failed; previous config restored.", {"backup": backup})
        return IntegrationOperationResult(True, IntegrationStatus.RESTART_REQUIRED,
            "%s configured. Restart %s to load RedVector." % (self.display_name, self.display_name),
            {"backup": backup, "config_path": p})

    def verify_configuration(self) -> IntegrationOperationResult:
        info = self.inspect_configuration()
        if not info["present"]:
            return IntegrationOperationResult(False, IntegrationStatus.NOT_CONFIGURED, "No config file.")
        if info["valid_json"] is False:
            return IntegrationOperationResult(False, IntegrationStatus.MISCONFIGURED, "Invalid JSON.")
        if not info["has_redvector"]:
            return IntegrationOperationResult(False, IntegrationStatus.NOT_CONFIGURED,
                                              "RedVector entry not present.")
        return IntegrationOperationResult(True, IntegrationStatus.CONFIGURED,
            "RedVector MCP entry present; unrelated servers preserved: %s." %
            ([k for k in info["server_keys"] if k != self.generator.SERVER_KEY]))


class ClaudeDesktopAdapter(MCPClientAdapter):
    client_id = MCPClientId.CLAUDE_DESKTOP
    display_name = "Claude Desktop"

    def config_path(self) -> Optional[str]:
        if self.system == "Windows":
            return os.path.join(self.home, "AppData", "Roaming", "Claude",
                                "claude_desktop_config.json")
        if self.system == "Darwin":
            return os.path.join(self.home, "Library", "Application Support", "Claude",
                                "claude_desktop_config.json")
        # Linux: official desktop app availability varies; use XDG-style path
        return os.path.join(self.home, ".config", "Claude", "claude_desktop_config.json")


class CursorAdapter(MCPClientAdapter):
    client_id = MCPClientId.CURSOR
    display_name = "Cursor"

    def config_path(self) -> Optional[str]:
        # Cursor reads a per-user MCP config at ~/.cursor/mcp.json on all OSes.
        return os.path.join(self.home, ".cursor", "mcp.json")


class ChatGPTAdapter(MCPClientAdapter):
    client_id = MCPClientId.CHATGPT
    display_name = "ChatGPT"

    def config_path(self) -> Optional[str]:
        return None  # no local JSON config to edit

    def supported(self) -> bool:
        return False  # not locally auto-configurable

    def detect(self) -> IntegrationStatus:
        return IntegrationStatus.SETUP_REQUIRED

    def apply_configuration(self) -> IntegrationOperationResult:
        return IntegrationOperationResult(
            False, IntegrationStatus.SETUP_REQUIRED,
            "ChatGPT cannot be configured by editing a local file. Expose RedVector's "
            "MCP server over a reachable URL (e.g. SSE transport or a secure tunnel) and "
            "add it as a connector in the ChatGPT app with your account's authorization.",
            {"guided_steps": [
                "Start the backend: python -m redvector",
                "Start MCP over SSE: python -m redvector.mcp.server --transport sse --mcp-port 8889",
                "Expose http://127.0.0.1:8889/sse via your own secure tunnel if remote access is needed",
                "In ChatGPT, add RedVector as an MCP connector and authorize it in-app",
            ]})

    def verify_configuration(self) -> IntegrationOperationResult:
        return IntegrationOperationResult(False, IntegrationStatus.SETUP_REQUIRED,
            "ChatGPT MCP connection is configured in the ChatGPT app, not on disk.")


class MCPClientManager:
    def __init__(self, home: Optional[str] = None, generator: Optional[MCPConfigGenerator] = None,
                 system: Optional[str] = None) -> None:
        self.home = home or os.path.expanduser("~")
        self.generator = generator or MCPConfigGenerator()
        self.system = system or platform.system()

    def adapters(self) -> Dict[str, MCPClientAdapter]:
        return {
            MCPClientId.CLAUDE_DESKTOP.value: ClaudeDesktopAdapter(self.home, self.generator, self.system),
            MCPClientId.CURSOR.value: CursorAdapter(self.home, self.generator, self.system),
            MCPClientId.CHATGPT.value: ChatGPTAdapter(self.home, self.generator, self.system),
        }

    def get(self, client_id: str) -> Optional[MCPClientAdapter]:
        return self.adapters().get(client_id)

    def list_clients(self) -> List[Dict[str, Any]]:
        out = []
        for cid, a in self.adapters().items():
            out.append({"id": cid, "display_name": a.display_name,
                        "supported": a.supported(), "status": a.detect().value,
                        "config_path": a.config_path()})
        return out

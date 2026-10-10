"""AI provider setup (Ollama / Claude API / Gemini API / DeepSeek API).

Thin orchestration over the existing ``AIProviderManager`` (single provider
registry; no duplicate). Adds the Ollama model UX: installed-model discovery, the
recommended default (dolphin-llama3:8b, recommendation only), strict custom-model
validation (no shell injection), explicit pull confirmation (never silent), and a
minimal inference readiness test. Secrets are stored through the existing
credential store and never echoed, logged, or returned.
"""
from __future__ import annotations

import json
import re
import subprocess
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from redvector import ai_integration as _ai
from redvector.setup.vendors import (RECOMMENDED_OLLAMA_MODEL, RECOMMENDED_OLLAMA_MODEL_NOTE,
                                      OLLAMA_INSTALL_STEPS, OLLAMA_DOCS)

# Ollama model states
M_INSTALLED = "INSTALLED"
M_AVAILABLE_TO_PULL = "AVAILABLE_TO_PULL"
M_DOWNLOADING = "DOWNLOADING"
M_READY = "READY"
M_FAILED = "FAILED"

_OLLAMA_DEFAULT_ENDPOINT = "http://127.0.0.1:11434"
# Allowed Ollama model identifier: starts alnum; then alnum . _ : / - only.
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_SHELL_META = set(";|&$<>`\\\n\r\t \"'(){}[]*?!")


def _default_http(method: str, url: str, payload: Optional[dict] = None, timeout: int = 10) -> Dict[str, Any]:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"} if data else {})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (localhost only in practice)
        body = r.read().decode("utf-8", "replace")
        try:
            return {"status": r.status, "json": json.loads(body)}
        except Exception:
            return {"status": r.status, "json": {}, "text": body}


class OllamaModelManager:
    def __init__(self, endpoint: str = _OLLAMA_DEFAULT_ENDPOINT,
                 http: Callable[..., Dict[str, Any]] = _default_http,
                 runner: Optional[Callable[[List[str]], Dict[str, Any]]] = None,
                 which: Optional[Callable[[str], Optional[str]]] = None) -> None:
        self.endpoint = endpoint.rstrip("/")
        self._http = http
        self._runner = runner or (lambda cmd: {"returncode": subprocess.run(
            list(cmd), capture_output=True, text=True, shell=False).returncode})  # noqa: S603
        import shutil
        self._which = which or shutil.which

    # -- detection --
    def installed(self) -> bool:
        return self._which("ollama") is not None

    def endpoint_healthy(self) -> bool:
        try:
            return self._http("GET", self.endpoint + "/api/tags").get("status") == 200
        except Exception:
            return False

    def installed_models(self) -> List[str]:
        try:
            resp = self._http("GET", self.endpoint + "/api/tags")
            models = resp.get("json", {}).get("models", [])
            return [m.get("name", "") for m in models if m.get("name")]
        except Exception:
            return []

    # -- recommendation (never a hard dependency) --
    def recommended(self) -> Dict[str, Any]:
        return {"model": RECOMMENDED_OLLAMA_MODEL, "note": RECOMMENDED_OLLAMA_MODEL_NOTE}

    def recommended_state(self) -> str:
        return M_INSTALLED if RECOMMENDED_OLLAMA_MODEL in self.installed_models() else M_AVAILABLE_TO_PULL

    # -- validation --
    def validate_model_name(self, name: str) -> bool:
        if not name or len(name) > 128:
            return False
        if any(c in _SHELL_META for c in name):
            return False
        return bool(_MODEL_RE.match(name))

    def model_state(self, name: str) -> str:
        if not self.validate_model_name(name):
            return M_FAILED
        return M_INSTALLED if name in self.installed_models() else M_AVAILABLE_TO_PULL

    # -- pull (structured args, confirmation required, never silent) --
    def pull(self, name: str, confirmed: bool = False) -> Dict[str, Any]:
        if not self.validate_model_name(name):
            return {"ok": False, "state": M_FAILED, "model": name,
                    "message": "Invalid model identifier (rejected unsafe characters)."}
        if name in self.installed_models():
            return {"ok": True, "state": M_INSTALLED, "model": name, "message": "Already installed."}
        if not confirmed:
            return {"ok": False, "state": M_AVAILABLE_TO_PULL, "model": name,
                    "message": "Pull of %r requires explicit confirmation." % name}
        try:
            res = self._runner(["ollama", "pull", name])   # shell=False argument vector
        except Exception as e:
            return {"ok": False, "state": M_FAILED, "model": name,
                    "message": "Pull failed: %s" % type(e).__name__}
        if res.get("returncode", 1) != 0:
            return {"ok": False, "state": M_FAILED, "model": name, "message": "Pull returned non-zero."}
        if name not in self.installed_models():
            return {"ok": False, "state": M_FAILED, "model": name,
                    "message": "Pull ran but model not detected."}
        return {"ok": True, "state": M_INSTALLED, "model": name, "message": "Pulled."}

    def _generate_once(self, name: str, timeout: int) -> Dict[str, Any]:
        """One /api/generate attempt. Distinguishes a timeout (model likely cold /
        still loading) from a hard failure (e.g. model missing)."""
        try:
            resp = self._http("POST", self.endpoint + "/api/generate",
                              {"model": name, "prompt": "ping", "stream": False}, timeout=timeout)
        except (TimeoutError, OSError) as e:
            # socket.timeout is TimeoutError on 3.10+; a cold model keeps the request open.
            is_timeout = isinstance(e, TimeoutError) or e.__class__.__name__ in ("timeout", "TimeoutError")
            return {"ok": False, "timed_out": is_timeout, "message": type(e).__name__}
        except Exception as e:
            return {"ok": False, "timed_out": False, "message": type(e).__name__}
        body = resp.get("json", {})
        if resp.get("status") == 200 and ("response" in body or body.get("done")):
            return {"ok": True, "timed_out": False}
        return {"ok": False, "timed_out": False, "message": "no valid response"}

    # -- minimal inference readiness (cold-start aware, bounded) --
    def inference_test(self, name: str, warm_timeout: int = 20, deadline: int = 120,
                       on_cold: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
        """Verify the model can load and respond. A warm model answers within
        ``warm_timeout``; a cold model may take ~60s+ to load, so after a warm-path
        timeout we make ONE bounded long attempt for the remaining window (up to
        ``deadline`` total). Bounded (2 attempts, <= deadline); never an infinite loop."""
        if not self.validate_model_name(name):
            return {"ok": False, "state": M_FAILED, "message": "Invalid model identifier."}
        first = self._generate_once(name, warm_timeout)
        if first["ok"]:
            return {"ok": True, "state": M_READY, "message": "Minimal inference succeeded."}
        if not first.get("timed_out"):
            return {"ok": False, "state": M_FAILED,
                    "message": "Model did not produce a valid response (%s)." % first.get("message", "error")}
        # warm path timed out -> treat as cold start; one bounded long attempt
        if on_cold:
            try:
                on_cold(name)
            except Exception:
                pass
        cold_timeout = max(1, deadline - warm_timeout)
        second = self._generate_once(name, cold_timeout)
        if second["ok"]:
            return {"ok": True, "state": M_READY,
                    "message": "Minimal inference succeeded after cold start."}
        return {"ok": False, "state": M_FAILED,
                "message": "Model %s did not become ready within %ds." % (name, deadline)}

    def install_guidance(self) -> Dict[str, Any]:
        return {"method": "MANUAL_REQUIRED", "docs": OLLAMA_DOCS, "steps": list(OLLAMA_INSTALL_STEPS),
                "note": "RedVector does not auto-install Ollama; use the official installer."}


class ProviderSetup:
    """Wraps AIProviderManager for the four providers; never stores a second registry."""

    def __init__(self, manager: _ai.AIProviderManager,
                 ollama: Optional[OllamaModelManager] = None) -> None:
        self.manager = manager
        self.ollama = ollama or OllamaModelManager(
            endpoint=(manager.endpoints.get("ollama") or _OLLAMA_DEFAULT_ENDPOINT))

    def status(self) -> Dict[str, Any]:
        return {"providers": self.manager.list_providers(), "active": self.manager.active()}

    def unified(self) -> list:
        """Three-dimension status per provider. Installation is N/A for cloud APIs.
        Ollama connection is probed locally (free); cloud-API connection is only
        CONNECTED when the provider is active (no passive paid test in diagnostics)."""
        from redvector.setup import status as S
        active = self.manager.active()
        out = []
        for p in self.manager.list_providers():
            pid = p["id"]
            if p.get("is_local"):   # Ollama
                healthy = self.ollama.endpoint_healthy()
                installation = S.INSTALLED if (self.ollama.installed() or healthy) else S.NOT_INSTALLED
                is_active = active.get("active_provider") == pid and bool(active.get("active_model"))
                out.append({"id": pid, "display_name": p["display_name"],
                            "installation": installation,
                            "configuration": S.CONFIGURED if is_active else S.NOT_CONFIGURED,
                            "connection": S.CONNECTED if healthy else S.NOT_CONNECTED})
            else:   # cloud API provider
                out.append({"id": pid, "display_name": p["display_name"],
                            "installation": S.NOT_APPLICABLE,
                            "configuration": S.CONFIGURED if p.get("credential_present") else S.NOT_CONFIGURED,
                            "connection": S.CONNECTED if p.get("active") else S.NOT_OBSERVABLE})
        return out

    def test(self, provider_id: str, model: str = "") -> Dict[str, Any]:
        try:
            pid = _ai.AIProviderId(provider_id)
        except ValueError:
            return {"ok": False, "message": "Unknown provider %r." % provider_id}
        r = self.manager.test_provider(pid, model)
        return {"ok": r.ok, "provider": provider_id, "status": r.status.value,
                "message": r.message, "models": list(getattr(r, "models", []) or [])}

    def configure_api_key(self, provider_id: str, api_key: str) -> Dict[str, Any]:
        """Store the key via the existing credential store. Never echoes/returns it."""
        try:
            pid = _ai.AIProviderId(provider_id)
        except ValueError:
            return {"ok": False, "message": "Unknown provider %r." % provider_id}
        definition = _ai.PROVIDER_DEFINITIONS[pid]
        if not api_key:
            return {"ok": False, "message": "No API key provided."}
        stored = self.manager.credentials.store(definition.credential_key, api_key)
        if not stored:
            return {"ok": False, "message": "Credential store is read-only; set %s in the environment."
                    % _ai.EnvCredentialStore.ENV_MAP.get(definition.credential_key, definition.credential_key)}
        return {"ok": True, "provider": provider_id, "message": "%s API key stored (redacted)."
                % definition.display_name, "secret_backend": self.manager.credentials.backend}

    def activate(self, provider_id: str, model: str = "") -> Dict[str, Any]:
        try:
            pid = _ai.AIProviderId(provider_id)
        except ValueError:
            return {"ok": False, "message": "Unknown provider %r." % provider_id}
        r = self.manager.activate_provider(pid, model)
        return {"ok": r.ok, "provider": provider_id, "status": r.status.value, "message": r.message,
                "active": self.manager.active()}

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

    # -- minimal inference readiness --
    def inference_test(self, name: str) -> Dict[str, Any]:
        if not self.validate_model_name(name):
            return {"ok": False, "state": M_FAILED, "message": "Invalid model identifier."}
        try:
            resp = self._http("POST", self.endpoint + "/api/generate",
                              {"model": name, "prompt": "ping", "stream": False}, timeout=30)
        except Exception as e:
            return {"ok": False, "state": M_FAILED, "message": "Inference request failed: %s" % type(e).__name__}
        body = resp.get("json", {})
        if resp.get("status") == 200 and ("response" in body or body.get("done")):
            return {"ok": True, "state": M_READY, "message": "Minimal inference succeeded."}
        return {"ok": False, "state": M_FAILED, "message": "Model did not produce a valid response."}

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

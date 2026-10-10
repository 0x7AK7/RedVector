"""AI client (Claude Desktop / Cursor / ChatGPT / generic) setup orchestration.

Wraps the existing Phase 7 ``MCPClientManager`` adapters (which already do atomic,
backup-first, merge-preserving config writes) and adds Phase 10 behavior:
richer normalized states, stale-entry detection, idempotent connect
(ADDED / ALREADY_CONFIGURED / UPDATED), safe disconnect (removes only RedVector),
and a generic-client config example. CONNECTED is never fabricated for desktop
clients: a valid config is reported CONFIGURED, waiting for the client to connect.
"""
from __future__ import annotations

import json
import os
import re
import shutil
from typing import Any, Callable, Dict, Optional

from redvector import ai_integration as _ai
from redvector.setup import status as S

# Normalized Phase 10 client states (strings; we do not mutate the shared enum).
NOT_INSTALLED = "NOT_INSTALLED"
INSTALLED = "INSTALLED"
NOT_CONFIGURED = "NOT_CONFIGURED"
CONFIGURED = "CONFIGURED"
CONFIGURED_BUT_STALE = "CONFIGURED_BUT_STALE"
CONFIG_INVALID = "CONFIG_INVALID"
SETUP_REQUIRED = "SETUP_REQUIRED"
CONNECTED = "CONNECTED"   # only if a live connection is actually observed (desktop apps: not observable)


def _read_json(path: str) -> Optional[dict]:
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:
        return None


class ClientSetup:
    def __init__(self, manager: Optional[_ai.MCPClientManager] = None,
                 which: Optional[Callable[[str], Optional[str]]] = None,
                 runner: Optional[Callable[[list], Dict[str, Any]]] = None) -> None:
        self.manager = manager or _ai.MCPClientManager()
        self._which = which or shutil.which
        import subprocess
        self._runner = runner or (lambda cmd: {
            "returncode": 0,
            "stdout": (lambda p: p.stdout or "")(subprocess.run(list(cmd), capture_output=True,
                                                                text=True, shell=False))})  # noqa: S603

    # -- introspection --
    def _existing_entry(self, adapter) -> Optional[dict]:
        p = adapter.config_path()
        if not p or not os.path.isfile(p):
            return None
        data = _read_json(p)
        if not isinstance(data, dict):
            return None
        servers = data.get("mcpServers", {})
        if not isinstance(servers, dict):
            return None
        return servers.get(adapter.generator.SERVER_KEY)

    def _stale_reason(self, adapter, entry: dict) -> str:
        """Return a reason string if the existing RedVector entry is stale, else ''."""
        desired = adapter.generator.server_entry()
        # stale if it still points at a flat module script, a different module, or a different cwd
        args = entry.get("args", [])
        if any(isinstance(a, str) and a.endswith(("redvector_mcp.py", "redvector_server.py")) for a in args):
            return "entry references a pre-package flat script path"
        if desired.get("args") != args:
            return "entry arguments differ from the current RedVector entrypoint"
        if entry.get("command") != desired.get("command"):
            return "entry interpreter differs from the current one"
        if entry.get("cwd") and desired.get("cwd") and entry.get("cwd") != desired.get("cwd"):
            return "entry working directory differs from the current project root"
        return ""

    def status(self, client_id: str) -> Dict[str, Any]:
        adapter = self.manager.get(client_id)
        if adapter is None:
            return {"client": client_id, "state": NOT_INSTALLED, "supported": False,
                    "config_path": None, "display_name": client_id}
        # ChatGPT: no local config; platform-dependent connector in-app
        if not adapter.supported() and adapter.client_id.value == "chatgpt":
            return {"client": client_id, "display_name": adapter.display_name, "supported": False,
                    "state": SETUP_REQUIRED, "config_path": None,
                    "note": "ChatGPT connects via an in-app MCP connector, not a local config file."}
        p = adapter.config_path()
        info = adapter.inspect_configuration()
        preserved = [k for k in info.get("server_keys", []) if k != adapter.generator.SERVER_KEY]
        if not info["present"]:
            # config dir may still indicate the app is installed
            installed = bool(p and os.path.isdir(os.path.dirname(p)))
            state = NOT_CONFIGURED if installed else NOT_INSTALLED
            return {"client": client_id, "display_name": adapter.display_name, "supported": True,
                    "state": state, "config_path": p, "preserved_servers": preserved}
        if info["valid_json"] is False:
            return {"client": client_id, "display_name": adapter.display_name, "supported": True,
                    "state": CONFIG_INVALID, "config_path": p, "preserved_servers": []}
        if not info["has_redvector"]:
            return {"client": client_id, "display_name": adapter.display_name, "supported": True,
                    "state": NOT_CONFIGURED, "config_path": p, "preserved_servers": preserved}
        entry = self._existing_entry(adapter) or {}
        reason = self._stale_reason(adapter, entry)
        state = CONFIGURED_BUT_STALE if reason else CONFIGURED
        return {"client": client_id, "display_name": adapter.display_name, "supported": True,
                "state": state, "config_path": p, "preserved_servers": preserved,
                "stale_reason": reason,
                "note": "Configuration is valid. Waiting for %s to connect." % adapter.display_name}

    # -- actions --
    def connect(self, client_id: str) -> Dict[str, Any]:
        """Idempotent connect. Returns outcome ADDED | ALREADY_CONFIGURED | UPDATED | error."""
        adapter = self.manager.get(client_id)
        if adapter is None:
            return {"client": client_id, "ok": False, "outcome": "UNSUPPORTED",
                    "message": "Unknown client."}
        if not adapter.supported():
            res = adapter.apply_configuration()   # ChatGPT -> guided SETUP_REQUIRED result
            return {"client": client_id, "ok": res.ok, "outcome": "SETUP_REQUIRED",
                    "message": res.message, "details": res.data}
        before = self.status(client_id)["state"]
        if before == CONFIGURED:
            return {"client": client_id, "ok": True, "outcome": "ALREADY_CONFIGURED",
                    "message": "%s already has the current RedVector MCP entry." % adapter.display_name,
                    "config_path": adapter.config_path()}
        res = adapter.apply_configuration()   # atomic, backup-first, preserves unrelated servers
        outcome = "UPDATED" if before == CONFIGURED_BUT_STALE else "ADDED"
        if not res.ok:
            outcome = "ERROR"
        return {"client": client_id, "ok": res.ok, "outcome": outcome, "message": res.message,
                "details": res.data, "config_path": adapter.config_path()}

    def disconnect(self, client_id: str) -> Dict[str, Any]:
        """Remove ONLY the RedVector entry; preserve every unrelated MCP server."""
        adapter = self.manager.get(client_id)
        if adapter is None or not adapter.supported():
            return {"client": client_id, "ok": False, "outcome": "UNSUPPORTED",
                    "message": "Nothing to disconnect for this client."}
        p = adapter.config_path()
        if not p or not os.path.isfile(p):
            return {"client": client_id, "ok": True, "outcome": "NOT_PRESENT",
                    "message": "No config file; nothing to remove."}
        data = _read_json(p)
        if not isinstance(data, dict):
            return {"client": client_id, "ok": False, "outcome": "CONFIG_INVALID",
                    "message": "Existing config is not valid JSON; left unchanged for manual review."}
        servers = data.get("mcpServers", {})
        if not isinstance(servers, dict) or adapter.generator.SERVER_KEY not in servers:
            return {"client": client_id, "ok": True, "outcome": "NOT_PRESENT",
                    "message": "RedVector entry not present; nothing to remove."}
        backup = adapter.backup_configuration()
        preserved = [k for k in servers if k != adapter.generator.SERVER_KEY]
        del servers[adapter.generator.SERVER_KEY]
        data["mcpServers"] = servers
        try:
            _ai._atomic_write_json(p, data)
        except Exception as e:
            if backup:
                adapter.restore_configuration(backup)
            return {"client": client_id, "ok": False, "outcome": "ERROR",
                    "message": "Write failed (%s); previous config restored." % type(e).__name__}
        return {"client": client_id, "ok": True, "outcome": "REMOVED",
                "message": "Removed RedVector; preserved: %s." % preserved,
                "preserved_servers": preserved, "backup": backup}

    def repair(self, client_id: str) -> Dict[str, Any]:
        return self.connect(client_id)

    # -- unified three-dimension status (Phase 10.2) --
    _CONFIG_MAP = {CONFIGURED: S.CONFIGURED, CONFIGURED_BUT_STALE: S.STALE,
                   CONFIG_INVALID: S.INVALID, NOT_CONFIGURED: S.NOT_CONFIGURED,
                   NOT_INSTALLED: S.NOT_CONFIGURED, SETUP_REQUIRED: S.SETUP_REQUIRED}

    def app_installation(self, client_id: str) -> str:
        """Detect whether the actual APP is installed (config presence is NOT used
        as proof of installation). Claude Code (the `claude` CLI) is NEVER treated
        as Claude Desktop."""
        system = self.manager.system
        if client_id == "claude_desktop":
            if self._which("claude-desktop"):
                return S.INSTALLED
            return S.NOT_INSTALLED if system == "Linux" else S.UNKNOWN
        if client_id == "cursor":
            if self._which("cursor"):
                return S.INSTALLED
            return S.NOT_INSTALLED if system == "Linux" else S.UNKNOWN
        if client_id == "chatgpt":
            return S.NOT_APPLICABLE   # integrates via in-app connector, not a local install
        return S.UNKNOWN

    def unified(self, client_id: str) -> Dict[str, Any]:
        st = self.status(client_id)
        display = st.get("display_name", client_id)
        if client_id == "chatgpt":
            return {"client": client_id, "display_name": display,
                    "installation": S.NOT_APPLICABLE, "configuration": S.SETUP_REQUIRED,
                    "connection": S.NOT_OBSERVABLE,
                    "note": "ChatGPT connects via an in-app MCP connector, not a local file."}
        return {"client": client_id, "display_name": display,
                "installation": self.app_installation(client_id),
                "configuration": self._CONFIG_MAP.get(st["state"], S.NOT_CONFIGURED),
                "connection": S.NOT_OBSERVABLE,   # desktop client owns its own session
                "config_path": st.get("config_path"),
                "note": st.get("note")}

    def claude_code(self) -> Dict[str, Any]:
        """Detect the Claude Code CLI (`claude`), which is DISTINCT from Claude
        Desktop. Reports installation + version only; RedVector does not configure
        Claude Code's MCP in this phase."""
        path = self._which("claude")
        if not path:
            return {"client": "claude_code", "display_name": "Claude Code",
                    "installation": S.NOT_INSTALLED, "version": None}
        version = None
        try:
            out = self._runner(["claude", "--version"]).get("stdout", "") or ""
            m = re.search(r"\d+\.\d+\.\d+", out)
            version = m.group(0) if m else None
        except Exception:
            version = None
        return {"client": "claude_code", "display_name": "Claude Code",
                "installation": S.INSTALLED, "version": version, "path": path}

    def generic_example(self) -> Dict[str, Any]:
        """A copy-pasteable config for an arbitrary MCP client (no auto-edit)."""
        entry = self.manager.generator.server_entry()
        return {"transport": "stdio",
                "config": {"mcpServers": {self.manager.generator.SERVER_KEY: entry}}}

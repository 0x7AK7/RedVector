"""Read-only diagnostics. Never modifies config, installs software, pulls models,
runs security tools, or creates provider traffic beyond minimal health checks.

Reads actual runtime state (counts come from the live registries, not hard-coded).
All external probes are injectable for deterministic tests.
"""
from __future__ import annotations

import sys
import types
from typing import Any, Callable, Dict, Optional

from redvector import security_tools as _st
from redvector.version import __version__


def live_mcp_counts() -> Dict[str, Any]:
    """Count MCP tools by registering into a throwaway recorder (read-only).

    Returns None values if the MCP runtime import is unavailable (e.g. deps not
    installed), rather than raising.
    """
    try:
        from redvector.mcp import server as mcpserver
    except Exception:
        return {"available": False, "historical": None, "declarative": None,
                "custom": None, "meta": None, "live": None}

    class _Rec:
        def __init__(s, *a, **k): s.tools = []
        def tool(s, *a, **k):
            def d(fn): s.tools.append(fn.__name__); return fn
            return d
        def run(s, *a, **k): pass

    class _Cli:
        def safe_get(s, *a, **k): return {}
        def safe_post(s, *a, **k): return {}
        def safe_delete(s, *a, **k): return {}
        def check_health(s): return {}

    try:
        prev = getattr(mcpserver, "FastMCP", None)
        mcpserver.FastMCP = _Rec
        m = mcpserver.setup_mcp_server(_Cli())
        historical = len(m.tools)
        kinds = [mcpserver.MCP_TOOL_REGISTRY.get(n).handler_type
                 for n in mcpserver.MCP_TOOL_REGISTRY.names()]
        meta = mcpserver.register_agent_mcp_tools(m, _Cli())
        live = len(m.tools)
        if prev is not None:
            mcpserver.FastMCP = prev
        return {"available": True, "historical": historical,
                "declarative": kinds.count("generic"), "custom": kinds.count("wrapper"),
                "meta": meta, "live": live}
    except Exception:
        return {"available": False, "historical": None, "declarative": None,
                "custom": None, "meta": None, "live": None}


class Diagnostics:
    def __init__(self, client_setup, provider_setup, harness,
                 backend_probe: Optional[Callable[[], bool]] = None,
                 python_ok: bool = True, venv_ok: Optional[bool] = None,
                 deps_probe: Optional[Callable[[], bool]] = None,
                 mcp_counts: Optional[Callable[[], Dict[str, Any]]] = None) -> None:
        self.client_setup = client_setup
        self.provider_setup = provider_setup
        self.harness = harness
        self._backend_probe = backend_probe or (lambda: False)
        self._python_ok = python_ok
        self._venv_ok = venv_ok if venv_ok is not None else (hasattr(sys, "real_prefix") or
                                                             sys.prefix != sys.base_prefix)
        self._deps_probe = deps_probe or _default_deps_probe
        self._mcp_counts = mcp_counts or live_mcp_counts

    def collect(self) -> Dict[str, Any]:
        reg = _st.SECURITY_TOOL_REGISTRY
        counts = self._mcp_counts()
        clients = {cid: self.client_setup.status(cid)
                   for cid in ("claude_desktop", "cursor", "chatgpt")}
        providers = self.provider_setup.status()
        pre = self.harness.prerequisites()
        return {
            "version": __version__,
            "core": {
                "python": "OK" if self._python_ok else "ERROR",
                "virtual_environment": "OK" if self._venv_ok else "WARN",
                "dependencies": "OK" if self._deps_probe() else "WARN",
                "backend": "READY" if self._backend_probe() else "NOT CONFIGURED",
            },
            "capabilities": {
                "historical_mcp": counts.get("historical"),
                "phase8_meta_tools": counts.get("meta"),
                "live_mcp": counts.get("live"),
                "security_integrations": reg.count(),
                "security_declarative": len(reg.declarative_names()),
                "security_custom": len(reg.custom_names()),
            },
            "clients": clients,
            "providers": providers,
            "harness": {"deepseek_harness": {
                "node_present": pre["node_present"], "node_version": pre["node_version"],
                "node_ok": pre["node_ok"], "npx_present": pre["npx_present"],
                "node_requirement": pre["node_requirement"],
            }},
            "read_only": True,
        }


def _default_deps_probe() -> bool:
    for m in ("flask", "requests"):
        try:
            __import__(m)
        except Exception:
            return False
    return True

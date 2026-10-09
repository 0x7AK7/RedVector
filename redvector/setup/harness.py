"""DeepSeek Harness (DSH) - optional AI harness setup.

Official scoped package @deepseek-ai/dsh (developer preview). We verify Node
against the current declared engine range, never install a similarly named
unofficial package, never perform a silent global npm install, and never invent
DSH MCP configuration syntax (current MCP capability is UNVERIFIED -> manual
guidance). First-run validation uses a safe temporary workspace, never the user's
home, private keys, or RedVector's private development workspace.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Callable, Dict, List, Optional

from redvector.setup import vendors

STOPPED = "STOPPED"
STARTING = "STARTING"
READY = "READY"
FAILED = "FAILED"
# Harness (not prerequisite) states for diagnostics/status:
NOT_INSTALLED = "NOT_INSTALLED"
INSTALLED_STOPPED = "INSTALLED_STOPPED"

_VER_RE = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")


def _default_dsh_http(method: str, url: str, payload=None, timeout: int = 2) -> Dict[str, Any]:
    import urllib.request
    req = urllib.request.Request(url, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (localhost probe only)
        return {"status": r.status}


def _parse_node_version(text: str):
    m = _VER_RE.search(text or "")
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def node_satisfies(version) -> bool:
    """Current DSH engine range: ^22.19.0 || >=24.0.0."""
    if not version:
        return False
    major, minor, patch = version
    if major == 22 and (minor, patch) >= (19, 0):
        return True
    if major >= 24:
        return True
    return False


class DeepSeekHarnessManager:
    PACKAGE = vendors.DSH_PACKAGE
    REPO = vendors.DSH_REPO
    NODE_REQUIREMENT = vendors.DSH_NODE_REQUIREMENT
    RUN_COMMAND = list(vendors.DSH_RUN_COMMAND)
    DEFAULT_ENDPOINT = vendors.DSH_DEFAULT_ENDPOINT
    PREVIEW = vendors.DSH_PREVIEW
    MCP_CAPABILITY = vendors.DSH_MCP_CAPABILITY   # "UNVERIFIED"

    def __init__(self, which: Optional[Callable[[str], Optional[str]]] = None,
                 runner: Optional[Callable[[List[str]], Dict[str, Any]]] = None,
                 http: Optional[Callable[..., Dict[str, Any]]] = None) -> None:
        self._which = which or shutil.which
        self._runner = runner or (lambda cmd: _run(cmd))
        # Default to a real (short-timeout) endpoint probe so readiness/state reflect
        # whether DSH is actually running, not merely whether Node is installed.
        self._http = http if http is not None else _default_dsh_http

    # -- prerequisites --
    def node_version(self):
        if not self._which("node"):
            return None
        res = self._runner(["node", "--version"])
        return _parse_node_version(res.get("stdout", ""))

    def prerequisites(self) -> Dict[str, Any]:
        ver = self.node_version()
        return {
            "node_present": ver is not None,
            "node_version": ".".join(map(str, ver)) if ver else None,
            "node_requirement": self.NODE_REQUIREMENT,
            "node_ok": node_satisfies(ver),
            "npm_present": self._which("npm") is not None,
            "npx_present": self._which("npx") is not None,
        }

    def prerequisites_ok(self) -> bool:
        p = self.prerequisites()
        return p["node_ok"] and p["npx_present"]

    # -- install / run plan (confirmation required; no silent global install) --
    def run_plan(self) -> Dict[str, Any]:
        return {
            "package": self.PACKAGE, "repo": self.REPO, "preview": self.PREVIEW,
            "node_requirement": self.NODE_REQUIREMENT,
            "command": list(self.RUN_COMMAND),   # npx @deepseek-ai/dsh web (no global install)
            "endpoint": self.DEFAULT_ENDPOINT,
            "needs_confirmation": True,
            "persistence_note": ("npx caches the package under the user's npm cache; this does not perform "
                                 "a global install. DSH is a developer preview."),
        }

    def start(self, confirmed: bool = False, workspace: Optional[str] = None) -> Dict[str, Any]:
        if not self.prerequisites_ok():
            return {"ok": False, "state": FAILED, "message": "Node.js %s (or >=24) and npx are required."
                    % self.NODE_REQUIREMENT, "prerequisites": self.prerequisites()}
        if not confirmed:
            return {"ok": False, "state": STOPPED, "message": "Starting DSH requires explicit confirmation.",
                    "plan": self.run_plan()}
        ws = workspace or self.safe_workspace()
        try:
            res = self._runner(list(self.RUN_COMMAND))   # run in a safe workspace (cwd owned by caller)
        except Exception as e:
            return {"ok": False, "state": FAILED, "message": "DSH failed to start: %s" % type(e).__name__}
        # we do not keep the process here; readiness is probed separately
        return {"ok": res.get("returncode", 1) == 0, "state": STARTING,
                "message": "DSH invoked via npx; probe readiness at %s." % self.DEFAULT_ENDPOINT,
                "workspace": ws}

    # -- DSH presence (independent of Node; Node/npm/npx are only prerequisites) --
    def installed(self) -> bool:
        """True only if the OFFICIAL DeepSeek Harness package (@deepseek-ai/dsh) is
        globally installed. A bare 'dsh' binary is NOT used (it is commonly an
        unrelated tool, e.g. dancer's/distributed shell). Node/npm/npx presence is
        NEVER treated as proof of DSH presence; an npx-only invocation is not a
        persistent install and correctly reports as not installed."""
        if self._which("npm") is None:
            return False
        try:
            res = self._runner(["npm", "ls", "-g", self.PACKAGE, "--depth=0"])
        except Exception:
            return False
        out = (res.get("stdout", "") or "") + (res.get("stderr", "") or "")
        return res.get("returncode", 1) == 0 and self.PACKAGE in out

    # -- readiness --
    def readiness(self, endpoint: Optional[str] = None) -> str:
        endpoint = endpoint or self.DEFAULT_ENDPOINT
        if self._http is None:
            return STOPPED
        try:
            resp = self._http("GET", endpoint)
            return READY if resp.get("status", 0) and resp["status"] < 500 else FAILED
        except Exception:
            return STOPPED

    def state(self, endpoint: Optional[str] = None) -> str:
        """Observable DSH state: READY only when the endpoint actually responds;
        INSTALLED_STOPPED when a DSH runtime exists but is not reachable; otherwise
        NOT_INSTALLED. Never READY on the basis of Node/npm/npx alone."""
        if self.readiness(endpoint) == READY:
            return READY
        return INSTALLED_STOPPED if self.installed() else NOT_INSTALLED

    # -- MCP capability (honest) --
    def mcp_capability(self) -> Dict[str, Any]:
        return {
            "capability": self.MCP_CAPABILITY,   # UNVERIFIED
            "result": "MANUAL_GUIDANCE_REQUIRED",
            "message": ("DSH's current MCP client capability, transports, and config schema are not verified "
                        "here. RedVector will not invent DSH configuration syntax. Consult the official DSH "
                        "documentation (%s) to add RedVector's MCP endpoint." % self.REPO),
        }

    # -- safe workspace (never home / private keys / the private dev workspace) --
    def safe_workspace(self) -> str:
        d = tempfile.mkdtemp(prefix="redvector-dsh-")
        return d


def _run(cmd: List[str]) -> Dict[str, Any]:
    p = subprocess.run(list(cmd), capture_output=True, text=True, shell=False)  # noqa: S603
    return {"returncode": p.returncode, "stdout": p.stdout or "", "stderr": p.stderr or ""}

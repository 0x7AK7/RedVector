#!/usr/bin/env python3
# ============================================================================
#  RedVector Diagnostic Plugin v0.1 - isolated, read-only MCP stdio adapter
# ----------------------------------------------------------------------------
#  Exposes EXACTLY three read-only diagnostic tools over MCP stdio:
#      - backend_health   : is the local RedVector backend reachable/healthy?
#      - service_status   : minimal, non-sensitive loopback reachability info
#      - backend_version  : the RUNNING backend's self-reported version
#
#  Security model (ENFORCED IN CODE, not merely described):
#    * Hard exact-name allowlist; any other tool name is rejected (fail closed).
#    * No shells, no subprocess, no os.system - none are imported or used.
#    * Does NOT import RedVector's project modules or its (offensive) MCP
#      registry, and does not enumerate RedVector tools.
#    * Only performs HTTP GETs to a VALIDATED loopback address; non-loopback
#      and non-http destinations are refused.
#    * No HTTP redirects are followed; short timeouts; no Authorization header
#      is ever sent; nothing sensitive is logged.
#    * Returns minimal data only - no stack traces, no secrets, no filesystem
#      paths.
#    * Never starts, stops or restarts the backend; never opens a listener.
#
#  Pure Python standard library only. No third-party dependencies.
#  Backend host/port are DISCOVERED from the documented RedVector environment
#  variables (REDVECTOR_HOST / REDVECTOR_PORT); nothing is hardcoded. If the
#  port is not configured, the tools report that instead of guessing.
# ============================================================================
from __future__ import annotations

import ipaddress
import json
import os
import socket
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit

SERVER_NAME = "redvector-diagnostics"
SERVER_VERSION = "0.1.0"
DEFAULT_PROTOCOL_VERSION = "2025-06-18"

# Short, bounded timeout for any loopback request (seconds), overridable.
try:
    HTTP_TIMEOUT = max(0.5, min(10.0, float(os.environ.get("REDVECTOR_DIAG_TIMEOUT", "3"))))
except (TypeError, ValueError):
    HTTP_TIMEOUT = 3.0

# Exact-name allowlist. Anything not in this tuple is rejected, fail-closed.
ALLOWED_TOOLS = ("backend_health", "service_status", "backend_version")

_MAX_BODY_BYTES = 65536


# --------------------------------------------------------------------------
# Configuration discovery (no hardcoded port; loopback-only by design)
# --------------------------------------------------------------------------
def _resolve_target():
    """Return (host, port_or_None) from the documented RedVector env vars.

    Host defaults to loopback (127.0.0.1) because this adapter only ever talks
    to a local backend. The port is taken strictly from REDVECTOR_PORT; if it is
    not set to a valid value we return None so callers report 'not configured'
    rather than guessing a port.
    """
    host = (os.environ.get("REDVECTOR_HOST", "") or "127.0.0.1").strip() or "127.0.0.1"
    raw = (os.environ.get("REDVECTOR_PORT", "") or "").strip()
    port = None
    if raw.isdigit():
        value = int(raw)
        if 1 <= value <= 65535:
            port = value
    return host, port


def _is_loopback(host):
    """True only for a loopback address or the literal name 'localhost'."""
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_ipv6(host):
    """True if host is an IPv6 literal (so it must be bracketed in a URL)."""
    try:
        return ipaddress.ip_address(host).version == 6
    except ValueError:
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow any redirect (prevents redirect to a non-loopback host)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _loopback_get(path):
    """Single loopback-only HTTP GET. Returns (ok, http_status_or_None, text).

    Refuses anything that is not a validated http:// loopback destination. Sends
    no Authorization header and follows no redirects.
    """
    host, port = _resolve_target()
    if port is None:
        return (False, None, "backend port not configured (set REDVECTOR_PORT)")
    if not _is_loopback(host):
        return (False, None, "refused: destination host is not loopback")

    netloc_host = "[{0}]".format(host) if _is_ipv6(host) else host
    url = "http://{0}:{1}{2}".format(netloc_host, port, path)
    parts = urlsplit(url)
    if parts.scheme != "http" or not _is_loopback(parts.hostname or ""):
        return (False, None, "refused: non-loopback or non-http destination")

    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, method="GET")  # no auth header set
    try:
        with opener.open(request, timeout=HTTP_TIMEOUT) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            text = resp.read(_MAX_BODY_BYTES).decode("utf-8", "replace")
            return (True, status, text)
    except urllib.error.HTTPError as exc:
        return (True, exc.code, "")
    except (urllib.error.URLError, socket.timeout, OSError):
        return (False, None, "unreachable")


def _loopback_tcp_open(host, port):
    """Best-effort loopback TCP connect check (no scanning, no payload)."""
    if not _is_loopback(host):
        return False
    try:
        with socket.create_connection((host, port), timeout=HTTP_TIMEOUT):
            return True
    except (OSError, socket.timeout):
        return False


def _health_json(text):
    """Parse /health JSON, returning the dict only (or None). No leakage."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


# --------------------------------------------------------------------------
# The three approved, read-only tools
# --------------------------------------------------------------------------
def tool_backend_health():
    ok, status, text = _loopback_get("/health")
    if not ok:
        return {"available": False, "detail": text}
    body = _health_json(text) or {}
    reported = body.get("status")
    status_str = reported if isinstance(reported, str) and len(reported) <= 32 else None
    result = {"available": status == 200, "http_status": status}
    if status_str:
        result["status"] = status_str
    return result


def tool_service_status():
    host, port = _resolve_target()
    if port is None:
        return {"configured": False, "detail": "REDVECTOR_PORT is not set"}
    if not _is_loopback(host):
        return {"configured": True, "reachable": False,
                "detail": "non-loopback host refused"}
    return {"configured": True, "host": host, "port": port,
            "reachable": _loopback_tcp_open(host, port)}


def tool_backend_version():
    ok, status, text = _loopback_get("/health")
    if ok and status == 200:
        body = _health_json(text) or {}
        value = body.get("version")
        if isinstance(value, str) and 0 < len(value) <= 64:
            return {"version": value, "source": "/health"}
    return {"version": "unknown"}


HANDLERS = {
    "backend_health": tool_backend_health,
    "service_status": tool_service_status,
    "backend_version": tool_backend_version,
}

_EMPTY_INPUT = {"type": "object", "properties": {}, "additionalProperties": False}
_READONLY = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}

TOOL_DEFS = [
    {
        "name": "backend_health",
        "title": "RedVector backend health",
        "description": "Read-only check of whether the local RedVector backend is reachable and reports healthy.",
        "inputSchema": _EMPTY_INPUT,
        "annotations": _READONLY,
    },
    {
        "name": "service_status",
        "title": "RedVector service status",
        "description": "Minimal, non-sensitive loopback reachability diagnostics for the local RedVector service.",
        "inputSchema": _EMPTY_INPUT,
        "annotations": _READONLY,
    },
    {
        "name": "backend_version",
        "title": "RedVector backend version",
        "description": "Return the running RedVector backend's self-reported version, or 'unknown' if unavailable.",
        "inputSchema": _EMPTY_INPUT,
        "annotations": _READONLY,
    },
]


# --------------------------------------------------------------------------
# Minimal MCP stdio transport (newline-delimited JSON-RPC 2.0)
# --------------------------------------------------------------------------
def _send(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _result(mid, result):
    _send({"jsonrpc": "2.0", "id": mid, "result": result})


def _error(mid, code, message):
    _send({"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}})


def _handle_tools_call(mid, params):
    name = (params or {}).get("name")
    # Fail-closed allowlist: reject any name that is not exactly approved.
    if name not in ALLOWED_TOOLS or name not in HANDLERS:
        _error(mid, -32601, "tool not allowed")
        return
    try:
        data = HANDLERS[name]()
    except Exception:  # never leak a stack trace to the model
        _result(mid, {"isError": True,
                      "content": [{"type": "text", "text": "diagnostic error"}]})
        return
    _result(mid, {
        "content": [{"type": "text", "text": json.dumps(data, separators=(",", ":"))}],
        "structuredContent": data,
    })


def main():
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except (ValueError, TypeError):
            # JSON-RPC parse error: respond with a null id per the spec.
            _error(None, -32700, "parse error")
            continue
        if not isinstance(msg, dict):
            # Arrays/batches are not supported by this transport; ignore.
            continue
        method = msg.get("method")
        mid = msg.get("id")
        if method is None:
            # No method: this is a response or an invalid object, not a request.
            continue
        if method == "initialize":
            params = msg.get("params") or {}
            requested = params.get("protocolVersion")
            protocol = requested if isinstance(requested, str) else DEFAULT_PROTOCOL_VERSION
            _result(mid, {
                "protocolVersion": protocol,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            })
        elif method == "notifications/initialized":
            continue  # notification: no response
        elif method == "tools/list":
            _result(mid, {"tools": TOOL_DEFS})
        elif method == "tools/call":
            _handle_tools_call(mid, msg.get("params"))
        elif method == "ping":
            _result(mid, {})
        elif mid is not None:
            _error(mid, -32601, "method not found")
        # unknown notifications (no id) are ignored


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError, BrokenPipeError):
        pass

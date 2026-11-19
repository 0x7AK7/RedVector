#!/usr/bin/env python3
"""Regression tests for MCP-client error reporting and health reachability.

Covers the timeout-safety client changes:
  * C1 — typed error classification in ``RedVectorClient._error_response``:
    connection_error / client_timeout / backend_http_error / request_error /
    unexpected_error, with a ``status_code`` for HTTP errors. This is what lets
    the host tell a slow-but-alive backend apart from one that is actually down.
  * C5 — credential redaction in those error strings (``_redact_error_text`` and
    the live-token scrub), so a token embedded in an exception never leaves the
    client or reaches the logs.
  * C4 — the additive ``reachable`` flag on ``check_health`` (no new tool, no
    input-schema change, no extra backend call).

Isolation / safety
  * No real RedVector backend, no penetration-testing tool and no outbound
    network: a tiny in-process ``/health`` stub on 127.0.0.1 stands in for the
    backend so the client constructs cleanly, and the error paths are exercised
    with synthetic ``requests`` exceptions.
  * Synthetic credentials only; the user's Claude Desktop config is never read
    or written.

``redvector_mcp`` imports the official ``mcp`` SDK at module load, so where the
SDK is not installed (e.g. the Windows dev box, where it cannot be pip-installed)
this whole module is SKIPPED — it is exercised on Kali with MCP SDK 1.30.0. It is
never silently passed off as having run.

Run with pytest:   pytest tests/test_mcp_error_reporting.py
Standalone:        python tests/test_mcp_error_reporting.py
"""
import contextlib
import json
import os
import pathlib
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

try:
    import pytest
except Exception:  # pragma: no cover
    pytest = None

try:
    import redvector_mcp as rvm  # imports `mcp` at module load
    HAVE_MCP = True
    MCP_IMPORT_ERROR = ""
except Exception as exc:  # pragma: no cover - environment dependent
    HAVE_MCP = False
    MCP_IMPORT_ERROR = repr(exc)

SKIP_REASON = f"redvector_mcp / official MCP SDK not importable here: {MCP_IMPORT_ERROR}"
if pytest is not None:
    pytestmark = pytest.mark.skipif(not HAVE_MCP, reason=SKIP_REASON)


class _HealthStubHandler(BaseHTTPRequestHandler):
    def _send(self, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        self._send({"status": "healthy", "version": "8.0-stub"})

    def log_message(self, *a):  # silence the stub
        return


@contextlib.contextmanager
def _stub_backend():
    srv = HTTPServer(("127.0.0.1", 0), _HealthStubHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


@contextlib.contextmanager
def _client():
    """Construct a RedVectorClient against the local /health stub with a strong
    synthetic token, restoring any pre-existing REDVECTOR_API_TOKEN afterwards."""
    token = "tkn_" + secrets.token_urlsafe(32)
    prev = os.environ.get("REDVECTOR_API_TOKEN")
    os.environ["REDVECTOR_API_TOKEN"] = token
    try:
        with _stub_backend() as port:
            client = rvm.RedVectorClient(f"http://127.0.0.1:{port}")
            yield client, token
    finally:
        if prev is None:
            os.environ.pop("REDVECTOR_API_TOKEN", None)
        else:
            os.environ["REDVECTOR_API_TOKEN"] = prev


# --- C5: credential redaction in error strings -----------------------------

def test_redact_error_text_masks_common_credential_shapes():
    cases = [
        ("Authorization: Bearer abc.DEF-123 failed", "abc.DEF-123"),
        ("sent header bearer sk-live-SECRETTOKEN to host", "sk-live-SECRETTOKEN"),
        ("url https://user:hunter2@host/path refused", "hunter2"),
        ("query token=TOPSECRETVALUE&x=1", "TOPSECRETVALUE"),
        ("api_key=AKIAEXAMPLEKEY blocked", "AKIAEXAMPLEKEY"),
    ]
    for text, secret in cases:
        out = rvm._redact_error_text(text)
        assert secret not in out, f"secret leaked for input {text!r}: {out!r}"
        assert "***REDACTED***" in out, f"no redaction marker for input {text!r}: {out!r}"


# --- C1: typed error classification ----------------------------------------

def test_error_response_classifies_connection_error():
    with _client() as (client, _tok):
        r = client._error_response(requests.exceptions.ConnectionError(
            "Failed to establish a new connection: [Errno 111] Connection refused"))
    assert r["success"] is False
    assert r["error_type"] == "connection_error"
    assert "status_code" not in r


def test_error_response_classifies_read_timeout():
    with _client() as (client, _tok):
        r = client._error_response(requests.exceptions.ReadTimeout(
            "HTTPConnectionPool(host='127.0.0.1'): Read timed out. (read timeout=300)"))
    assert r["error_type"] == "client_timeout"
    assert r["success"] is False


def test_error_response_classifies_connect_timeout_as_connection():
    """A timed-out CONNECT (backend not accepting) is a connection problem, not
    a slow response — it must classify as connection_error."""
    with _client() as (client, _tok):
        r = client._error_response(requests.exceptions.ConnectTimeout("connect timed out"))
    assert r["error_type"] == "connection_error"


def test_error_response_classifies_http_error_with_status_code():
    resp = requests.Response()
    resp.status_code = 503
    with _client() as (client, _tok):
        r = client._error_response(requests.exceptions.HTTPError("503 Server Error", response=resp))
    assert r["error_type"] == "backend_http_error"
    assert r["status_code"] == 503
    assert "503" in r["error"]


def test_error_response_classifies_other_request_error():
    with _client() as (client, _tok):
        r = client._error_response(requests.exceptions.TooManyRedirects("too many redirects"))
    assert r["error_type"] == "request_error"


def test_error_response_classifies_unexpected_error():
    with _client() as (client, _tok):
        r = client._error_response(ValueError("not a requests error"))
    assert r["error_type"] == "unexpected_error"


def test_error_response_scrubs_live_token():
    """An exception string that embeds the live API token must not leak it."""
    with _client() as (client, token):
        exc = requests.exceptions.ConnectionError(
            f"HTTPConnectionPool: sent Authorization: Bearer {token} and failed")
        r = client._error_response(exc)
    blob = json.dumps(r)
    assert token not in blob, "live API token leaked into the classified error"
    assert r["error_type"] == "connection_error"


# --- C4: reachable flag on check_health ------------------------------------

def test_check_health_reachable_true_against_live_stub():
    with _client() as (client, _tok):
        health = client.check_health()
    assert health.get("reachable") is True
    assert health.get("status") == "healthy"
    assert "error_type" not in health


def test_check_health_reachable_false_when_backend_unreachable():
    with _client() as (client, _tok):
        def _boom(*a, **k):
            raise requests.exceptions.ConnectionError("connection refused")
        client.session.get = _boom  # type: ignore[assignment]
        health = client.check_health()
    assert health.get("reachable") is False
    assert health.get("error_type") == "connection_error"
    assert health.get("success") is False


def _main():
    if not HAVE_MCP:
        print(f"SKIP  (all) — {SKIP_REASON}")
        return 0
    import types

    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and isinstance(v, types.FunctionType)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {t.__name__}: {e!r}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_main())

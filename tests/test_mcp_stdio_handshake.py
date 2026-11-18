#!/usr/bin/env python3
"""Real MCP stdio handshake integration test using the OFFICIAL MCP Python SDK.

This test launches the actual RedVector MCP server (``redvector_mcp.py``) as a
child process over stdio, performs MCP initialization and tool discovery through
the official SDK client, and confirms all 328 tools are registered. It also
verifies that a startup failure produces useful diagnostics WITHOUT exposing the
API credential.

Isolation / safety
  * A tiny in-process HTTP stub on 127.0.0.1 stands in for the backend's /health
    endpoints — no real RedVector backend, no penetration-testing tool and no
    external network connection are involved.
  * Synthetic credentials only; the user's real Claude Desktop configuration is
    never read or written.

The official ``mcp`` SDK is required. Where it is not installed (e.g. the Windows
dev box, where it cannot be pip-installed), the whole module is SKIPPED — it is
exercised on Kali with MCP SDK 1.30.0. It is never silently passed off as having
run.

Run with pytest:   pytest tests/test_mcp_stdio_handshake.py
Standalone:        python tests/test_mcp_stdio_handshake.py
"""
import asyncio
import contextlib
import json
import os
import pathlib
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import redvector_credentials as cred  # noqa: E402

try:
    import pytest
except Exception:  # pragma: no cover
    pytest = None

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    HAVE_MCP = True
    MCP_IMPORT_ERROR = ""
except Exception as exc:  # pragma: no cover - environment dependent
    HAVE_MCP = False
    MCP_IMPORT_ERROR = repr(exc)

SKIP_REASON = f"official MCP Python SDK (`mcp`) not importable here: {MCP_IMPORT_ERROR}"
if pytest is not None:
    pytestmark = pytest.mark.skipif(not HAVE_MCP, reason=SKIP_REASON)

MCP_SCRIPT = str(REPO / "redvector_mcp.py")
EXPECTED_TOOL_COUNT = 328


class _HealthStubHandler(BaseHTTPRequestHandler):
    """Answers only the health endpoints the MCP client probes at startup."""

    def _send(self, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/health/details"):
            self._send({
                "status": "healthy",
                "category_stats": {"essential": {"available": 8, "total": 8}},
                "all_essential_tools_available": True,
            })
        elif self.path.startswith("/health"):
            self._send({"status": "healthy", "version": "8.0-stub"})
        else:
            self._send({"ok": True})

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


async def _handshake(port, token):
    params = StdioServerParameters(
        command=sys.executable,
        args=[MCP_SCRIPT, "--server", f"http://127.0.0.1:{port}"],
        env={**os.environ, "REDVECTOR_API_TOKEN": token},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            # MCP initialization (the real protocol handshake).
            await session.initialize()
            # Tool discovery.
            result = await session.list_tools()
            return [t.name for t in result.tools]


def test_stdio_handshake_lists_all_328_tools():
    """Start the real MCP server over stdio, initialize, discover tools, and
    confirm 328 unique registrations — then shut down cleanly."""
    token = cred.generate_token()
    with _stub_backend() as port:
        names = asyncio.run(asyncio.wait_for(_handshake(port, token), timeout=120))
    assert len(names) == EXPECTED_TOOL_COUNT, f"{len(names)} tools registered, expected {EXPECTED_TOOL_COUNT}"
    assert len(set(names)) == len(names), "duplicate tool registrations over stdio"


def test_deliberate_startup_rejection_is_clean_and_leaks_no_credential():
    """DELIBERATE startup rejection: a non-local plain-HTTP server URL trips the
    'HTTPS required' guard BEFORE the server starts serving. It must exit
    non-zero with a clear, useful diagnostic and MUST NOT echo the credential.
    This is a controlled refusal, distinct from an unexpected crash."""
    token = cred.generate_token()
    env = {**os.environ, "REDVECTOR_API_TOKEN": token}
    proc = subprocess.run(
        [sys.executable, MCP_SCRIPT, "--server", "http://nonlocal.invalid.example"],
        input="", capture_output=True, text=True, env=env, timeout=90,
    )
    assert proc.returncode == 1, "a deliberate rejection should exit(1), not crash/kill"
    diagnostics = proc.stdout + proc.stderr
    assert "HTTPS is required" in diagnostics, "rejection lacks a useful diagnostic"
    assert token not in diagnostics, "API credential leaked into rejection diagnostics"


def test_unexpected_termination_is_distinct_and_leaks_no_credential():
    """UNEXPECTED termination: the server starts, connects to the stub backend
    and reaches the stdio serving loop, then is terminated by a signal (not a
    clean MCP shutdown and not a startup rejection). It must have been running
    first, and no credential may appear in its output on the way down."""
    import time

    token = cred.generate_token()
    with _stub_backend() as port:
        proc = subprocess.Popen(
            [sys.executable, MCP_SCRIPT, "--server", f"http://127.0.0.1:{port}"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env={**os.environ, "REDVECTOR_API_TOKEN": token},
        )
        # Allow initialization and entry into the stdio serving loop.
        for _ in range(60):
            if proc.poll() is not None:
                break
            time.sleep(0.25)
        was_running = proc.poll() is None
        proc.terminate()  # unexpected SIGTERM/TerminateProcess, mid-session
        try:
            out, err = proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()

    assert was_running, "server exited before serving (that would be a rejection, not a termination)"
    assert proc.returncode is not None, "process did not terminate"
    assert token not in (out + err), "credential leaked during unexpected termination"


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

#!/usr/bin/env python3
"""Isolated, non-destructive regression tests for the GitHub issue #3 security
remediation (RedVector v8.0.0):

  * CWE-798  - hard-coded default API authentication token.
  * CWE-184  - incomplete command validation / arbitrary command execution.
  * Arbitrary local file access through the ``/api/command`` endpoint.

These tests never execute a real exploit, never scan external systems and never
touch a live credential. The authentication and command-endpoint tests drive the
Flask app in-process through its test client with a throwaway token. The MCP
registration test parses ``redvector_mcp.py`` statically (the ``mcp`` package is
not required), so the full 328-tool surface is verified without a live server.

Run standalone:   python tests/test_security_remediation.py
Or with pytest:   pytest tests/test_security_remediation.py
"""
import ast
import logging
import os
import pathlib
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

# A strong, throwaway token must be present *before* importing the server so
# that the fail-closed configuration resolves to "authentication configured".
TEST_TOKEN = "unit-test-strong-token-0123456789abcdef"
os.environ["REDVECTOR_API_TOKEN"] = TEST_TOKEN

import redvector_server as rv  # noqa: E402

AUTH_HEADER = {"Authorization": f"Bearer {TEST_TOKEN}"}


def _client():
    rv.app.config.update(TESTING=True)
    return rv.app.test_client()


# ── CWE-798: authentication ─────────────────────────────────────────────────
def test_missing_token_is_rejected():
    resp = _client().post("/api/command", json={"command": "echo hi"})
    assert resp.status_code == 401


def test_published_default_token_is_rejected():
    resp = _client().post(
        "/api/command",
        json={"command": "echo hi"},
        headers={"Authorization": "Bearer redvector-dev-token"},
    )
    assert resp.status_code == 401


def test_incorrect_token_is_rejected():
    resp = _client().post(
        "/api/command",
        json={"command": "echo hi"},
        headers={"Authorization": "Bearer totally-wrong-token"},
    )
    assert resp.status_code == 401


def test_unconfigured_server_fails_closed(monkeypatch):
    """With no secure token configured, every protected request is rejected,
    even one bearing a correct-looking token."""
    monkeypatch.setattr(rv, "AUTH_CONFIGURED", False)
    resp = _client().post("/api/command", json={"command": "echo hi"}, headers=AUTH_HEADER)
    assert resp.status_code == 401
    assert "not configured" in resp.get_json()["error"].lower()


def test_valid_token_is_authorized():
    resp = _client().post(
        "/api/command", json={"command": "echo authorized"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)


def test_health_endpoint_requires_no_auth():
    assert _client().get("/health").status_code == 200


# ── CWE-184: command validation (unit level) ────────────────────────────────
def test_validator_allows_supported_scanner():
    assert rv._validate_generic_command(["httpx", "-u", "http://example.com"]) == (None, None)
    assert rv._validate_generic_command(["echo", "scan-complete"]) == (None, None)


def test_validator_blocks_arbitrary_binary():
    status, _ = rv._validate_generic_command(["bash", "-c", "id"])
    assert status == 403
    status, _ = rv._validate_generic_command(["python", "-c", "print(1)"])
    assert status == 403


def test_validator_blocks_find_and_debuggers():
    # `find` (and its `-exec` RCE primitive) is removed from the allowlist.
    assert rv._validate_generic_command(["find", ".", "-exec", "id", "+"])[0] == 403
    # Debuggers / code-exec engines removed as well.
    assert rv._validate_generic_command(["gdb", "-ex", "r"])[0] == 403
    assert rv._validate_generic_command(["r2", "-c", "!id"])[0] == 403


def test_validator_blocks_indirect_exec_flag_on_allowed_tool():
    status, msg = rv._validate_generic_command(["nmap", "-exec", "id"])
    assert status == 403
    assert "indirect code execution" in msg


def test_validator_blocks_sensitive_file_reads():
    assert rv._validate_generic_command(["cat", "/etc/passwd"])[0] == 403  # cat removed
    assert rv._validate_generic_command(["nuclei", "-l", "/etc/shadow"])[0] == 403
    assert rv._validate_generic_command(["httpx", "-l", "../../etc/passwd"])[0] == 403
    assert rv._validate_generic_command(["sqlmap", "-r", "/root/.ssh/id_rsa"])[0] == 403


def test_sensitive_path_helper():
    f = rv._argument_accesses_sensitive_path
    assert f("/etc/passwd")
    assert f("../../etc/shadow")
    assert f("~/.ssh/id_rsa")
    assert f("-l=/root/.ssh/authorized_keys")
    assert f("C:/Windows/System32/config/SAM")
    # Legitimate scan inputs are not flagged.
    assert not f("http://example.com/FUZZ")
    assert not f("/usr/share/wordlists/common.txt")
    assert not f("example.com")


def test_sensitive_path_slash_collapse_bypass_blocked():
    """Repeated leading separators must not bypass the prefix check."""
    f = rv._argument_accesses_sensitive_path
    assert f("//etc/passwd")
    assert f("///etc//passwd")
    assert f("/etc/./passwd")
    assert not f("http://example.com/etc/passwd")  # URL, not a local path


def test_validator_blocks_code_loading_flags():
    """Allowlisted tools must not load attacker-supplied code via scripting,
    OS-command, plugin, config, or code-protocol flags."""
    v = rv._validate_generic_command
    assert v(["nmap", "--script", "http-shellshock", "t"])[0] == 403
    assert v(["sqlmap", "-u", "http://t", "--eval", "x"])[0] == 403
    assert v(["sqlmap", "-u", "http://t", "--os-cmd", "id"])[0] == 403
    assert v(["exiftool", "-config", "evil.pl", "x.jpg"])[0] == 403
    assert v(["nuclei", "-code", "-t", "x.yaml"])[0] == 403
    assert v(["checkov", "--external-checks-dir", "/tmp/x"])[0] == 403
    assert v(["volatility3", "--plugin-dirs", "/tmp/x"])[0] == 403
    assert v(["nmap", "--datadir=/tmp/evil", "127.0.0.1"])[0] == 403


def test_validator_preserves_legitimate_scans():
    """Core, non-code-loading tool usage must keep working."""
    v = rv._validate_generic_command
    assert v(["nmap", "127.0.0.1", "-sV"]) == (None, None)
    assert v(["sqlmap", "-u", "http://t", "--batch"]) == (None, None)
    assert v(["nuclei", "-u", "http://t", "-t", "cves/"]) == (None, None)
    assert v(["ffuf", "-w", "/usr/share/wordlists/common.txt", "-u", "http://t/FUZZ"]) == (None, None)
    assert v(["httpx", "-u", "http://example.com"]) == (None, None)


# ── CWE-184: command validation (HTTP level, authorized) ────────────────────
def test_http_blocks_arbitrary_binary():
    resp = _client().post("/api/command", json={"command": "bash -c id"}, headers=AUTH_HEADER)
    assert resp.status_code == 403


def test_http_blocks_find_exec():
    resp = _client().post(
        "/api/command", json={"command": "find . -maxdepth 1 -exec id +"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 403


def test_http_blocks_sensitive_file_read():
    resp = _client().post(
        "/api/command", json={"command": "cat /etc/passwd"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 403


def test_http_blocks_shell_metacharacters():
    resp = _client().post(
        "/api/command", json={"command": "nmap 127.0.0.1; id"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 400


def test_http_allows_legitimate_operation():
    resp = _client().post(
        "/api/command", json={"command": "echo legitimate-scan"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert "legitimate-scan" in body.get("stdout", "")


# ── MCP compatibility: 328 registrations + basic schemas ────────────────────
def _collect_mcp_tools():
    tree = ast.parse((REPO / "redvector_mcp.py").read_text(encoding="utf-8"))
    tools = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                if isinstance(target, ast.Attribute) and target.attr == "tool":
                    tools.append(node)
    return tools


def test_all_328_mcp_tools_registered():
    assert len(_collect_mcp_tools()) == 328


def test_mcp_tool_input_schemas_intact():
    """FastMCP derives each tool's input schema from its annotated signature,
    so every tool must keep a docstring and fully type-annotated parameters."""
    for fn in _collect_mcp_tools():
        assert ast.get_docstring(fn), f"{fn.name} lost its docstring"
        params = fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs
        for a in params:
            if a.arg in ("self", "cls"):
                continue
            assert a.annotation is not None, f"{fn.name}:{a.arg} lost its type annotation"


# ── CWE-798: no usable default credential in shipped artifacts ───────────────
def test_mcp_config_has_no_dev_token():
    cfg = (REPO / "redvector-mcp.json").read_text(encoding="utf-8")
    assert "redvector-dev-token" not in cfg


def test_launchers_reject_dev_token():
    sh = (REPO / "start_redvector.sh").read_text(encoding="utf-8")
    ps = (REPO / "start_redvector.ps1").read_text(encoding="utf-8")
    # The dev token must only appear as a value that is rejected, never as a default.
    assert 'REDVECTOR_API_TOKEN:-redvector-dev-token' not in sh
    assert '{ "redvector-dev-token" }' not in ps
    assert "Refusing to start" in sh and "Refusing to start" in ps


def test_mcp_client_source_fails_closed():
    src = (REPO / "redvector_mcp.py").read_text(encoding="utf-8")
    assert 'os.environ.get("REDVECTOR_API_TOKEN", "redvector-dev-token")' not in src
    assert 'raise ValueError' in src


# ── CWE-184: strict per-tool allowlist + argument schema ────────────────────
def test_unsupported_tool_rejected():
    v = rv._validate_generic_command
    for prog in (["bash", "-c", "id"], ["python", "-c", "x"], ["curl", "http://x"],
                 ["find", ".", "-name", "x"], ["gdb", "./a"], ["cat", "/etc/passwd"]):
        assert v(prog)[0] == 403, prog


def test_unknown_argument_rejected_by_default():
    v = rv._validate_generic_command
    # A supported tool with an unsupported/unknown option is rejected.
    status, msg = rv._validate_generic_command(["nmap", "-sV", "--totally-unknown", "t"])
    assert status == 403 and "not a supported option" in msg
    # Positional that fails the tool's validator is rejected.
    assert v(["gobuster", "notamode", "-u", "http://t"])[0] == 403


def test_value_schema_is_enforced():
    v = rv._validate_generic_command
    assert v(["nmap", "--top-ports", "100", "t"]) == (None, None)
    assert v(["nmap", "--top-ports", "abc", "t"])[0] == 403       # int expected
    assert v(["nmap", "-p", "80,443,8000-8100", "t"]) == (None, None)
    assert v(["nmap", "-iL", "/tmp/targets.txt", "t"]) == (None, None)
    assert v(["nmap", "-iL", "/etc/shadow", "t"])[0] == 403       # sensitive path
    # A value flag cannot swallow a following option (no flag smuggling).
    assert v(["nmap", "-oN", "-sV", "t"])[0] == 403


def test_generic_allowlist_is_schema_backed():
    # The legacy allowlist name now reflects exactly the schema-backed tools.
    assert rv.GENERIC_COMMAND_ALLOWLIST == frozenset(rv.TOOL_SCHEMAS)
    assert "nmap" in rv.GENERIC_COMMAND_ALLOWLIST
    for removed in ("cat", "find", "gdb", "exiftool", "volatility3", "hydra"):
        assert removed not in rv.GENERIC_COMMAND_ALLOWLIST


# ── Consistency: async endpoint cannot bypass validation ────────────────────
def test_async_endpoint_blocks_arbitrary_binary():
    resp = _client().post(
        "/api/process/execute-async", json={"command": "bash -c id"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 403


def test_async_endpoint_blocks_metacharacters():
    resp = _client().post(
        "/api/process/execute-async", json={"command": "nmap 127.0.0.1; id"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 400


def test_async_endpoint_requires_auth():
    resp = _client().post("/api/process/execute-async", json={"command": "nmap 127.0.0.1"})
    assert resp.status_code == 401


# ── Central guard: enforced on every execution path (incl. typed adapters) ──
def test_central_guard_blocks_sensitive_reads_and_find_exec():
    g = rv._command_execution_block_reason
    assert g(["strings", "/etc/shadow"])          # arbitrary file read via a typed adapter
    assert g(["find", ".", "-exec", "id", "+"])   # indirect execution
    assert g(["nmap", "-iL", "/root/.ssh/id_rsa", "t"])
    # execute_command() itself refuses rather than running these.
    out = rv.execute_command(["strings", "/etc/shadow"])
    assert out["success"] is False and "blocked" in out["error"].lower()


def test_central_guard_preserves_dedicated_scripting():
    """Tool-specific scripting used by dedicated adapters is not blocked by the
    cross-cutting guard (only Issue #3 classes are)."""
    g = rv._command_execution_block_reason
    assert g(["gdb", "-ex", "run", "./chall"]) is None
    assert g(["nmap", "--script", "vuln", "127.0.0.1"]) is None
    assert g(["strings", "/tmp/sample.bin"]) is None


def test_symlink_to_sensitive_is_blocked():
    """A symlink whose target is sensitive is resolved and blocked."""
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "id_rsa")
        with open(target, "w") as fh:
            fh.write("x")
        link = os.path.join(d, "harmless.txt")
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError, AttributeError):
            return  # symlink unsupported/unprivileged on this host; skip quietly
        assert rv._argument_accesses_sensitive_path(link)


# ── Python exec/install endpoints: disabled by default, opt-in, loopback-only ─
def test_python_endpoints_disabled_by_default():
    for path, body in (("/api/python/execute", {"script": "print(1)"}),
                       ("/api/python/install", {"package": "requests"})):
        resp = _client().post(path, json=body, headers=AUTH_HEADER)
        assert resp.status_code == 403, path
        assert "disabled" in resp.get_json()["error"].lower()


def test_python_endpoints_require_auth():
    resp = _client().post("/api/python/execute", json={"script": "print(1)"})
    assert resp.status_code == 401  # auth runs before the opt-in guard


def test_python_opt_in_allows_on_loopback(monkeypatch):
    monkeypatch.setattr(rv, "PYTHON_EXEC_ENABLED", True)
    monkeypatch.setattr(rv, "API_HOST", "127.0.0.1")
    assert rv._python_endpoint_block_reason() is None


def test_python_opt_in_blocked_on_non_loopback(monkeypatch):
    monkeypatch.setattr(rv, "PYTHON_EXEC_ENABLED", True)
    monkeypatch.setattr(rv, "API_HOST", "0.0.0.0")
    assert rv._python_endpoint_block_reason() is not None
    resp = _client().post("/api/python/execute", json={"script": "print(1)"}, headers=AUTH_HEADER)
    assert resp.status_code == 403


def test_python_opt_in_not_enabled_by_launchers():
    for name in ("start_redvector.sh", "start_redvector.ps1", "redvector_ai_desktop_manager.sh"):
        text = (REPO / name).read_text(encoding="utf-8")
        assert "REDVECTOR_ENABLE_PYTHON_EXEC" not in text, name


# ── Credential redaction in logs ────────────────────────────────────────────
def test_redact_command_removes_credentials():
    r = rv._redact_command_for_log
    for secret, cmd in [
        ("SuperSecret123", "hydra -l admin -p SuperSecret123 ssh://10.0.0.1"),
        ("ABCD1234TOKEN", "wpscan --url http://t --api-token ABCD1234TOKEN"),
        ("eyJhbGciOi.sig", 'httpx -u http://t -H "Authorization: Bearer eyJhbGciOi.sig"'),
        ("p4ss", "curl http://user:p4ss@example.com/path"),
        ("Winter2024", "netexec smb 10.0.0.1 -u admin -p Winter2024"),
        ("sessionsecret", "sqlmap -u http://t --cookie SESSION=sessionsecret"),
    ]:
        out = r(cmd)
        assert secret not in out, f"leaked {secret!r} in {out!r}"
        assert "***REDACTED***" in out or "***:***@" in out


def test_redact_preserves_non_secret_arguments():
    r = rv._redact_command_for_log
    # Ports and ordinary scan arguments must survive (logs stay useful).
    assert r("nmap -p 80,443 -sV 10.0.0.1") == "nmap -p 80,443 -sV 10.0.0.1"
    assert r("nmap --top-ports 100 scanme.org") == "nmap --top-ports 100 scanme.org"
    assert "FUZZ" in r("ffuf -u http://t/FUZZ -w /usr/share/wl.txt")


def test_redact_inline_secrets():
    f = rv._redact_inline_secrets
    assert "hunter2" not in f("Trying password=hunter2")
    assert "abc.def" not in f("header Authorization: Bearer abc.def.ghi")
    assert "secretpw" not in f("ftp://bob:secretpw@host/")


class _FakeStream:
    def readline(self):
        return ""

    def read(self, *a):
        return ""


def _install_mock_execution(monkeypatch):
    """Replace subprocess.Popen with a fake so NO real tool (hydra, nmap, …)
    runs, and trip any real network use. Returns a dict recording the argv the
    (mocked) executor received, to prove execution arguments are unchanged."""
    calls = {"popen": 0, "argv": None}

    class _FakePopen:
        def __init__(self, args, *a, **k):
            calls["popen"] += 1
            calls["argv"] = list(args)
            self.pid = 4242
            self.stdout = _FakeStream()
            self.stderr = _FakeStream()
            self.returncode = 0

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

        def terminate(self):
            pass

        def kill(self):
            pass

    monkeypatch.setattr(rv.subprocess, "Popen", _FakePopen)

    import socket as _socket

    def _no_network(*a, **k):
        raise AssertionError("network connection attempted during an isolated test")

    monkeypatch.setattr(_socket, "socket", _no_network)
    monkeypatch.setattr(_socket, "create_connection", _no_network)
    return calls


def _capture_server_logs(argv):
    srv_logger = logging.getLogger("redvector_server")
    captured = []

    class _Capture(logging.Handler):
        def emit(self, record):
            captured.append(record.getMessage())

    handler = _Capture()
    srv_logger.addHandler(handler)
    old_level = srv_logger.level
    srv_logger.setLevel(logging.INFO)
    try:
        rv.execute_command(argv, use_cache=False)
    finally:
        srv_logger.removeHandler(handler)
        srv_logger.setLevel(old_level)
    return captured


def test_command_summary_logs_never_leak_credentials(monkeypatch):
    """Fully isolated (mocked subprocess, no network): across every captured
    log record — EXECUTING, PROCESS, REGISTERED, FINAL RESULTS, SUCCESS and
    cleanup — the credential must never appear, for several credential formats.
    The original argv handed to the (mocked) executor stays intact."""
    calls = _install_mock_execution(monkeypatch)

    SECRET = "TOPSECRETPW123"
    cases = [
        ["hydra", "-l", "admin", "-p", SECRET, "ssh://127.0.0.1"],      # password flag
        ["httpx", "-u", "http://t", "-H", f"Authorization: Bearer {SECRET}"],  # auth header
        ["wpscan", "--url", "http://t", "--api-token", SECRET],         # API token
        ["curl", f"http://admin:{SECRET}@host/"],                       # URL-embedded password
    ]

    for argv in cases:
        before = calls["popen"]
        captured = _capture_server_logs(argv)

        # The mock really intercepted execution (no real tool, no network) ...
        assert calls["popen"] == before + 1, "subprocess.Popen was not intercepted"
        # ... and received the ORIGINAL, unredacted argv (execution unchanged).
        assert SECRET in " ".join(calls["argv"]), "execution argv must be unchanged"
        # The FINAL RESULTS command-summary line was emitted ...
        assert any("🚀 Command:" in m for m in captured), f"FINAL RESULTS line missing for {argv[0]}"
        # ... and NO captured log record (any summary/error/cleanup line) leaks it.
        leaks = [m for m in captured if SECRET in m]
        assert not leaks, f"credential leaked in logs for {argv[0]}: {leaks}"


def test_final_results_summary_line_is_redacted(monkeypatch):
    """Focused check on the FINAL RESULTS 'Command:' line itself."""
    calls = _install_mock_execution(monkeypatch)
    captured = _capture_server_logs(
        ["hydra", "-l", "admin", "-p", "TOPSECRETPW123", "ssh://127.0.0.1"]
    )
    cmd_lines = [m for m in captured if "🚀 Command:" in m]
    assert cmd_lines, "no FINAL RESULTS command line captured"
    assert all("TOPSECRETPW123" not in m for m in cmd_lines), cmd_lines
    assert any("***REDACTED***" in m for m in cmd_lines), cmd_lines


# ── Process-registry / dashboard / stats API-boundary redaction ─────────────
class _InertProcess:
    """Stand-in for a live subprocess.Popen handle (never executed)."""


_SECRET = "REGISTRYSECRET123"


def _sample_process_entry(pid=4242):
    return {
        "pid": pid,
        "command": f"hydra -l admin -p {_SECRET} ssh://10.0.0.1",
        "process": _InertProcess(),
        "start_time": 1.0,
        "status": "running",
        "progress": 0.0,
        "last_output": f"sent Authorization: Bearer {_SECRET}",
        "bytes_processed": 0,
        "password": _SECRET,
    }


def test_sanitize_process_response_redacts_and_preserves():
    entry = _sample_process_entry()
    original_command = entry["command"]
    out = rv._sanitize_process_response({4242: entry})[4242]
    # Credentials redacted
    assert _SECRET not in out["command"] and "***REDACTED***" in out["command"]
    assert _SECRET not in out["last_output"]
    assert out["password"] == "***REDACTED***"
    # Live handle never exposed; result is JSON-safe
    assert out["process"] == "<_InertProcess>"
    import json
    json.dumps(out)  # must not raise
    # Non-sensitive fields preserved, originals untouched (no in-place mutation)
    assert out["pid"] == 4242 and out["status"] == "running" and out["start_time"] == 1.0
    assert entry["command"] == original_command
    assert isinstance(entry["process"], _InertProcess)


def test_process_list_and_status_endpoints_redact():
    pid = 991234
    rv.active_processes[pid] = _sample_process_entry(pid)
    try:
        c = _client()
        r1 = c.get("/api/processes/list", headers=AUTH_HEADER)
        r2 = c.get(f"/api/processes/status/{pid}", headers=AUTH_HEADER)
    finally:
        rv.active_processes.pop(pid, None)
    for r in (r1, r2):
        assert r.status_code == 200, r.get_data(as_text=True)
        body = r.get_data(as_text=True)
        assert _SECRET not in body
        assert "***REDACTED***" in body


def test_dashboard_visual_string_redacts():
    safe = rv._sanitize_process_response({7: _sample_process_entry(7)})
    visual = rv.ModernVisualEngine.create_live_dashboard(safe)
    assert _SECRET not in visual


def test_async_submit_response_redacts(monkeypatch):
    # No execution: the pool submit is stubbed so nothing runs.
    monkeypatch.setattr(rv.enhanced_process_manager, "execute_command_async",
                        lambda argv, context=None: "task_stub")
    resp = _client().post(
        "/api/process/execute-async",
        json={"command": f"wpscan --url http://t --api-token {_SECRET}"},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert _SECRET not in body and "***REDACTED***" in body


def test_task_result_response_redacts(monkeypatch):
    monkeypatch.setattr(rv.enhanced_process_manager, "get_task_result",
                        lambda task_id: {"status": "completed",
                                          "command": f"hydra -p {_SECRET} ssh://t",
                                          "result": {"stdout": "ok", "return_code": 0}})
    resp = _client().get("/api/process/get-task-result/task_stub", headers=AUTH_HEADER)
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert _SECRET not in body
    # Legitimate, non-sensitive result output is preserved.
    assert "ok" in body


def test_pool_stats_response_redacts_nested_history(monkeypatch):
    monkeypatch.setattr(
        rv.enhanced_process_manager, "get_comprehensive_stats",
        lambda: {"process_pool": {"active_workers": 4},
                 "cache": {"hit_rate": 50},
                 "history": [{"command": f"sqlmap -u http://t --tamper x --cookie S={_SECRET}",
                              "success": True}]},
    )
    resp = _client().get("/api/process/pool-stats", headers=AUTH_HEADER)
    assert resp.status_code == 200
    assert _SECRET not in resp.get_data(as_text=True)
    # Non-sensitive metrics intact.
    assert resp.get_json()["stats"]["process_pool"]["active_workers"] == 4


def test_process_error_response_redacts_credentials(monkeypatch):
    """A credential embedded in an exception message must not leak through the
    serialized error response."""
    err = ("boom while running hydra -p ERRSECRET123 ssh://10.0.0.1 "
           "-H Authorization: Bearer ERRTOKENXYZ via http://u:ERRPASS@h/")

    def _raise():
        raise RuntimeError(err)

    monkeypatch.setattr(rv.enhanced_process_manager, "get_comprehensive_stats", _raise)
    resp = _client().get("/api/process/pool-stats", headers=AUTH_HEADER)
    assert resp.status_code == 500
    body = resp.get_data(as_text=True)
    for secret in ("ERRSECRET123", "ERRTOKENXYZ", "ERRPASS"):
        assert secret not in body, body


def test_error_message_redactor_unit():
    r = rv._redact_error_message
    assert "ERRSECRET" not in r("failed: hydra -p ERRSECRET ssh://t")
    assert "TOK" not in r("sent Authorization: Bearer TOK123 to host")
    assert "PW" not in r("connect http://admin:PW@host/path failed")


def test_task_result_findings_are_preserved(monkeypatch):
    """stdout/stderr carry real security-tool findings and must NOT be silently
    removed. Only command/metadata fields are redacted."""
    finding = "VULN: login form accepts password=admin123 at /admin"
    monkeypatch.setattr(
        rv.enhanced_process_manager, "get_task_result",
        lambda task_id: {"status": "completed",
                         "command": f"hydra -p {_SECRET} ssh://t",
                         "result": {"stdout": finding, "stderr": "", "return_code": 0}},
    )
    resp = _client().get("/api/process/get-task-result/t", headers=AUTH_HEADER)
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Our injected command credential is redacted ...
    assert _SECRET not in body
    # ... but the legitimate finding in stdout is preserved intact.
    assert finding in body


# ── Exception-LOGGING credential redaction (Kali-confirmed gap) ──────────────
# The process API *responses* were already redacted; these tests assert that
# the server LOG records emitted by the same exception handlers (logger.error,
# including full stack traces) never contain the synthetic credential either.
# Every test is fully isolated: no real tool runs and no socket is opened.
class _ServerLogCapture:
    """Capture every record emitted on the 'redvector_server' logger."""

    def __init__(self, level=logging.DEBUG):
        self._level = level
        self.records = []

    def __enter__(self):
        self._logger = logging.getLogger("redvector_server")
        parent = self

        class _Handler(logging.Handler):
            def emit(self, record):
                try:
                    parent.records.append(record.getMessage())
                except Exception:
                    parent.records.append(str(record.msg))

        self._handler = _Handler()
        self._logger.addHandler(self._handler)
        self._old_level = self._logger.level
        self._logger.setLevel(self._level)
        return self.records

    def __exit__(self, *exc):
        self._logger.removeHandler(self._handler)
        self._logger.setLevel(self._old_level)
        return False


_LOG_LEAK = "LOGLEAKPW123"
_LOG_LEAK_PAYLOADS = {
    "password_flag": f"hydra -l admin -p {_LOG_LEAK} ssh://10.0.0.1",
    "ambiguous_p": f"medusa -p {_LOG_LEAK} -h host",
    "auth_header": f"httpx -H Authorization: Bearer {_LOG_LEAK}",
    "api_token": f"wpscan --url http://t --api-token {_LOG_LEAK}",
    "url_userinfo": f"curl http://admin:{_LOG_LEAK}@host/",
    "cookie": f"sqlmap -u http://t --cookie SESSION={_LOG_LEAK}",
}


def test_pool_stats_exception_log_is_redacted(monkeypatch):
    """Regression for the Kali finding: the /api/process/pool-stats exception
    handler logged the raw exception. For every credential format, no captured
    server-log record may contain the secret, while the response stays a
    redacted HTTP 500 and a diagnostic line is still emitted."""
    for fmt, payload in _LOG_LEAK_PAYLOADS.items():
        def _raise(p=payload):
            raise RuntimeError(f"pool failure while processing {p}")

        monkeypatch.setattr(rv.enhanced_process_manager,
                            "get_comprehensive_stats", _raise)
        with _ServerLogCapture() as records:
            resp = _client().get("/api/process/pool-stats", headers=AUTH_HEADER)

        assert resp.status_code == 500
        assert _LOG_LEAK not in resp.get_data(as_text=True), fmt
        leaks = [m for m in records if _LOG_LEAK in m]
        assert not leaks, f"[{fmt}] credential leaked in server log: {leaks}"
        # Redacted, not suppressed: the handler still recorded the event.
        assert any("Error getting pool stats" in m for m in records), fmt


def test_process_endpoint_exception_logs_are_redacted(monkeypatch):
    """The same guarantee for another /api/process/* handler that logs on
    error (resource-usage), covering a password flag and an auth header."""
    secret = "ENDPOINTLEAK456"

    def _raise():
        raise RuntimeError(f"boom: hydra -p {secret} ssh://h "
                           f"-H Authorization: Bearer {secret}")

    monkeypatch.setattr(rv.enhanced_process_manager.resource_monitor,
                        "get_current_usage", _raise)
    with _ServerLogCapture() as records:
        resp = _client().get("/api/process/resource-usage", headers=AUTH_HEADER)
    assert resp.status_code == 500
    assert secret not in resp.get_data(as_text=True)
    assert not [m for m in records if secret in m], \
        [m for m in records if secret in m]


def test_command_endpoint_exception_log_and_traceback_redacted(monkeypatch):
    """/api/command logs both an error line and a full traceback on failure;
    neither the log nor the response may contain the credential."""
    secret = "CMDLEAK789"

    def _raise(*a, **k):
        raise RuntimeError(f"endpoint boom: sqlmap -u http://t --cookie S={secret}")

    monkeypatch.setattr(rv, "execute_command", _raise)
    with _ServerLogCapture() as records:
        resp = _client().post("/api/command",
                             json={"command": "echo diagnostic"},
                             headers=AUTH_HEADER)
    assert resp.status_code == 500
    assert secret not in resp.get_data(as_text=True)
    assert not [m for m in records if secret in m], [m for m in records if secret in m]
    # A traceback record was emitted (redaction, not suppression).
    assert any("Traceback (most recent call last)" in m for m in records)


def test_executor_exception_logs_and_result_redacted(monkeypatch):
    """When the (mocked) subprocess raises, the executor's error + TRACEBACK log
    lines and the returned stderr/error fields are all redacted. No real tool
    runs and no socket is opened."""
    _install_mock_execution(monkeypatch)
    secret = "EXECLEAK321"

    def _boom(*a, **k):
        raise RuntimeError(f"exec failed: hydra -l admin -p {secret} ssh://127.0.0.1")

    monkeypatch.setattr(rv.subprocess, "Popen", _boom)
    with _ServerLogCapture() as records:
        result = rv.execute_command(
            ["hydra", "-l", "admin", "-p", secret, "ssh://127.0.0.1"],
            use_cache=False,
        )
    assert not [m for m in records if secret in m], [m for m in records if secret in m]
    assert any("TRACEBACK" in m for m in records)
    assert secret not in (result.get("stderr", "") + str(result.get("error", "")))


def test_redact_log_text_redacts_multiline_traceback():
    """_redact_log_text masks credentials across a multi-line traceback while
    preserving the diagnostic structure (file, line, function)."""
    secret = "TBLEAKPW123"
    tb = (
        "Traceback (most recent call last):\n"
        '  File "redvector_server.py", line 8200, in execute\n'
        "    proc = subprocess.Popen(['hydra', '-p', '%s'])\n"
        "RuntimeError: auth http://admin:%s@h/ via Authorization: Bearer %s\n"
        % (secret, secret, secret)
    )
    out = rv._redact_log_text(tb)
    assert secret not in out, out
    assert "Traceback (most recent call last):" in out
    assert "line 8200, in execute" in out
    assert ("***REDACTED***" in out) or ("***:***@" in out)


def test_logging_handler_encoding_failure_does_not_leak(monkeypatch):
    """Redaction happens BEFORE any handler sees the record, so a handler that
    hits a Unicode/encoding error (e.g. a cp1252 Windows console choking on the
    log emojis) or formats the full record cannot resurface the secret. Drives
    the executor error + multiline TRACEBACK path with a mocked subprocess and
    no network, covering passwords, auth headers and URL-embedded credentials."""
    _install_mock_execution(monkeypatch)
    secret = "ENCLEAKPW123"

    def _boom(*a, **k):
        raise RuntimeError(
            f"exec failed: hydra -l admin -p {secret} ssh://127.0.0.1 "
            f"-H Authorization: Bearer {secret} via http://admin:{secret}@h/"
        )

    monkeypatch.setattr(rv.subprocess, "Popen", _boom)

    srv_logger = logging.getLogger("redvector_server")
    seen = []
    enc_failures = {"n": 0}

    class _StrictConsoleHandler(logging.Handler):
        def emit(self, record):
            formatted = self.format(record)          # full formatted record
            seen.append(formatted)
            try:
                formatted.encode("cp1252")           # emoji -> UnicodeEncodeError
            except UnicodeEncodeError:
                enc_failures["n"] += 1
                # The diagnostic fallbacks logging would use must also be clean.
                seen.append(formatted.encode("cp1252", "backslashreplace").decode("cp1252"))
                seen.append(formatted.encode("ascii", "backslashreplace").decode("ascii"))

    handler = _StrictConsoleHandler()
    srv_logger.addHandler(handler)
    old_level = srv_logger.level
    srv_logger.setLevel(logging.DEBUG)
    try:
        result = rv.execute_command(
            ["hydra", "-l", "admin", "-p", secret, "ssh://127.0.0.1"],
            use_cache=False,
        )
    finally:
        srv_logger.removeHandler(handler)
        srv_logger.setLevel(old_level)

    assert seen, "no log records were formatted"
    # A real encoding failure occurred (emoji on cp1252), exercising the fallback.
    assert enc_failures["n"] > 0, "expected a Unicode encoding failure to exercise the fallback path"
    leaks = [m for m in seen if secret in m]
    assert not leaks, f"credential leaked through a failing/formatting handler: {leaks}"
    # Diagnostic value preserved: the redaction marker survives the fallbacks.
    assert any("***REDACTED***" in m for m in seen)
    # The returned payload is redacted too (internal behaviour unchanged).
    assert secret not in (result.get("stderr", "") + str(result.get("error", "")))


def _main():
    import types

    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and isinstance(v, types.FunctionType)]

    class _MP:
        def __init__(self):
            self._undo = []

        def setattr(self, obj, name, value):
            self._undo.append((obj, name, getattr(obj, name)))
            setattr(obj, name, value)

        def undo(self):
            for obj, name, old in reversed(self._undo):
                setattr(obj, name, old)

    failed = 0
    for t in tests:
        mp = _MP()
        try:
            if "monkeypatch" in t.__code__.co_varnames[: t.__code__.co_argcount]:
                t(mp)
            else:
                t()
            print(f"PASS  {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {t.__name__}: {e!r}")
        finally:
            mp.undo()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_main())

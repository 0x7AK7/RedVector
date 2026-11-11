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


def test_executing_log_line_is_redacted():
    """The execution-layer EXECUTING log (used by every /api/tools/* adapter)
    must not contain credential values."""
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
        # The binary almost certainly is not installed here; the EXECUTING line
        # is emitted before the process is spawned regardless, which is what we
        # are asserting on. No network and no credential ever leaves the host.
        rv.execute_command(
            ["hydra", "-l", "admin", "-p", "TOPSECRETPW123", "ssh://127.0.0.1"],
            use_cache=False,
        )
    finally:
        srv_logger.removeHandler(handler)
        srv_logger.setLevel(old_level)

    exec_lines = [m for m in captured if "EXECUTING" in m]
    assert exec_lines, "no EXECUTING log line captured"
    assert all("TOPSECRETPW123" not in m for m in exec_lines), exec_lines


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

#!/usr/bin/env python3
"""Regression tests for the MCP configuration logic in
``redvector_ai_desktop_manager.sh`` (function ``claude_configure_mcp``).

These tests extract the *actual* embedded Python writer block from the shipped
manager script at runtime and execute it against **temporary** configuration
fixtures in a throwaway directory. They never read, write or depend on a live
Claude Desktop configuration, and they do not run the interactive manager.

Run standalone (no pytest needed):   python tests/test_claude_mcp_config.py
Or with pytest:                       pytest tests/test_claude_mcp_config.py
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
MANAGER = REPO / "redvector_ai_desktop_manager.sh"
SECURE_LAUNCHER = str(pathlib.Path.home() / ".local" / "bin" / "redvector_claude_secure.sh")


def _extract_writer_block():
    """Return the embedded `python3 -I - <<'PY' ... PY` block that WRITES the
    config (identified by containing `os.replace`)."""
    lines = MANAGER.read_text(encoding="utf-8").splitlines()
    blocks, i = [], 0
    while i < len(lines):
        if "<<'PY'" in lines[i]:
            start = i + 1
            j = start
            while j < len(lines) and lines[j].strip() != "PY":
                j += 1
            blocks.append("\n".join(lines[start:j]))
            i = j + 1
        else:
            i += 1
    writers = [b for b in blocks if "os.replace" in b]
    assert len(writers) == 1, f"expected exactly 1 writer heredoc, found {len(writers)}"
    return writers[0]


WRITER = _extract_writer_block()


def _run(project_dir, config_path):
    env = dict(os.environ)
    env["RV_PROJECT"] = str(project_dir)
    env["RV_CONFIG"] = str(config_path)
    return subprocess.run(
        [sys.executable, "-I", "-"],
        input=WRITER, env=env, capture_output=True, text=True,
    )


def _load(p):
    return json.loads(pathlib.Path(p).read_text(encoding="utf-8"))


# ── Tests ──────────────────────────────────────────────────────────────────
def test_fresh_registration():
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        cfg = d / "claude_desktop_config.json"  # does not exist yet
        proc = _run(d, cfg)
        assert proc.returncode == 0, proc.stderr
        rv = _load(cfg)["mcpServers"]["redvector-ai"]
        assert rv["command"] == "/bin/bash"
        assert rv["args"] == [str(d / "start_redvector.sh")]
        assert "redvector-dev-token" not in cfg.read_text(encoding="utf-8")


def test_preserves_other_servers():
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        cfg = d / "cfg.json"
        other = {"command": "node", "args": ["server.js"], "env": {"K": "v"}}
        cfg.write_text(json.dumps({"mcpServers": {"other": other}}), encoding="utf-8")
        proc = _run(d, cfg)
        assert proc.returncode == 0, proc.stderr
        data = _load(cfg)
        assert data["mcpServers"]["other"] == other
        assert "redvector-ai" in data["mcpServers"]


def test_preserves_secure_custom_launcher():
    """KEY regression: an existing secure launcher must NOT be replaced by
    start_redvector.sh, and its extra keys must survive."""
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        cfg = d / "cfg.json"
        secure = {
            "command": "/bin/bash",
            "args": [SECURE_LAUNCHER],
            "timeout": 300,
            "alwaysAllow": ["server_health"],
            "cwd": "/opt/redvector",
            "env": {"REDVECTOR_API_TOKEN": "a-real-user-token"},
        }
        cfg.write_text(json.dumps({"mcpServers": {"redvector-ai": secure}}), encoding="utf-8")
        proc = _run(d, cfg)
        assert proc.returncode == 0, proc.stderr
        rv = _load(cfg)["mcpServers"]["redvector-ai"]
        assert rv["args"] == [SECURE_LAUNCHER], "secure launcher args were replaced!"
        assert "start_redvector.sh" not in json.dumps(rv), "start_redvector.sh was injected!"
        assert rv["timeout"] == 300
        assert rv["alwaysAllow"] == ["server_health"]
        assert rv["cwd"] == "/opt/redvector"
        assert rv["env"]["REDVECTOR_API_TOKEN"] == "a-real-user-token"
        assert "redvector-dev-token" not in cfg.read_text(encoding="utf-8")


def test_repoints_managers_own_launcher_but_keeps_keys():
    """An existing start_redvector.sh entry at a stale path is repointed to the
    current project, but its other keys are preserved (not dropped)."""
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        cfg = d / "cfg.json"
        existing = {
            "command": "/bin/bash",
            "args": ["/old/location/start_redvector.sh"],
            "timeout": 120,
            "env": {"REDVECTOR_API_TOKEN": "keep-me"},
        }
        cfg.write_text(json.dumps({"mcpServers": {"redvector-ai": existing}}), encoding="utf-8")
        proc = _run(d, cfg)
        assert proc.returncode == 0, proc.stderr
        rv = _load(cfg)["mcpServers"]["redvector-ai"]
        assert rv["args"] == [str(d / "start_redvector.sh")], "path was not refreshed"
        assert rv["timeout"] == 120, "extra key was dropped"
        assert rv["env"]["REDVECTOR_API_TOKEN"] == "keep-me"
        assert "redvector-dev-token" not in cfg.read_text(encoding="utf-8")


def test_never_injects_dev_token():
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        cfg = d / "cfg.json"
        proc = _run(d, cfg)
        assert proc.returncode == 0, proc.stderr
        rv = _load(cfg)["mcpServers"]["redvector-ai"]
        assert "env" not in rv, "no env (and no token) should be added on fresh install"
        assert "redvector-dev-token" not in cfg.read_text(encoding="utf-8")


def test_malformed_config_rejected_no_data_loss():
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        cfg = d / "cfg.json"
        bad = "{ this is : not valid json "
        cfg.write_text(bad, encoding="utf-8")
        proc = _run(d, cfg)
        assert proc.returncode != 0, "malformed config should be rejected"
        assert cfg.read_text(encoding="utf-8") == bad, "original file must be untouched"


def test_idempotent_secure_launcher():
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        cfg = d / "cfg.json"
        secure = {"command": "/bin/bash", "args": [SECURE_LAUNCHER], "alwaysAllow": ["x"]}
        cfg.write_text(json.dumps({"mcpServers": {"redvector-ai": secure}}), encoding="utf-8")
        assert _run(d, cfg).returncode == 0
        first = _load(cfg)["mcpServers"]["redvector-ai"]
        assert _run(d, cfg).returncode == 0
        second = _load(cfg)["mcpServers"]["redvector-ai"]
        assert first == second == secure, "re-running changed a preserved secure entry"


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
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

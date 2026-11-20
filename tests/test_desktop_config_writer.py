#!/usr/bin/env python3
"""Tests for the shared Claude Desktop config writer ``redvector_desktop_config``.

These exercise the SAME safety contract the Linux manager enforces, now for the
cross-platform one-command installers: preserve other servers and all
pre-existing keys, never replace a custom launcher, NEVER add/modify
``alwaysAllow`` (no automatic permission grant), migrate the revoked dev token
from the default launcher only, back up + write atomically, reject malformed
configs, and refuse while Claude Desktop is running.

Imports only the writer module (stdlib + lazy psutil) — no MCP SDK — so it runs
on the Windows dev box and on Kali. Temporary fixtures only; never touches a real
Claude Desktop configuration.

Run:  pytest tests/test_desktop_config_writer.py
"""
import json
import os
import pathlib
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import redvector_desktop_config as cw  # noqa: E402

try:
    import pytest
except Exception:  # pragma: no cover
    pytest = None

SECURE = str(pathlib.Path.home() / ".local" / "bin" / "redvector_claude_secure.sh")


def _cfg(d, name="claude_desktop_config.json"):
    return pathlib.Path(d) / name


def _reg(cfg, project, platform="posix", check_running=False):
    return cw.register(cfg, project, platform=platform, check_running=check_running)


def _load(p):
    return json.loads(pathlib.Path(p).read_text(encoding="utf-8"))


def test_fresh_registration_posix():
    with tempfile.TemporaryDirectory() as d:
        cfg = _cfg(d)
        r = _reg(cfg, d, "posix")
        rv = _load(cfg)["mcpServers"]["redvector-ai"]
        assert rv["command"] == "/bin/bash"
        assert rv["args"] == [str(pathlib.Path(d).resolve() / "start_redvector.sh")]
        assert "env" not in rv and "alwaysAllow" not in rv
        assert r["launcher_mode"] == "registered-default"
        assert "redvector-dev-token" not in cfg.read_text(encoding="utf-8")


def test_fresh_registration_windows():
    with tempfile.TemporaryDirectory() as d:
        cfg = _cfg(d)
        _reg(cfg, d, "windows")
        rv = _load(cfg)["mcpServers"]["redvector-ai"]
        assert rv["command"] == "powershell"
        assert rv["args"][0:4] == ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]
        assert os.path.basename(rv["args"][-1]) == "start_redvector.ps1"
        assert "alwaysAllow" not in rv


def test_preserves_other_servers():
    with tempfile.TemporaryDirectory() as d:
        cfg = _cfg(d)
        other = {"command": "node", "args": ["server.js"], "env": {"K": "v"}}
        cfg.write_text(json.dumps({"mcpServers": {"other": other}}), encoding="utf-8")
        _reg(cfg, d, "posix")
        data = _load(cfg)
        assert data["mcpServers"]["other"] == other
        assert "redvector-ai" in data["mcpServers"]


def test_preserves_custom_launcher_and_keys():
    with tempfile.TemporaryDirectory() as d:
        cfg = _cfg(d)
        secure = {"command": "/bin/bash", "args": [SECURE], "timeout": 300,
                  "alwaysAllow": ["server_health"], "cwd": "/opt/redvector",
                  "env": {"REDVECTOR_API_TOKEN": "a-real-user-token"}}
        cfg.write_text(json.dumps({"mcpServers": {"redvector-ai": secure}}), encoding="utf-8")
        r = _reg(cfg, d, "posix")
        rv = _load(cfg)["mcpServers"]["redvector-ai"]
        assert rv == secure, "custom launcher entry must be preserved byte-for-byte"
        assert r["launcher_mode"] == "preserved-custom"


def test_repoints_default_launcher_keeps_keys():
    with tempfile.TemporaryDirectory() as d:
        cfg = _cfg(d)
        existing = {"command": "/bin/bash", "args": ["/old/loc/start_redvector.sh"],
                    "timeout": 120, "env": {"REDVECTOR_API_TOKEN": "keep-me"}}
        cfg.write_text(json.dumps({"mcpServers": {"redvector-ai": existing}}), encoding="utf-8")
        _reg(cfg, d, "posix")
        rv = _load(cfg)["mcpServers"]["redvector-ai"]
        assert rv["args"] == [str(pathlib.Path(d).resolve() / "start_redvector.sh")]
        assert rv["timeout"] == 120
        assert rv["env"]["REDVECTOR_API_TOKEN"] == "keep-me"


def test_never_injects_dev_token_fresh():
    with tempfile.TemporaryDirectory() as d:
        cfg = _cfg(d)
        _reg(cfg, d, "posix")
        rv = _load(cfg)["mcpServers"]["redvector-ai"]
        assert "env" not in rv
        assert "redvector-dev-token" not in cfg.read_text(encoding="utf-8")


def test_never_adds_alwaysAllow_and_preserves_existing():
    # Fresh: no alwaysAllow added.
    with tempfile.TemporaryDirectory() as d:
        cfg = _cfg(d)
        _reg(cfg, d, "posix")
        assert "alwaysAllow" not in _load(cfg)["mcpServers"]["redvector-ai"]
    # Existing default-launcher entry WITH alwaysAllow: preserved untouched.
    with tempfile.TemporaryDirectory() as d:
        cfg = _cfg(d)
        existing = {"command": "/bin/bash", "args": [str(pathlib.Path(d).resolve() / "start_redvector.sh")],
                    "alwaysAllow": ["server_health", "get_cache_stats"]}
        cfg.write_text(json.dumps({"mcpServers": {"redvector-ai": existing}}), encoding="utf-8")
        _reg(cfg, d, "posix")
        rv = _load(cfg)["mcpServers"]["redvector-ai"]
        assert rv["alwaysAllow"] == ["server_health", "get_cache_stats"]


def test_migrates_dev_token_from_default_launcher():
    with tempfile.TemporaryDirectory() as d:
        cfg = _cfg(d)
        existing = {"command": "/bin/bash", "args": ["/old/start_redvector.sh"],
                    "env": {"REDVECTOR_API_TOKEN": "redvector-dev-token", "HTTP_PROXY": "http://p:8080"}}
        cfg.write_text(json.dumps({"mcpServers": {"redvector-ai": existing}}), encoding="utf-8")
        r = _reg(cfg, d, "posix")
        rv = _load(cfg)["mcpServers"]["redvector-ai"]
        assert rv.get("env", {}).get("REDVECTOR_API_TOKEN") is None
        assert rv["env"]["HTTP_PROXY"] == "http://p:8080"
        assert r["migrated_dev_token"] is True
        assert "redvector-dev-token" not in cfg.read_text(encoding="utf-8")


def test_custom_launcher_dev_token_reported_not_modified():
    with tempfile.TemporaryDirectory() as d:
        cfg = _cfg(d)
        custom = {"command": "/bin/bash", "args": [SECURE],
                  "env": {"REDVECTOR_API_TOKEN": "redvector-dev-token"}}
        cfg.write_text(json.dumps({"mcpServers": {"redvector-ai": custom}}), encoding="utf-8")
        r = _reg(cfg, d, "posix")
        rv = _load(cfg)["mcpServers"]["redvector-ai"]
        assert rv["env"]["REDVECTOR_API_TOKEN"] == "redvector-dev-token"
        assert r["custom_launcher_dev_token"] is True


def test_malformed_config_rejected_no_change():
    with tempfile.TemporaryDirectory() as d:
        cfg = _cfg(d)
        bad = "{ not valid json "
        cfg.write_text(bad, encoding="utf-8")
        err = None
        try:
            _reg(cfg, d, "posix")
        except cw.ConfigError as e:
            err = e
        assert err is not None, "malformed config must raise ConfigError"
        assert cfg.read_text(encoding="utf-8") == bad, "original file must be untouched"


def test_backup_created_and_atomic_valid_json():
    with tempfile.TemporaryDirectory() as d:
        cfg = _cfg(d)
        cfg.write_text(json.dumps({"mcpServers": {"other": {"command": "x", "args": []}}}), encoding="utf-8")
        r = _reg(cfg, d, "posix")
        assert r["backup"] and pathlib.Path(r["backup"]).exists(), "a backup must be created"
        json.loads(cfg.read_text(encoding="utf-8"))  # valid JSON after atomic write
        # no stray temp files left behind
        leftovers = [p for p in pathlib.Path(d).iterdir() if p.name.startswith(".rv-mcp-")]
        assert not leftovers, leftovers


def test_refuses_when_claude_running(monkeypatch):
    with tempfile.TemporaryDirectory() as d:
        cfg = _cfg(d)
        monkeypatch.setattr(cw, "claude_run_state", lambda: "running")
        err = None
        try:
            cw.register(cfg, d, platform="posix", check_running=True)
        except cw.ConfigError as e:
            err = e
        assert err is not None and "running" in str(err).lower()
        assert not cfg.exists(), "nothing may be written while Claude Desktop is running"


def test_refuses_when_run_state_unknown(monkeypatch):
    """Fail-safe: if the running state cannot be determined, refuse to write."""
    with tempfile.TemporaryDirectory() as d:
        cfg = _cfg(d)
        monkeypatch.setattr(cw, "claude_run_state", lambda: "unknown")
        err = None
        try:
            cw.register(cfg, d, platform="posix", check_running=True)
        except cw.ConfigError as e:
            err = e
        assert err is not None and "could not determine" in str(err).lower()
        assert not cfg.exists(), "nothing may be written when the state is unknown"


def test_assume_stopped_proceeds_despite_unknown(monkeypatch):
    """A caller that verified 'stopped' with a reliable OS check (assume_stopped)
    is not blocked by a psutil 'unknown' or 'running' psutil reading."""
    with tempfile.TemporaryDirectory() as d:
        cfg = _cfg(d)
        monkeypatch.setattr(cw, "claude_run_state", lambda: "unknown")
        cw.register(cfg, d, platform="posix", check_running=True, assume_stopped=True)
        assert "redvector-ai" in _load(cfg)["mcpServers"]


def test_run_state_unknown_without_psutil(monkeypatch):
    """claude_run_state reports 'unknown' (not 'stopped') when psutil is absent."""
    import builtins
    real_import = builtins.__import__

    def _no_psutil(name, *a, **k):
        if name == "psutil":
            raise ImportError("psutil unavailable")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", _no_psutil)
    assert cw.claude_run_state() == "unknown"


def test_idempotent_default_launcher():
    with tempfile.TemporaryDirectory() as d:
        cfg = _cfg(d)
        _reg(cfg, d, "posix")
        first = _load(cfg)["mcpServers"]["redvector-ai"]
        _reg(cfg, d, "posix")
        second = _load(cfg)["mcpServers"]["redvector-ai"]
        assert first == second


def _main():
    import types

    class _MP:
        def __init__(self): self._u = []
        def setattr(self, o, n, v): self._u.append((o, n, getattr(o, n))); setattr(o, n, v)
        def undo(self):
            for o, n, v in reversed(self._u): setattr(o, n, v)

    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and isinstance(v, types.FunctionType)]
    failed = 0
    for t in tests:
        mp = _MP()
        try:
            if "monkeypatch" in t.__code__.co_varnames[:t.__code__.co_argcount]:
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

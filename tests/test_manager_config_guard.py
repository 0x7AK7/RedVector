#!/usr/bin/env python3
"""Regression tests for the Claude Desktop config-write guard in
``redvector_ai_desktop_manager.sh`` (function ``claude_configure_mcp``).

The guard must REFUSE to modify the configuration while Claude Desktop is
running (detected via ``pgrep``), print a clear "fully quit" instruction and
change nothing; and it must WRITE normally when Claude Desktop is closed. These
tests run the REAL shell function in an isolated environment with stubbed
``pgrep`` / ``dpkg-query`` / ``python3`` on PATH, a throwaway HOME and config
path. They never read or write a real Claude Desktop configuration and never
start Claude Desktop. Skipped where ``bash`` is unavailable (e.g. a bare Windows
shell); they run on Kali and anywhere Git Bash is on PATH.

Run with pytest:   pytest tests/test_manager_config_guard.py
"""
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile

try:
    import pytest
except Exception:  # pragma: no cover
    pytest = None

REPO = pathlib.Path(__file__).resolve().parents[1]
MANAGER = REPO / "redvector_ai_desktop_manager.sh"
BASH = shutil.which("bash")

if pytest is not None:
    pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not available on PATH")


def _bash_path(p) -> str:
    """Render a filesystem path for use inside bash. On Windows (Git Bash) a
    ``C:/foo`` entry would split a colon-separated PATH at the drive colon, so
    convert drive paths to MSYS form (``/c/foo``). POSIX paths are unchanged."""
    s = str(p).replace("\\", "/")
    if os.name == "nt":
        m = re.match(r"^([A-Za-z]):/(.*)$", s)
        if m:
            return f"/{m.group(1).lower()}/{m.group(2)}"
    return s


def _stub(dirpath: pathlib.Path, name: str, body: str) -> None:
    p = dirpath / name
    p.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _stripped_manager(dirpath: pathlib.Path) -> pathlib.Path:
    """Copy the manager without its trailing ``main "$@"`` so sourcing it only
    defines functions (does not launch the interactive menu)."""
    src = MANAGER.read_text(encoding="utf-8")
    src = re.sub(r'\nmain\s+"\$@"\s*\n?\Z', "\n", src)
    out = dirpath / "manager_nomain.sh"
    out.write_text(src, encoding="utf-8")
    return out


def _run_configure(running: bool):
    d = pathlib.Path(tempfile.mkdtemp(prefix="rv-guard-"))
    binp = d / "bin"
    binp.mkdir()
    _stub(binp, "pgrep", "exit 0\n" if running else "exit 1\n")   # running -> found
    _stub(binp, "dpkg-query", "echo 'install ok installed'\n")    # claude_installed -> true
    pyexe = sys.executable.replace("\\", "/")
    _stub(binp, "python3", f'exec "{pyexe}" "$@"\n')              # writer interpreter

    cfg = d / "claude_desktop_config.json"
    mgr = _stripped_manager(d)
    harness = (
        f'export PATH="{_bash_path(binp)}:$PATH"\n'
        f'export HOME="{_bash_path(d)}"\n'
        f'source "{_bash_path(mgr)}"\n'
        f'require_non_root() {{ return 0; }}\n'     # test env may run as root
        f'PROJECT="{_bash_path(REPO)}"\n'
        f'CLAUDE_CONFIG="{_bash_path(cfg)}"\n'
        f'claude_configure_mcp\n'
        f'echo "RC=$?"\n'
    )
    proc = subprocess.run([BASH, "-c", harness], capture_output=True, text=True)
    return proc, cfg


def test_config_refused_while_claude_desktop_running():
    proc, cfg = _run_configure(running=True)
    out = proc.stdout + proc.stderr
    assert "RC=1" in out, out
    assert "Fully quit" in out, out
    assert not cfg.exists(), "configuration must NOT be written while Claude Desktop is running"


def test_config_written_when_claude_desktop_closed():
    proc, cfg = _run_configure(running=False)
    out = proc.stdout + proc.stderr
    assert "RC=0" in out, out
    assert cfg.exists(), "configuration should be written when Claude Desktop is closed"
    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert "redvector-ai" in data.get("mcpServers", {}), data
    assert "redvector-dev-token" not in cfg.read_text(encoding="utf-8")


def _main():
    import types

    if BASH is None:
        print("SKIP (all) — bash not available")
        return 0
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

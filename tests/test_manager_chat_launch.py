#!/usr/bin/env python3
"""Regression tests for the Claude Desktop Chat-mode launch in
``redvector_ai_desktop_manager.sh`` (function ``claude_start``).

The launcher must prioritise the vendor-documented Chat deep link
``claude://claude.ai/new``, attempt it whenever ``xdg-open`` exists (even when
``xdg-mime`` reports no handler), fall back to a direct launch on a real
dispatch failure, and always tell the user to select the Chat tab. These tests
run the REAL shell function in an isolated environment with stubbed
``xdg-open`` / ``timeout`` / ``pgrep`` / ``claude-desktop`` / ``dpkg-query`` on
PATH; they never launch Claude Desktop. Skipped where ``bash`` is unavailable.

Run with pytest:   pytest tests/test_manager_chat_launch.py
"""
import os
import pathlib
import re
import shutil
import stat
import subprocess
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
    src = MANAGER.read_text(encoding="utf-8")
    src = re.sub(r'\nmain\s+"\$@"\s*\n?\Z', "\n", src)
    out = dirpath / "manager_nomain.sh"
    out.write_text(src, encoding="utf-8")
    return out


def _run_start(xdg_rc: int, pgrep_rc: int):
    d = pathlib.Path(tempfile.mkdtemp(prefix="rv-start-"))
    binp = d / "bin"
    binp.mkdir()
    log = d / "log"
    _stub(binp, "xdg-open", f'echo "XDGOPEN $*" >> "{_bash_path(log)}"\nexit {xdg_rc}\n')
    _stub(binp, "timeout", 'shift\nexec "$@"\n')                  # drop duration, run cmd
    _stub(binp, "pgrep", f"exit {pgrep_rc}\n")
    _stub(binp, "claude-desktop", f'echo "CLAUDEDESKTOP $*" >> "{_bash_path(log)}"\nsleep 3\n')
    _stub(binp, "dpkg-query", "echo 'install ok installed'\n")   # claude_installed -> true
    mgr = _stripped_manager(d)
    harness = (
        f'export PATH="{_bash_path(binp)}:$PATH"\n'
        f'export HOME="{_bash_path(d)}"\n'
        f'export DISPLAY=":0"\n'                                   # gui_available -> true
        f'source "{_bash_path(mgr)}"\n'
        f'require_non_root() {{ return 0; }}\n'
        f'claude_start\n'
        f'echo "RC=$?"\n'
    )
    proc = subprocess.run([BASH, "-c", harness], capture_output=True, text=True)
    logtext = log.read_text(encoding="utf-8") if log.exists() else ""
    return proc, logtext


def test_chat_deep_link_dispatched_without_xdg_mime_handler():
    """xdg-open present, dispatch succeeds (rc 0), process appears: the Chat URI
    is used and no direct binary launch occurs."""
    proc, log = _run_start(xdg_rc=0, pgrep_rc=0)
    out = proc.stdout + proc.stderr + log
    assert "XDGOPEN claude://claude.ai/new" in log, log
    assert "CLAUDEDESKTOP" not in log, "must not direct-launch when the deep link dispatched"
    assert "RC=0" in out, out


def test_falls_back_to_direct_launch_on_deep_link_failure():
    """A real dispatch failure (xdg-open rc 4) falls through to a direct launch,
    with a clear instruction to select the Chat tab."""
    proc, log = _run_start(xdg_rc=4, pgrep_rc=1)
    out = proc.stdout + proc.stderr + log
    assert "XDGOPEN claude://claude.ai/new" in log, "the Chat deep link must be attempted first"
    assert "CLAUDEDESKTOP" in log, "a dispatch failure must fall back to a direct launch"
    assert "Chat tab" in out, "the fallback must instruct the user to select the Chat tab"


def test_manager_uses_chat_uri_not_code_or_cowork():
    text = MANAGER.read_text(encoding="utf-8")
    assert "claude://claude.ai/new" in text
    assert "claude://claude.ai/code" not in text, "must not launch Code mode"
    assert "cowork/new" not in text, "must not launch Cowork mode"


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

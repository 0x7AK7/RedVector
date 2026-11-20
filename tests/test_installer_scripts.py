#!/usr/bin/env python3
"""Lint/contract tests for the one-command installers (install.sh / install.ps1).

These do NOT run a full install (which would create a venv and hit PyPI). They
verify the installers are syntactically valid and wire up the required safety
properties: explicit consent before touching the Claude Desktop config, a
running-guard, delegation to the shared safe writer, dependency error reporting,
and the absence of any automatic permission grant (no ``alwaysAllow`` write) or
dev-token injection. Full install behaviour is covered by manual acceptance on
Kali and Windows.
"""
import pathlib
import shutil
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
SH = REPO / "install.sh"
PS1 = REPO / "install.ps1"

try:
    import pytest
except Exception:  # pragma: no cover
    pytest = None

BASH = shutil.which("bash")


def test_installers_exist():
    assert SH.exists() and PS1.exists()


def test_install_sh_syntax_ok():
    if BASH is None:
        if pytest:
            pytest.skip("bash not available")
        return
    proc = subprocess.run([BASH, "-n", str(SH)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_install_sh_safety_properties():
    t = SH.read_text(encoding="utf-8")
    assert "redvector_desktop_config.py" in t, "must delegate config write to the shared safe writer"
    assert "redvector_credentials.py" in t, "must reuse the credential helper"
    assert "requirements.txt" in t
    assert "pgrep" in t and "claude-desktop" in t, "must guard against a running Claude Desktop"
    assert "[y/N]" in t, "must ask for explicit consent before config changes"
    assert ".install-pip.log" in t and "tail" in t, "must report dependency install errors"
    # the installer must never WRITE a JSON alwaysAllow key (it delegates all
    # config writing to the shared writer, which is tested to never add it); a
    # single-quoted mention in a reassuring comment is fine.
    assert '"alwaysAllow"' not in t, "installer must never write an alwaysAllow key"
    # no arbitrary Python upper bound; only a sane lower bound
    assert "(3,9)" in t


def test_install_ps1_safety_properties():
    t = PS1.read_text(encoding="utf-8")
    assert "redvector_desktop_config.py" in t
    assert "redvector_credentials.py" in t
    assert "requirements.txt" in t
    assert "Get-Process" in t and "claude" in t.lower(), "must guard against a running Claude Desktop"
    assert "Read-Host" in t, "must ask for explicit consent before config changes"
    assert ".install-pip.log" in t, "must report dependency install errors"
    assert '"alwaysAllow"' not in t, "installer must never write an alwaysAllow key"


def test_install_ps1_uses_direct_invocation_not_cmd_c():
    """Regression for the cmd /c percent-expansion bug: install.ps1 must invoke
    Python directly and carry no fragile `cmd /c` Python calls or `%d` snippets."""
    t = PS1.read_text(encoding="utf-8")
    assert "cmd /c" not in t, "must not route Python through cmd /c"
    assert "%d" not in t, "must not embed cmd-expandable %d format specifiers"
    assert "& $PyExe @PyArgs" in t, "must invoke Python directly (exe + args array)"
    # supports both `python` and `py -3`
    assert '"py"' in t and '"-3"' in t, "must support the Windows `py -3` launcher"
    assert "--assume-stopped" in t, "must assert its verified Get-Process result to the writer"


def test_install_sh_asserts_stopped_only_after_check():
    t = SH.read_text(encoding="utf-8")
    assert "--assume-stopped" in t and "ASSUME_STOPPED" in t, \
        "install.sh must assert stopped only after its own pgrep check"


def test_platform_overrides_are_explicit():
    assert "--platform posix" in SH.read_text(encoding="utf-8")
    assert "--platform windows" in PS1.read_text(encoding="utf-8")


def _main():
    import types
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and isinstance(v, types.FunctionType)]
    failed = 0
    for t in tests:
        try:
            t(); print(f"PASS  {t.__name__}")
        except AssertionError as e:
            failed += 1; print(f"FAIL  {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1; print(f"ERROR {t.__name__}: {e!r}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_main())

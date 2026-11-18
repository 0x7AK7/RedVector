#!/usr/bin/env python3
"""Isolated regression tests for the secure API-credential lifecycle
(``redvector_credentials.py``) shared by the launcher and the Claude Desktop
manager.

Every test uses a throwaway temporary directory and synthetic credentials. No
real network, no penetration-testing tools, and no real Claude Desktop or user
configuration are ever touched. The module performs no network I/O at all.

Run standalone:   python tests/test_credential_lifecycle.py
Or with pytest:   pytest tests/test_credential_lifecycle.py
"""
import concurrent.futures as cf
import os
import pathlib
import stat
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import redvector_credentials as cred  # noqa: E402

MODULE = str(REPO / "redvector_credentials.py")
DEV_TOKEN = "redvector-dev-token"
POSIX = os.name == "posix"


def _tmp_token_path():
    d = tempfile.mkdtemp(prefix="rv-cred-")
    return pathlib.Path(d) / "nested" / "api_token"


def _clean_env():
    """Subprocess env with no externally provided REDVECTOR_API_TOKEN, so the
    CLI exercises the persisted-file path (other test modules set that variable
    at import time in the shared pytest process)."""
    env = dict(os.environ)
    env.pop("REDVECTOR_API_TOKEN", None)
    return env


# 1 + 2: fresh install generates a strong token and creates the file.
def test_fresh_install_generates_secure_token():
    p = _tmp_token_path()
    assert not p.exists()
    tok = cred.ensure_token(str(p))
    assert cred.is_valid_token(tok) and tok != DEV_TOKEN
    assert len(tok) >= 40, "generated token is not high-entropy"
    assert p.is_file()
    assert p.read_text(encoding="utf-8").strip() == tok


# 3 + 16: persistence / idempotency — reuse never rotates a valid token.
def test_token_persists_and_is_not_rotated():
    p = _tmp_token_path()
    first = cred.ensure_token(str(p))
    for _ in range(5):
        assert cred.ensure_token(str(p)) == first


# 11: "restart" — a brand-new process reads the same persisted token.
def test_token_survives_process_restart():
    p = _tmp_token_path()
    first = cred.ensure_token(str(p))
    out = subprocess.run(
        [sys.executable, MODULE, "ensure", "--path", str(p)],
        capture_output=True, text=True, env=_clean_env(),
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout == first, "restart produced a different token"


# 4: migrate a revoked development token found in the credential file.
def test_migrates_revoked_dev_token_in_file():
    p = _tmp_token_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(DEV_TOKEN + "\n", encoding="utf-8")
    tok = cred.ensure_token(str(p))
    assert tok != DEV_TOKEN and cred.is_valid_token(tok)
    assert p.read_text(encoding="utf-8").strip() == tok


# 5: a valid explicitly provided token is honoured and NOT persisted.
def test_preserves_valid_provided_token_without_writing():
    p = _tmp_token_path()
    seeded = cred.ensure_token(str(p))  # file now holds `seeded`
    provided = "user-managed-strong-token-abcdef123456"
    assert cred.ensure_token(str(p), provided=provided) == provided
    assert p.read_text(encoding="utf-8").strip() == seeded, "provided token overwrote the store"


# 6: an explicitly provided DEV token is ignored (migrated away), file reused.
def test_ignores_provided_dev_token():
    p = _tmp_token_path()
    seeded = cred.ensure_token(str(p))
    assert cred.ensure_token(str(p), provided=DEV_TOKEN) == seeded


# 9: credential file is 0600 and its directory 0700 (POSIX).
def test_file_and_dir_permissions():
    if not POSIX:
        return  # chmod bits are not meaningfully enforced on Windows
    p = _tmp_token_path()
    cred.ensure_token(str(p))
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert stat.S_IMODE(p.parent.stat().st_mode) == 0o700


# 14: malformed / empty file is treated as missing and regenerated.
def test_malformed_or_empty_file_regenerates():
    for bad in ("", "   \n", "has space in it\n", DEV_TOKEN):
        p = _tmp_token_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(bad, encoding="utf-8")
        tok = cred.ensure_token(str(p))
        assert cred.is_valid_token(tok) and tok != DEV_TOKEN


# 12: concurrent ensure() calls converge on exactly one token (no duplicates).
def test_concurrent_ensure_is_consistent():
    p = _tmp_token_path()
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(lambda _: cred.ensure_token(str(p)), range(80)))
    assert len(set(results)) == 1, ("tokens diverged under concurrency", set(results))


# 15: an interrupted atomic write leaves no partial or temp file behind.
def test_interrupted_write_is_atomic(monkeypatch=None):
    p = _tmp_token_path()
    p.parent.mkdir(parents=True, exist_ok=True)

    def _boom(src, dst):
        raise OSError("simulated crash during replace")

    orig = os.replace
    os.replace = _boom
    try:
        raised = False
        try:
            cred.ensure_token(str(p))
        except OSError:
            raised = True
        assert raised, "atomic write should have surfaced the failure"
    finally:
        os.replace = orig
    assert not p.exists(), "a partial credential file was left behind"
    leftovers = [n for n in os.listdir(p.parent) if n.startswith(".rv-token-")]
    assert not leftovers, f"temp files left behind: {leftovers}"


# 10 + 20: the CLI never emits a credential in diagnostics/help/errors.
def test_cli_help_and_errors_have_no_credential():
    # help
    h = subprocess.run([sys.executable, MODULE, "--help"], capture_output=True, text=True)
    assert h.returncode == 0
    # unknown command -> usage on stderr, nothing on stdout
    u = subprocess.run([sys.executable, MODULE, "bogus"], capture_output=True, text=True)
    assert u.returncode == 2 and u.stdout == ""
    # a seeded token must never appear in help/usage text
    p = _tmp_token_path()
    tok = cred.ensure_token(str(p))
    assert tok not in h.stdout and tok not in h.stderr
    assert tok not in u.stdout and tok not in u.stderr


# 17: `ensure` prints ONLY the token (sole stdout line) for capture.
def test_cli_ensure_prints_only_token():
    p = _tmp_token_path()
    out = subprocess.run(
        [sys.executable, MODULE, "ensure", "--path", str(p)],
        capture_output=True, text=True, env=_clean_env(),
    )
    assert out.returncode == 0
    assert out.stdout == cred.read_token(p), "stdout is not exactly the token"
    assert "\n" not in out.stdout, "ensure emitted extra output"


# `read` is non-generating: exit 1 when absent, print when present, never create.
def test_cli_read_is_non_generating():
    p = _tmp_token_path()
    miss = subprocess.run(
        [sys.executable, MODULE, "read", "--path", str(p)],
        capture_output=True, text=True,
    )
    assert miss.returncode == 1 and miss.stdout == ""
    assert not p.exists(), "read must not create the credential file"
    tok = cred.ensure_token(str(p))
    hit = subprocess.run(
        [sys.executable, MODULE, "read", "--path", str(p)],
        capture_output=True, text=True,
    )
    assert hit.returncode == 0 and hit.stdout == tok


# `ensure` honours a provided env token and leaves the store untouched.
def test_cli_ensure_honours_env_token():
    p = _tmp_token_path()
    seeded = cred.ensure_token(str(p))
    env = dict(os.environ, REDVECTOR_API_TOKEN="env-supplied-strong-token-zzz999")
    out = subprocess.run(
        [sys.executable, MODULE, "ensure", "--path", str(p)],
        capture_output=True, text=True, env=env,
    )
    assert out.returncode == 0
    assert out.stdout == "env-supplied-strong-token-zzz999"
    assert cred.read_token(p) == seeded, "env token overwrote the persisted store"


def test_validity_rules():
    assert cred.is_valid_token("abcdef1234567890")
    for bad in ("", DEV_TOKEN, "   ", "with space", "tab\tx", 1234, None, "trail \n"):
        assert not cred.is_valid_token(bad), bad


def _main():
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

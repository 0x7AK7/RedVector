#!/usr/bin/env python3
"""RedVector secure API-credential lifecycle (shared by the launcher and the
Claude Desktop manager).

Responsibilities
  * Generate a cryptographically secure API token (``secrets.token_urlsafe``).
  * Persist it in a protected, user-local location OUTSIDE the Git repository,
    so the backend and the MCP client use the SAME token across restarts and
    reboots (the root cause of "Connection closed"/401 was an ephemeral,
    per-launch token that a detached backend no longer shared).
  * Never accept the revoked published development token ``redvector-dev-token``.
  * Preserve a valid, explicitly provided credential and never rotate it during
    ordinary startup.
  * Update the credential file atomically with restrictive permissions
    (file 0600, directory 0700) and guard against concurrent launcher/installer
    runs.

Security
  * No hard-coded default token exists.
  * The token value is only ever written to the protected credential file and
    printed as the SOLE stdout line of the ``ensure`` CLI (for capture by the
    launcher via command substitution). It is never written to logs, stderr,
    error messages or diagnostics.

CLI
  python3 redvector_credentials.py ensure         # prints the effective token
  python3 redvector_credentials.py path           # prints the credential path

``ensure`` reads ``REDVECTOR_API_TOKEN`` from the environment as an explicitly
provided credential; a valid value is returned unchanged (and never persisted,
leaving it under the user's control), the revoked development token is ignored,
and otherwise the persisted token is loaded or a new strong one is generated and
stored.
"""
from __future__ import annotations

import os
import secrets
import stat
import sys
import threading
from pathlib import Path
from typing import Optional

# The revoked published development credential and the empty string are never
# acceptable as a credential (CWE-798).
INSECURE_TOKENS = frozenset({"", "redvector-dev-token"})

# Newly generated tokens use 256 bits of entropy (~43 url-safe characters).
_TOKEN_NBYTES = 32

# Serialises ensure_token() within a single process; combined with an advisory
# file lock (POSIX) this protects concurrent launcher/installer operations.
_THREAD_LOCK = threading.Lock()


def is_valid_token(token: object) -> bool:
    """True if *token* is a usable credential: a non-empty string that is not
    the revoked development token and contains no surrounding/!embedded
    whitespace or newlines."""
    if not isinstance(token, str):
        return False
    if token != token.strip():
        return False
    if not token or token in INSECURE_TOKENS:
        return False
    if any(c.isspace() for c in token):
        return False
    return True


def generate_token() -> str:
    """Return a new cryptographically secure URL-safe token."""
    return secrets.token_urlsafe(_TOKEN_NBYTES)


def credentials_path(explicit: Optional[str] = None) -> Path:
    """Resolve the credential file path (user-local, outside the repository).

    Priority: *explicit* argument, then ``REDVECTOR_CREDENTIALS_FILE``, then a
    per-user config directory (``XDG_CONFIG_HOME`` / ``%LOCALAPPDATA%`` /
    ``~/.config``) under ``redvector/api_token``.
    """
    if explicit:
        return Path(explicit).expanduser()
    env = os.environ.get("REDVECTOR_CREDENTIALS_FILE")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME")
    if not base and os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    if not base:
        base = str(Path.home() / ".config")
    return Path(base) / "redvector" / "api_token"


def _protect_dir(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    try:  # best-effort on Windows, enforced on POSIX
        os.chmod(directory, stat.S_IRWXU)  # 0700
    except OSError:
        pass


def read_token(path: Path) -> Optional[str]:
    """Return the stored token if the file exists and holds a valid credential,
    else None. Any read/permission error yields None (treated as 'regenerate')."""
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    token = raw.strip()
    return token if is_valid_token(token) else None


def _atomic_write(path: Path, token: str) -> None:
    """Write *token* to *path* atomically with 0600 permissions, never leaving a
    partial or world-readable file."""
    _protect_dir(path.parent)
    fd, tmp = tempfile_mkstemp(path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(token + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except OSError:
            pass
        os.replace(tmp, path)
        tmp = None
    finally:
        if tmp is not None and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def tempfile_mkstemp(directory: Path):
    import tempfile

    return tempfile.mkstemp(prefix=".rv-token-", dir=str(directory))


class _FileLock:
    """Advisory lock: process-wide thread lock plus a POSIX ``flock`` across
    processes. A no-op beyond the thread lock where ``flock`` is unavailable
    (e.g. Windows); atomic ``os.replace`` still prevents corruption there."""

    def __init__(self, lock_path: Path):
        self._lock_path = lock_path
        self._fh = None

    def __enter__(self):
        _THREAD_LOCK.acquire()
        try:
            import fcntl  # POSIX only

            self._fh = open(self._lock_path, "w")
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
        except Exception:
            if self._fh is not None:
                try:
                    self._fh.close()
                except OSError:
                    pass
            self._fh = None
        return self

    def __exit__(self, *exc):
        try:
            if self._fh is not None:
                try:
                    import fcntl

                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
                finally:
                    self._fh.close()
        except Exception:
            pass
        finally:
            self._fh = None
            _THREAD_LOCK.release()
        return False


def ensure_token(path: Optional[str] = None, provided: Optional[str] = None) -> str:
    """Return the effective API token, generating and persisting one if needed.

    * A valid *provided* credential (e.g. ``REDVECTOR_API_TOKEN``) is returned
      unchanged and NOT persisted, leaving externally managed tokens under the
      user's control. The revoked development token is ignored (migrated away).
    * Otherwise a valid persisted token is reused (never rotated), or a new
      strong token is generated, stored atomically (0600), and returned.
    """
    if is_valid_token(provided):
        return provided.strip()  # type: ignore[union-attr]

    target = credentials_path(path)
    _protect_dir(target.parent)
    lock = target.parent / (target.name + ".lock")
    with _FileLock(lock):
        existing = read_token(target)
        if existing is not None:
            return existing
        token = generate_token()
        _atomic_write(target, token)
        return token


def _cli(argv) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        sys.stderr.write(
            "usage: redvector_credentials.py {ensure|read|path} [--path FILE]\n"
        )
        return 0 if argv and argv[0] in ("-h", "--help") else 2

    cmd = argv[0]
    explicit = None
    rest = argv[1:]
    if rest and rest[0] == "--path" and len(rest) >= 2:
        explicit = rest[1]

    if cmd == "path":
        sys.stdout.write(str(credentials_path(explicit)) + "\n")
        return 0

    if cmd == "read":
        # Non-generating: print the persisted token only if one already exists,
        # else exit non-zero WITHOUT creating or rotating anything. Used by the
        # manager's authenticated connection check.
        token = read_token(credentials_path(explicit))
        if token is None:
            return 1
        sys.stdout.write(token)
        return 0

    if cmd == "ensure":
        provided = os.environ.get("REDVECTOR_API_TOKEN")
        try:
            token = ensure_token(explicit, provided)
        except Exception:
            # Never echo the exception (it must not carry a credential).
            sys.stderr.write(
                "[RedVector] ERROR: unable to establish a secure API token.\n"
            )
            return 1
        if not is_valid_token(token):
            sys.stderr.write(
                "[RedVector] ERROR: refusing to emit an insecure API token.\n"
            )
            return 1
        sys.stdout.write(token)  # sole stdout output, for command substitution
        return 0

    sys.stderr.write(f"[RedVector] ERROR: unknown command {cmd!r}.\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))

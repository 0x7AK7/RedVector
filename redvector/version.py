"""Authoritative RedVector version source.

Every runtime version consumer (startup banner, health/status output, MCP client
banner, package metadata, launcher display) reads from here. Do not hard-code the
version anywhere else.
"""

PRODUCT_NAME = "RedVector"
__version__ = "8.0.0"
VERSION = __version__


def version_string() -> str:
    """Human-readable product identity, e.g. 'RedVector 8.0.0'."""
    return "%s %s" % (PRODUCT_NAME, __version__)


_BUILD_FINGERPRINT_CACHE = None


def build_fingerprint() -> str:
    """A content-based fingerprint of the installed RedVector package source
    (Phase 10.5 surgical fix, BUG 8). Used to detect a stale backend process that
    survived a code update: a running backend whose fingerprint differs from the
    current checkout is serving old code. Derived from the package's .py file names
    and bytes plus the version - NOT from git, so it works in packaged releases.
    Computed once per process and cached."""
    global _BUILD_FINGERPRINT_CACHE
    if _BUILD_FINGERPRINT_CACHE is not None:
        return _BUILD_FINGERPRINT_CACHE
    import hashlib
    import os
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    h = hashlib.sha256()
    h.update(__version__.encode("utf-8"))
    for root, dirs, files in os.walk(pkg_dir):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for fn in sorted(files):
            if not fn.endswith(".py"):
                continue
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, pkg_dir).replace("\\", "/")
            try:
                with open(path, "rb") as f:
                    data = f.read()
            except OSError:
                continue
            h.update(rel.encode("utf-8"))
            h.update(b"\0")
            h.update(data)
    _BUILD_FINGERPRINT_CACHE = h.hexdigest()[:16]
    return _BUILD_FINGERPRINT_CACHE

"""Evidence cache read layer for reviewed native tool compatibility (Phase 1: read-only).

Provides secure lookup into a root-owned evidence cache file that records verified native tool
compatibility evidence. This module ONLY reads evidence; writing is Phase 2. No side effects at
import time; no file reads at import time; safe to import on any platform.

Cache file schema (JSON):
  {
    "format_version": "1",
    "entries": {
      "<binary_sha256>": {
        "binary_sha256": "<hex>",
        "binding_key": "<hex>",
        "binding": { ... },
        "functional_tests_passed": true,
        "sandbox_tests_passed": true,
        "recorded_at": "<iso8601>",
        "recorded_by": "<str>",
        "notes": "<str>"
      }
    }
  }

Security model:
  - Cache file must be root-owned (uid=0), no group/other write, no symlinks in path chain.
  - User-owned cache files NEVER authorize native execution.
  - Entries are bound to the exact execution profile, parser, templates, and security policy
    in effect at verification time; any change invalidates cached evidence automatically.
  - lookup() performs triple-check: stored binding_key == expected, stored binding_key ==
    live-computed binding_key from stored binding dict, and both test flags are True.
"""
import hashlib
import json
import os
import stat
from pathlib import Path

EvidenceError = type("EvidenceError", (ValueError,), {})

CACHE_FORMAT_VERSION = "1"
_CACHE_MAX_BYTES = 1_048_576  # 1 MiB

AUTHORITATIVE_SYSTEM_PATHS = [
    "/var/lib/redvector/tool_evidence.json",
    "/etc/redvector/tool_evidence.json",
]

_REQUIRED_ENTRY_FIELDS = frozenset([
    "binary_sha256", "binding_key", "binding",
    "functional_tests_passed", "sandbox_tests_passed",
])


# ---------------------------------------------------------------------------
# Private path-safety helpers
# ---------------------------------------------------------------------------

def _no_symlink_in_chain(path: Path) -> bool:
    """Return True only when no component of path is a symlink.

    Never calls Path.resolve() (which follows symlinks). Checks each part
    of the absolute path independently using lstat.
    """
    try:
        parts = path.parts
        for i in range(1, len(parts) + 1):
            component = Path(*parts[:i])
            try:
                if component.is_symlink():
                    return False
            except OSError:
                return False
        return True
    except Exception:
        return False


def _trusted_cache(path: Path) -> bool:
    """Return True only when path is a safe, root-owned cache file.

    Checks: file exists, no symlink in chain, uid=0 and no group/other write
    on file AND every ancestor directory (matching the adapter _trusted() pattern),
    file size within limit. Never raises; returns False on any error.
    """
    try:
        if not path.is_absolute():
            return False
        if not _no_symlink_in_chain(path):
            return False
        if not path.is_file():
            return False
        # File and every ancestor: uid=0, no group/other write.
        # Consistent with _trusted() in reviewed adapters (searchsploit, nikto, profiles).
        # A world-writable parent directory lets non-root replace the file even when the
        # file itself is root-owned, so the ownership check must cover the full path chain.
        for component in (path, *path.parents):
            try:
                st = component.stat()
            except OSError:
                return False
            if st.st_uid != 0:
                return False
            if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return False
        if path.stat().st_size > _CACHE_MAX_BYTES:
            return False
        return True
    except Exception:
        return False


def _safe_absolute(raw: str) -> Path:
    """Return an absolute Path without following symlinks.

    Uses Path normalization of . and .. only; does not call resolve().
    """
    p = Path(raw)
    if not p.is_absolute():
        p = Path.cwd() / p
    # Normalize . and .. without following symlinks
    parts = []
    for part in p.parts:
        if part == "..":
            if parts and parts[-1] not in ("", "/", "\\"):
                parts.pop()
        elif part != ".":
            parts.append(part)
    if not parts:
        return Path("/")
    return Path(*parts) if len(parts) > 1 else Path(parts[0])


def _sha256_str(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Binding key computation
# ---------------------------------------------------------------------------

def compute_binding_key(obj) -> str:
    """Compute a stable SHA256 of the canonical JSON serialization of obj.

    Changes to any value or key name in obj produce a different key,
    automatically invalidating old cache entries.
    """
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return _sha256_str(canonical)


# ---------------------------------------------------------------------------
# Profile binding functions (lazy imports so module loads on Windows)
# ---------------------------------------------------------------------------

def nuclei_profile_binding() -> str:
    """Compute the live binding key for the Nuclei reviewed execution profile.

    Captures: fixed argv flags, env var keys (read live from _env() to stay
    current with the adapter), timeouts, output limits, template content,
    seccomp syscall numbers, and policy_version label.
    """
    import redvector_reviewed_assessment as ra  # noqa: PLC0415
    # Read the actual security env var names from _env() rather than hardcoding them.
    # _env() only builds a dict (no filesystem I/O); the probe path is never accessed.
    _sample_env = ra._env(Path("/nonexistent-rv-binding-probe"))
    security_env_keys = sorted(k for k in _sample_env if k.startswith("DISABLE_"))
    binding = {
        "profile": "nuclei-offline-header-v1",
        "policy_version": getattr(ra, "_POLICY_VERSION", "nuclei-offline-header-v1"),
        "limit": ra._LIMIT,
        "subprocess_timeout": 30,
        "env_keys": security_env_keys,
        "fixed_argv": [
            "-passive", "-ni", "-duc", "-dr", "-nh", "-no-stdin",
            "-jsonl", "-silent", "-nc", "-omit-raw",
            "-c", "1", "-bs", "1", "-timeout", "3", "-retries", "0",
        ],
        "no_network_syscalls": sorted([41, 42, 44, 46, 307]),
        "no_network_prctl": sorted([22, 38]),
    }
    # Capture template content so changes invalidate old entries
    try:
        sample_tpl = ra.template("redvector-binding-probe", "X-Probe: 1")
        binding["template_sample_hash"] = _sha256_str(sample_tpl)
    except Exception:
        pass
    return compute_binding_key(binding)


def nikto_profile_binding() -> str:
    """Compute the live binding key for the Nikto reviewed execution profile."""
    import redvector_reviewed_nikto as nk  # noqa: PLC0415
    binding = {
        "profile": "nikto-native-v1",
        "tuning": nk._TUNING,
        "maxtime": nk._MAXTIME,
        "deadline": nk._DEADLINE,
        "limit": nk._LIMIT,
    }
    return compute_binding_key(binding)


def nmap_discovery_binding() -> str:
    """Compute the live binding key for the Nmap discovery reviewed profile."""
    import redvector_reviewed_profiles as rp  # noqa: PLC0415
    binding = {
        "profile": "tcp-discovery-v1",
        "max_rate": rp._DISCOVERY_MAX_RATE,
        "host_timeout": rp._DISCOVERY_HOST_TIMEOUT,
        "deadline": rp._DISCOVERY_DEADLINE,
        "max_ports": rp.MAX_DISCOVERY_PORTS,
    }
    return compute_binding_key(binding)


def searchsploit_profile_binding() -> str:
    """Compute the live binding key for the Searchsploit reviewed profile."""
    import redvector_reviewed_searchsploit as ss  # noqa: PLC0415
    binding = {
        "profile": "searchsploit-v1",
        "deadline": ss._DEADLINE,
        "limit": ss._LIMIT,
        "required_flags": ["--json", "--disable-colour"],
    }
    return compute_binding_key(binding)


# ---------------------------------------------------------------------------
# Cache discovery and loading
# ---------------------------------------------------------------------------

def find_authoritative_cache() -> "Path | None":
    """Return the path of the authoritative evidence cache, or None.

    Checks REDVECTOR_EVIDENCE_PATH env var first, then system paths in order.
    All candidates must pass _trusted_cache() to be returned.
    """
    env_path = os.environ.get("REDVECTOR_EVIDENCE_PATH", "").strip()
    if env_path:
        p = _safe_absolute(env_path)
        if _trusted_cache(p):
            return p
        return None  # env var set but untrusted: do not fall through to system paths

    for raw in AUTHORITATIVE_SYSTEM_PATHS:
        p = Path(raw)
        if _trusted_cache(p):
            return p
    return None


def load_cache(path=None) -> dict:
    """Load and parse the evidence cache. Returns {} on any error; never raises.

    If path is None, calls find_authoritative_cache(). Returns the dict of
    entries keyed by binary_sha256, or {} if the file is missing, untrusted,
    malformed, wrong version, or otherwise unusable.
    """
    try:
        if path is None:
            path = find_authoritative_cache()
        if path is None:
            return {}
        if not _trusted_cache(path):
            return {}
        raw = path.read_bytes()
        if len(raw) > _CACHE_MAX_BYTES:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}
        if not isinstance(data, dict):
            return {}
        if data.get("format_version") != CACHE_FORMAT_VERSION:
            return {}
        entries = data.get("entries")
        if not isinstance(entries, dict):
            return {}
        return entries
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Entry validation and lookup
# ---------------------------------------------------------------------------

def validate_entry(entry) -> bool:
    """Return True only when entry has all required fields and test flags are True."""
    if not isinstance(entry, dict):
        return False
    if not _REQUIRED_ENTRY_FIELDS.issubset(entry.keys()):
        return False
    if entry.get("functional_tests_passed") is not True:
        return False
    if entry.get("sandbox_tests_passed") is not True:
        return False
    return True


def lookup(cache_data, binary_sha256: str, expected_binding_key: str) -> "dict | None":
    """Look up a verified evidence entry for the given binary and binding.

    Performs a triple check:
      1. The stored binding_key matches expected_binding_key (caller's live value).
      2. The stored binding_key matches compute_binding_key(entry["binding"])
         (self-consistency: no silent tampering of the binding dict).
      3. Both functional_tests_passed and sandbox_tests_passed are True.

    Returns the entry dict on a hit, None on any miss. Never raises.
    """
    try:
        if not isinstance(cache_data, dict) or not cache_data:
            return None
        if not binary_sha256 or not expected_binding_key:
            return None
        entry = cache_data.get(binary_sha256)
        if entry is None:
            return None
        if not validate_entry(entry):
            return None
        stored_binding_key = entry.get("binding_key", "")
        # Check 1: stored key must match the caller's live-computed expected key
        if stored_binding_key != expected_binding_key:
            return None
        # Check 2: stored key must be self-consistent with the stored binding dict
        live_key = compute_binding_key(entry.get("binding", {}))
        if stored_binding_key != live_key:
            return None
        return entry
    except Exception:
        return None

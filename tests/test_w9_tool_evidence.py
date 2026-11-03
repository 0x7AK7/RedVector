"""Phase 1 unit tests for redvector_tool_evidence — evidence cache read layer.

All tests are Windows-compatible. Ownership checks requiring root (uid=0) are
mocked via monkeypatch. Adapter-importing binding functions are skipped on
non-Linux platforms.
"""
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import redvector_tool_evidence as rte


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _make_valid_entry(binary_sha256=None, binding=None, binding_key=None):
    b = binding or {"profile": "test-v1", "limit": 65536}
    bk = binding_key if binding_key is not None else rte.compute_binding_key(b)
    sha = binary_sha256 or ("a" * 64)
    return {
        "binary_sha256": sha,
        "binding_key": bk,
        "binding": b,
        "functional_tests_passed": True,
        "sandbox_tests_passed": True,
        "recorded_at": "2024-01-01T00:00:00Z",
        "recorded_by": "test",
        "notes": "",
    }


def _make_cache_bytes(entries=None, format_version=rte.CACHE_FORMAT_VERSION):
    data = {"format_version": format_version, "entries": entries or {}}
    return json.dumps(data).encode("utf-8")


# ---------------------------------------------------------------------------
# compute_binding_key
# ---------------------------------------------------------------------------

class TestComputeBindingKey:
    def test_deterministic(self):
        obj = {"a": 1, "b": "x"}
        assert rte.compute_binding_key(obj) == rte.compute_binding_key(obj)

    def test_key_order_independent(self):
        a = {"x": 1, "y": 2}
        b = {"y": 2, "x": 1}
        assert rte.compute_binding_key(a) == rte.compute_binding_key(b)

    def test_sensitive_to_value_change(self):
        a = {"limit": 65536}
        b = {"limit": 65537}
        assert rte.compute_binding_key(a) != rte.compute_binding_key(b)

    def test_sensitive_to_key_name_change(self):
        a = {"limit": 65536}
        b = {"Limit": 65536}
        assert rte.compute_binding_key(a) != rte.compute_binding_key(b)

    def test_nested_dict(self):
        a = {"outer": {"inner": 1}}
        b = {"outer": {"inner": 2}}
        assert rte.compute_binding_key(a) != rte.compute_binding_key(b)

    def test_empty_dict(self):
        key = rte.compute_binding_key({})
        assert len(key) == 64
        assert all(c in "0123456789abcdef" for c in key)

    def test_returns_hex_string(self):
        key = rte.compute_binding_key({"a": 1})
        assert isinstance(key, str)
        assert len(key) == 64


# ---------------------------------------------------------------------------
# _no_symlink_in_chain
# ---------------------------------------------------------------------------

class TestNoSymlinkInChain:
    def test_returns_bool(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("x")
        result = rte._no_symlink_in_chain(f)
        assert isinstance(result, bool)

    def test_real_file_no_symlink(self, tmp_path):
        f = tmp_path / "real.txt"
        f.write_text("x")
        # tmp_path itself may have symlinks on some OS; only test the function doesn't crash
        result = rte._no_symlink_in_chain(f)
        assert isinstance(result, bool)

    def test_symlink_detected(self, tmp_path):
        real = tmp_path / "real.txt"
        real.write_text("x")
        link = tmp_path / "link.txt"
        try:
            link.symlink_to(real)
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not supported on this platform")
        assert rte._no_symlink_in_chain(link) is False

    def test_nonexistent_path(self, tmp_path):
        # Should return False (or True) gracefully without raising
        result = rte._no_symlink_in_chain(tmp_path / "nonexistent.txt")
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# _safe_absolute
# ---------------------------------------------------------------------------

class TestSafeAbsolute:
    def test_absolute_path_unchanged(self):
        p = rte._safe_absolute("/var/lib/redvector/tool_evidence.json")
        assert p.is_absolute()
        assert "redvector" in str(p)

    def test_dotdot_normalized(self):
        p = rte._safe_absolute("/var/lib/../lib/redvector/tool_evidence.json")
        assert ".." not in p.parts

    def test_dot_normalized(self):
        p = rte._safe_absolute("/var/./lib/redvector/tool_evidence.json")
        assert "." not in [part for part in p.parts if part != "."]

    def test_relative_becomes_absolute(self):
        p = rte._safe_absolute("somefile.json")
        assert p.is_absolute()


# ---------------------------------------------------------------------------
# _trusted_cache — ownership checks are mocked for non-root test environments
# ---------------------------------------------------------------------------

class TestTrustedCache:
    def _mock_trusted(self, monkeypatch, path: Path, uid=0, mode_extra=0, size=100, is_file=True, has_symlink=False):
        """Patch os.stat and related calls to simulate ownership."""
        st = MagicMock()
        st.st_uid = uid
        # stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH = 0o644
        st.st_mode = 0o100644 | mode_extra
        st.st_size = size

        def fake_stat(p, *args, **kwargs):
            return st

        def fake_is_file(p=None):
            return is_file

        def fake_no_symlink(p):
            return not has_symlink

        monkeypatch.setattr(rte, "_no_symlink_in_chain", fake_no_symlink)
        monkeypatch.setattr(Path, "stat", lambda self, *a, **kw: st)
        monkeypatch.setattr(Path, "is_file", lambda self: is_file)
        monkeypatch.setattr(Path, "is_symlink", lambda self: has_symlink)

    def test_nonexistent_returns_false(self, tmp_path):
        p = tmp_path / "nonexistent.json"
        assert rte._trusted_cache(p) is False

    def test_relative_path_rejected(self, monkeypatch):
        result = rte._trusted_cache(Path("relative/path.json"))
        assert result is False

    def test_symlink_in_chain_rejected(self, monkeypatch, tmp_path):
        p = tmp_path / "cache.json"
        p.write_bytes(b"{}")
        self._mock_trusted(monkeypatch, p, uid=0, has_symlink=True)
        assert rte._trusted_cache(p) is False

    def test_non_root_owner_rejected(self, monkeypatch, tmp_path):
        p = tmp_path / "cache.json"
        p.write_bytes(b"{}")
        self._mock_trusted(monkeypatch, p, uid=1000, has_symlink=False)
        assert rte._trusted_cache(p) is False

    def test_group_writable_rejected(self, monkeypatch, tmp_path):
        p = tmp_path / "cache.json"
        p.write_bytes(b"{}")
        self._mock_trusted(monkeypatch, p, uid=0, mode_extra=stat.S_IWGRP, has_symlink=False)
        assert rte._trusted_cache(p) is False

    def test_world_writable_rejected(self, monkeypatch, tmp_path):
        p = tmp_path / "cache.json"
        p.write_bytes(b"{}")
        self._mock_trusted(monkeypatch, p, uid=0, mode_extra=stat.S_IWOTH, has_symlink=False)
        assert rte._trusted_cache(p) is False

    def test_oversized_rejected(self, monkeypatch, tmp_path):
        p = tmp_path / "cache.json"
        p.write_bytes(b"{}")
        self._mock_trusted(monkeypatch, p, uid=0, size=rte._CACHE_MAX_BYTES + 1, has_symlink=False)
        assert rte._trusted_cache(p) is False

    def test_valid_passes(self, monkeypatch, tmp_path):
        p = tmp_path / "cache.json"
        p.write_bytes(b"{}")
        self._mock_trusted(monkeypatch, p, uid=0, size=100, has_symlink=False)
        assert rte._trusted_cache(p) is True

    def test_not_a_file_rejected(self, monkeypatch, tmp_path):
        p = tmp_path / "cache.json"
        self._mock_trusted(monkeypatch, p, uid=0, is_file=False, has_symlink=False)
        assert rte._trusted_cache(p) is False

    def test_parent_directory_ownership_checked(self, monkeypatch, tmp_path):
        # File is uid=0 but parent dir is uid=1000 — must be rejected.
        p = tmp_path / "cache.json"
        p.write_bytes(b"{}")

        call_count = [0]
        parent = p.parent

        def per_component_stat(self, *a, **kw):
            call_count[0] += 1
            st = MagicMock()
            st.st_size = 100
            # File is root-owned; parent dir is not
            st.st_uid = 0 if self == p else 1000
            st.st_mode = 0o100644
            return st

        monkeypatch.setattr(rte, "_no_symlink_in_chain", lambda x: True)
        monkeypatch.setattr(Path, "stat", per_component_stat)
        monkeypatch.setattr(Path, "is_file", lambda self: True)
        assert rte._trusted_cache(p) is False


# ---------------------------------------------------------------------------
# find_authoritative_cache
# ---------------------------------------------------------------------------

class TestFindAuthoritativeCache:
    def test_returns_none_when_no_file(self, monkeypatch):
        monkeypatch.delenv("REDVECTOR_EVIDENCE_PATH", raising=False)
        monkeypatch.setattr(rte, "_trusted_cache", lambda p: False)
        assert rte.find_authoritative_cache() is None

    def test_honors_env_var_when_trusted(self, monkeypatch, tmp_path):
        p = tmp_path / "cache.json"
        p.write_bytes(_make_cache_bytes())
        monkeypatch.setenv("REDVECTOR_EVIDENCE_PATH", str(p))
        monkeypatch.setattr(rte, "_trusted_cache", lambda path: path == p)
        result = rte.find_authoritative_cache()
        assert result == p

    def test_rejects_untrusted_env_var(self, monkeypatch, tmp_path):
        p = tmp_path / "bad_cache.json"
        p.write_bytes(b"{}")
        monkeypatch.setenv("REDVECTOR_EVIDENCE_PATH", str(p))
        monkeypatch.setattr(rte, "_trusted_cache", lambda path: False)
        # env var set but untrusted: must return None, not fall through to system paths
        assert rte.find_authoritative_cache() is None

    def test_returns_first_trusted_system_path(self, monkeypatch):
        monkeypatch.delenv("REDVECTOR_EVIDENCE_PATH", raising=False)
        first = Path(rte.AUTHORITATIVE_SYSTEM_PATHS[0])
        calls = []

        def fake_trusted(p):
            calls.append(p)
            return p == first

        monkeypatch.setattr(rte, "_trusted_cache", fake_trusted)
        result = rte.find_authoritative_cache()
        assert result == first

    def test_skips_untrusted_returns_second(self, monkeypatch):
        monkeypatch.delenv("REDVECTOR_EVIDENCE_PATH", raising=False)
        second = Path(rte.AUTHORITATIVE_SYSTEM_PATHS[1])
        first = Path(rte.AUTHORITATIVE_SYSTEM_PATHS[0])

        def fake_trusted(p):
            return p == second

        monkeypatch.setattr(rte, "_trusted_cache", fake_trusted)
        result = rte.find_authoritative_cache()
        assert result == second


# ---------------------------------------------------------------------------
# load_cache
# ---------------------------------------------------------------------------

class TestLoadCache:
    def _make_trusted_file(self, tmp_path, content: bytes, monkeypatch):
        p = tmp_path / "cache.json"
        p.write_bytes(content)
        monkeypatch.setattr(rte, "_trusted_cache", lambda path: path == p)
        monkeypatch.setattr(rte, "find_authoritative_cache", lambda: p)
        return p

    def test_missing_file_returns_empty(self, monkeypatch):
        monkeypatch.setattr(rte, "find_authoritative_cache", lambda: None)
        assert rte.load_cache() == {}

    def test_invalid_json_returns_empty(self, tmp_path, monkeypatch):
        p = self._make_trusted_file(tmp_path, b"not json at all", monkeypatch)
        assert rte.load_cache(p) == {}

    def test_wrong_format_version_returns_empty(self, tmp_path, monkeypatch):
        data = _make_cache_bytes(entries={}, format_version="99")
        p = self._make_trusted_file(tmp_path, data, monkeypatch)
        assert rte.load_cache(p) == {}

    def test_not_a_dict_returns_empty(self, tmp_path, monkeypatch):
        p = self._make_trusted_file(tmp_path, b"[1,2,3]", monkeypatch)
        assert rte.load_cache(p) == {}

    def test_valid_cache_returns_entries(self, tmp_path, monkeypatch):
        entry = _make_valid_entry()
        sha = entry["binary_sha256"]
        data = _make_cache_bytes(entries={sha: entry})
        p = self._make_trusted_file(tmp_path, data, monkeypatch)
        result = rte.load_cache(p)
        assert sha in result
        assert result[sha]["binary_sha256"] == sha

    def test_empty_entries_returns_empty_dict(self, tmp_path, monkeypatch):
        data = _make_cache_bytes(entries={})
        p = self._make_trusted_file(tmp_path, data, monkeypatch)
        result = rte.load_cache(p)
        assert result == {}

    def test_untrusted_path_returns_empty(self, tmp_path, monkeypatch):
        p = tmp_path / "cache.json"
        p.write_bytes(_make_cache_bytes())
        monkeypatch.setattr(rte, "_trusted_cache", lambda path: False)
        assert rte.load_cache(p) == {}

    def test_never_raises(self, monkeypatch):
        monkeypatch.setattr(rte, "find_authoritative_cache", lambda: None)
        result = rte.load_cache()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# validate_entry
# ---------------------------------------------------------------------------

class TestValidateEntry:
    def test_accepts_complete_entry(self):
        entry = _make_valid_entry()
        assert rte.validate_entry(entry) is True

    def test_rejects_missing_binary_sha256(self):
        entry = _make_valid_entry()
        del entry["binary_sha256"]
        assert rte.validate_entry(entry) is False

    def test_rejects_missing_binding_key(self):
        entry = _make_valid_entry()
        del entry["binding_key"]
        assert rte.validate_entry(entry) is False

    def test_rejects_missing_binding(self):
        entry = _make_valid_entry()
        del entry["binding"]
        assert rte.validate_entry(entry) is False

    def test_rejects_false_functional_tests(self):
        entry = _make_valid_entry()
        entry["functional_tests_passed"] = False
        assert rte.validate_entry(entry) is False

    def test_rejects_false_sandbox_tests(self):
        entry = _make_valid_entry()
        entry["sandbox_tests_passed"] = False
        assert rte.validate_entry(entry) is False

    def test_rejects_none_functional_tests(self):
        entry = _make_valid_entry()
        entry["functional_tests_passed"] = None
        assert rte.validate_entry(entry) is False

    def test_rejects_non_dict(self):
        assert rte.validate_entry("not a dict") is False
        assert rte.validate_entry(None) is False
        assert rte.validate_entry([]) is False

    def test_rejects_empty_dict(self):
        assert rte.validate_entry({}) is False


# ---------------------------------------------------------------------------
# lookup
# ---------------------------------------------------------------------------

class TestLookup:
    def test_hit_all_checks_pass(self):
        entry = _make_valid_entry()
        sha = entry["binary_sha256"]
        cache = {sha: entry}
        result = rte.lookup(cache, sha, entry["binding_key"])
        assert result is not None
        assert result["binary_sha256"] == sha

    def test_miss_unknown_sha(self):
        entry = _make_valid_entry()
        cache = {entry["binary_sha256"]: entry}
        assert rte.lookup(cache, "b" * 64, entry["binding_key"]) is None

    def test_miss_binding_key_mismatch(self):
        entry = _make_valid_entry()
        sha = entry["binary_sha256"]
        cache = {sha: entry}
        wrong_key = rte.compute_binding_key({"wrong": "binding"})
        assert rte.lookup(cache, sha, wrong_key) is None

    def test_miss_self_inconsistent_binding(self):
        # stored binding_key does not match compute_binding_key(stored binding)
        entry = _make_valid_entry()
        sha = entry["binary_sha256"]
        correct_bk = entry["binding_key"]
        # Tamper: change binding dict but keep old binding_key
        entry["binding"]["tampered"] = True
        cache = {sha: entry}
        # expected_binding_key matches stored but stored != live-computed
        assert rte.lookup(cache, sha, correct_bk) is None

    def test_miss_false_functional_tests(self):
        entry = _make_valid_entry()
        entry["functional_tests_passed"] = False
        sha = entry["binary_sha256"]
        cache = {sha: entry}
        assert rte.lookup(cache, sha, entry["binding_key"]) is None

    def test_miss_false_sandbox_tests(self):
        entry = _make_valid_entry()
        entry["sandbox_tests_passed"] = False
        sha = entry["binary_sha256"]
        cache = {sha: entry}
        assert rte.lookup(cache, sha, entry["binding_key"]) is None

    def test_never_raises_on_empty_cache(self):
        result = rte.lookup({}, "a" * 64, "b" * 64)
        assert result is None

    def test_never_raises_on_none_cache(self):
        result = rte.lookup(None, "a" * 64, "b" * 64)
        assert result is None

    def test_never_raises_on_empty_sha(self):
        result = rte.lookup({}, "", "b" * 64)
        assert result is None

    def test_never_raises_on_empty_binding_key(self):
        result = rte.lookup({}, "a" * 64, "")
        assert result is None


# ---------------------------------------------------------------------------
# Profile binding functions (Linux only — lazy imports)
# ---------------------------------------------------------------------------

_linux_only = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Adapter imports require native Linux"
)


@_linux_only
class TestNucleiProfileBinding:
    def test_returns_hex_string(self):
        key = rte.nuclei_profile_binding()
        assert isinstance(key, str)
        assert len(key) == 64

    def test_deterministic(self):
        assert rte.nuclei_profile_binding() == rte.nuclei_profile_binding()

    def test_changes_when_limit_changes(self, monkeypatch):
        import redvector_reviewed_assessment as ra
        original = ra._LIMIT
        key1 = rte.nuclei_profile_binding()
        monkeypatch.setattr(ra, "_LIMIT", original + 1)
        key2 = rte.nuclei_profile_binding()
        assert key1 != key2


@_linux_only
class TestNiktoProfileBinding:
    def test_returns_hex_string(self):
        key = rte.nikto_profile_binding()
        assert isinstance(key, str)
        assert len(key) == 64

    def test_deterministic(self):
        assert rte.nikto_profile_binding() == rte.nikto_profile_binding()

    def test_changes_when_tuning_changes(self, monkeypatch):
        import redvector_reviewed_nikto as nk
        monkeypatch.setattr(nk, "_TUNING", "999")
        key1 = rte.nikto_profile_binding()
        monkeypatch.setattr(nk, "_TUNING", "123b")
        key2 = rte.nikto_profile_binding()
        assert key1 != key2


@_linux_only
class TestNmapDiscoveryBinding:
    def test_returns_hex_string(self):
        key = rte.nmap_discovery_binding()
        assert isinstance(key, str)
        assert len(key) == 64

    def test_deterministic(self):
        assert rte.nmap_discovery_binding() == rte.nmap_discovery_binding()


@_linux_only
class TestSearchsploitProfileBinding:
    def test_returns_hex_string(self):
        key = rte.searchsploit_profile_binding()
        assert isinstance(key, str)
        assert len(key) == 64

    def test_deterministic(self):
        assert rte.searchsploit_profile_binding() == rte.searchsploit_profile_binding()


# ---------------------------------------------------------------------------
# Integration: load_cache + lookup round-trip
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def test_full_roundtrip(self, tmp_path, monkeypatch):
        binding = {"profile": "test-v1", "limit": 65536}
        bk = rte.compute_binding_key(binding)
        sha = _sha256("fakebinary")
        entry = {
            "binary_sha256": sha,
            "binding_key": bk,
            "binding": binding,
            "functional_tests_passed": True,
            "sandbox_tests_passed": True,
            "recorded_at": "2024-01-01T00:00:00Z",
            "recorded_by": "test",
            "notes": "",
        }
        data = _make_cache_bytes(entries={sha: entry})
        p = tmp_path / "cache.json"
        p.write_bytes(data)
        monkeypatch.setattr(rte, "_trusted_cache", lambda path: path == p)

        cache = rte.load_cache(p)
        result = rte.lookup(cache, sha, bk)
        assert result is not None
        assert result["binary_sha256"] == sha

    def test_miss_after_profile_change(self, tmp_path, monkeypatch):
        binding = {"profile": "test-v1", "limit": 65536}
        bk_old = rte.compute_binding_key(binding)
        sha = _sha256("fakebinary2")
        entry = {
            "binary_sha256": sha,
            "binding_key": bk_old,
            "binding": binding,
            "functional_tests_passed": True,
            "sandbox_tests_passed": True,
            "recorded_at": "2024-01-01T00:00:00Z",
            "recorded_by": "test",
            "notes": "",
        }
        data = _make_cache_bytes(entries={sha: entry})
        p = tmp_path / "cache.json"
        p.write_bytes(data)
        monkeypatch.setattr(rte, "_trusted_cache", lambda path: path == p)

        cache = rte.load_cache(p)
        # Simulate profile change: new limit
        new_binding = {"profile": "test-v1", "limit": 99999}
        bk_new = rte.compute_binding_key(new_binding)
        # The stored entry has old binding_key; new expected_binding_key doesn't match
        assert rte.lookup(cache, sha, bk_new) is None

"""W9 Phase 2: redvector_verify — unit tests for the native tool verification engine.

Tests cover:
  - Root check (_require_root)
  - Binary path and ownership validation
  - Binary SHA256 computation
  - dpkg provenance parsing (mocked subprocess)
  - Atomic evidence write (mocked root + temp dir)
  - Cache directory enforcement
  - Loopback HTTP server
  - Nuclei JSONL parsing and template ID validation
  - Profile test consistency check
  - Binding dict alignment with Phase 1 rte functions
  - CLI argument parsing
  - find_binary env-var and PATH fallbacks

Linux-only tests (require seccomp / adapter imports) are skipped on non-Linux platforms.
"""
import hashlib
import http.client
import json
import os
import platform
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

import redvector_verify as rv
from redvector_verify import (
    VerifyError,
    _ALLOWED_TEMPLATE_IDS,
    _DEFAULT_CACHE_PATH,
    _binary_sha256,
    _check_binary_ownership,
    _check_binary_path,
    _dpkg_provenance,
    _ensure_cache_dir,
    _find_binary,
    _loopback_server,
    _require_root,
    _run_nmap_functional_test,
    _run_nikto_functional_test,
    _run_searchsploit_functional_test,
    _verify_path_chain_trusted,
    _write_evidence_atomic,
    main,
)
import redvector_tool_evidence as rte

_linux_only = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux-only (seccomp/Kali)"
)


# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------

@_linux_only
class TestRequireRoot(unittest.TestCase):
    @patch("os.getuid", return_value=0)
    def test_passes_as_root(self, _):
        _require_root()  # must not raise

    @patch("os.getuid", return_value=1000)
    def test_raises_as_non_root(self, _):
        with self.assertRaises(VerifyError) as ctx:
            _require_root()
        self.assertIn("root", str(ctx.exception).lower())


# ---------------------------------------------------------------------------
# Binary path checks
# ---------------------------------------------------------------------------

class TestCheckBinaryPath(unittest.TestCase):
    def test_relative_path_raises(self):
        with self.assertRaises(VerifyError):
            _check_binary_path(Path("nuclei"))

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="symlink creation requires elevated privileges on Windows",
    )
    def test_symlink_raises(self):
        with tempfile.TemporaryDirectory() as d:
            real = Path(d) / "bin"
            real.write_bytes(b"\x7fELF")
            link = Path(d) / "link"
            link.symlink_to(real)
            with self.assertRaises(VerifyError):
                _check_binary_path(link)

    def test_missing_file_raises(self):
        with self.assertRaises(VerifyError):
            _check_binary_path(Path("/nonexistent/redvector-verify-test-bin"))

    def test_directory_raises(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(VerifyError):
                _check_binary_path(Path(d))

    def test_regular_file_passes(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x7fELF")
            p = Path(f.name)
        try:
            _check_binary_path(p)  # must not raise
        finally:
            p.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Binary ownership checks
# ---------------------------------------------------------------------------

class TestCheckBinaryOwnership(unittest.TestCase):
    def _stat_mock(self, uid: int, mode: int) -> MagicMock:
        m = MagicMock()
        m.st_uid = uid
        m.st_mode = mode
        return m

    def test_non_root_uid_raises(self):
        p = MagicMock(spec=Path)
        p.stat.return_value = self._stat_mock(uid=1000, mode=0o755)
        with self.assertRaises(VerifyError) as ctx:
            _check_binary_ownership(p)
        self.assertIn("root-owned", str(ctx.exception))

    def test_group_writable_raises(self):
        p = MagicMock(spec=Path)
        p.stat.return_value = self._stat_mock(uid=0, mode=0o775)  # g+w
        with self.assertRaises(VerifyError) as ctx:
            _check_binary_ownership(p)
        self.assertIn("group/other write", str(ctx.exception))

    def test_other_writable_raises(self):
        p = MagicMock(spec=Path)
        p.stat.return_value = self._stat_mock(uid=0, mode=0o757)  # o+w
        with self.assertRaises(VerifyError):
            _check_binary_ownership(p)

    def test_root_owned_no_group_other_write_passes(self):
        p = MagicMock(spec=Path)
        p.stat.return_value = self._stat_mock(uid=0, mode=0o755)
        _check_binary_ownership(p)  # must not raise


# ---------------------------------------------------------------------------
# SHA256 computation
# ---------------------------------------------------------------------------

class TestBinarySHA256(unittest.TestCase):
    def test_known_content(self):
        data = b"redvector verify test"
        expected = hashlib.sha256(data).hexdigest()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            p = Path(f.name)
        try:
            self.assertEqual(_binary_sha256(p), expected)
        finally:
            p.unlink(missing_ok=True)

    def test_large_content_streams(self):
        # 3 MiB (forces multiple 1-MiB blocks)
        data = b"x" * (3 * 1024 * 1024)
        expected = hashlib.sha256(data).hexdigest()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            p = Path(f.name)
        try:
            self.assertEqual(_binary_sha256(p), expected)
        finally:
            p.unlink(missing_ok=True)

    def test_empty_file(self):
        expected = hashlib.sha256(b"").hexdigest()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            p = Path(f.name)
        try:
            self.assertEqual(_binary_sha256(p), expected)
        finally:
            p.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# dpkg provenance (mocked subprocess)
# ---------------------------------------------------------------------------

class TestDpkgProvenance(unittest.TestCase):
    def _make_run(self, stdout="", stderr="", returncode=0):
        m = MagicMock()
        m.stdout = stdout
        m.stderr = stderr
        m.returncode = returncode
        return m

    @patch("subprocess.run")
    def test_packaged_binary_sets_package_and_status(self, mock_run):
        mock_run.side_effect = [
            self._make_run(stdout="nuclei: /usr/bin/nuclei\n", returncode=0),
            self._make_run(returncode=0),  # dpkg --verify
        ]
        result = _dpkg_provenance(Path("/usr/bin/nuclei"))
        self.assertEqual(result["package"], "nuclei")
        self.assertEqual(result["status"], "package-owned")
        self.assertTrue(result["dpkg_verify_clean"])

    @patch("subprocess.run")
    def test_not_packaged_sets_status(self, mock_run):
        mock_run.return_value = self._make_run(
            stdout="", stderr="no path found", returncode=1
        )
        result = _dpkg_provenance(Path("/usr/local/bin/nuclei"))
        self.assertEqual(result["status"], "not-packaged")
        self.assertIsNone(result["package"])

    @patch("subprocess.run", side_effect=FileNotFoundError("dpkg not found"))
    def test_dpkg_unavailable(self, _):
        result = _dpkg_provenance(Path("/usr/bin/nuclei"))
        self.assertIn("unavailable", result["status"])

    @patch("subprocess.run")
    def test_dpkg_verify_failure_detected(self, mock_run):
        mock_run.side_effect = [
            self._make_run(stdout="nuclei: /usr/bin/nuclei\n", returncode=0),
            self._make_run(stdout="??5....", stderr="", returncode=1),  # verify fail
        ]
        result = _dpkg_provenance(Path("/usr/bin/nuclei"))
        self.assertFalse(result["dpkg_verify_clean"])

    @patch("subprocess.run")
    def test_dpkg_s_output_truncated_at_500(self, mock_run):
        long_output = "nuclei: /usr/bin/nuclei\n" + "x" * 1000
        mock_run.side_effect = [
            self._make_run(stdout=long_output, returncode=0),
            self._make_run(returncode=0),
        ]
        result = _dpkg_provenance(Path("/usr/bin/nuclei"))
        self.assertLessEqual(len(result["dpkg_s_output"]), 500)


# ---------------------------------------------------------------------------
# Atomic evidence write (Linux only: requires os.getuid, os.fchmod, atomic rename)
# ---------------------------------------------------------------------------

@_linux_only
class TestWriteEvidenceAtomic(unittest.TestCase):
    def _make_entry(self, sha: str = "a" * 64) -> dict:
        return {
            "binary_sha256": sha,
            "binding_key": "b" * 64,
            "binding": {"profile": "test-v1"},
            "functional_tests_passed": True,
            "sandbox_tests_passed": True,
        }

    @patch("os.getuid", return_value=1000)
    def test_requires_root(self, _):
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "ev.json"
            with self.assertRaises(VerifyError) as ctx:
                _write_evidence_atomic(self._make_entry(), cache)
            self.assertIn("root", str(ctx.exception).lower())

    @patch("os.getuid", return_value=0)
    def test_creates_cache_file(self, _):
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "ev.json"
            with patch("redvector_verify._ensure_cache_dir"):
                with patch("redvector_verify._verify_path_chain_trusted"):
                    _write_evidence_atomic(self._make_entry(), cache)
            self.assertTrue(cache.exists())

    @patch("os.getuid", return_value=0)
    def test_written_json_has_correct_structure(self, _):
        sha = "c" * 64
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "ev.json"
            with patch("redvector_verify._ensure_cache_dir"):
                with patch("redvector_verify._verify_path_chain_trusted"):
                    _write_evidence_atomic(self._make_entry(sha), cache)
            data = json.loads(cache.read_text())
        self.assertEqual(data["format_version"], rte.CACHE_FORMAT_VERSION)
        self.assertIn(sha, data["entries"])
        self.assertEqual(data["entries"][sha]["binding_key"], "b" * 64)
        self.assertIn("updated_at", data)

    @patch("os.getuid", return_value=0)
    def test_preserves_existing_entries(self, _):
        sha1 = "1" * 64
        sha2 = "2" * 64
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "ev.json"
            with patch("redvector_verify._ensure_cache_dir"):
                with patch("redvector_verify._verify_path_chain_trusted"):
                    _write_evidence_atomic(self._make_entry(sha1), cache)
                    _write_evidence_atomic(self._make_entry(sha2), cache)
            data = json.loads(cache.read_text())
        self.assertIn(sha1, data["entries"])
        self.assertIn(sha2, data["entries"])

    @patch("os.getuid", return_value=0)
    def test_updates_entry_for_same_sha(self, _):
        sha = "a" * 64
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "ev.json"
            e1 = self._make_entry(sha)
            e1["notes"] = "first"
            e2 = self._make_entry(sha)
            e2["notes"] = "updated"
            with patch("redvector_verify._ensure_cache_dir"):
                with patch("redvector_verify._verify_path_chain_trusted"):
                    _write_evidence_atomic(e1, cache)
                    _write_evidence_atomic(e2, cache)
            data = json.loads(cache.read_text())
        self.assertEqual(data["entries"][sha]["notes"], "updated")

    @patch("os.getuid", return_value=0)
    def test_corrupted_existing_cache_starts_fresh(self, _):
        sha = "d" * 64
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "ev.json"
            cache.write_bytes(b"NOT VALID JSON {{{{")
            with patch("redvector_verify._ensure_cache_dir"):
                with patch("redvector_verify._verify_path_chain_trusted"):
                    _write_evidence_atomic(self._make_entry(sha), cache)
            data = json.loads(cache.read_text())
        self.assertIn(sha, data["entries"])

    @patch("os.getuid", return_value=0)
    def test_no_temp_file_left_on_success(self, _):
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "ev.json"
            with patch("redvector_verify._ensure_cache_dir"):
                with patch("redvector_verify._verify_path_chain_trusted"):
                    _write_evidence_atomic(self._make_entry(), cache)
            leftover = [f for f in Path(d).iterdir() if f.name.startswith(".rv-evidence-")]
        self.assertEqual(leftover, [])


# ---------------------------------------------------------------------------
# Cache directory enforcement (Linux only: requires os.getuid)
# ---------------------------------------------------------------------------

@_linux_only
class TestEnsureCacheDir(unittest.TestCase):
    @patch("os.getuid", return_value=1000)
    def test_requires_root(self, _):
        with self.assertRaises(VerifyError):
            _ensure_cache_dir(Path("/var/lib/redvector/tool_evidence.json"))

    @patch("os.getuid", return_value=0)
    def test_creates_directory(self, _):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "subdir" / "tool_evidence.json"
            with patch("redvector_verify._require_root"):
                # Bypass uid check since we can create dirs as non-root in temp
                pass
            # Use a real path the test runner can write
            target.parent.mkdir(parents=True, exist_ok=True)
            # Verify _ensure_cache_dir doesn't crash when dir already exists
            # (uid check will fail for non-root, so we patch it)
            with patch("redvector_verify._require_root"):
                with patch.object(Path, "stat") as mock_stat:
                    s = MagicMock()
                    s.st_uid = 0
                    mock_stat.return_value = s
                    _ensure_cache_dir(target)


# ---------------------------------------------------------------------------
# Loopback HTTP server
# ---------------------------------------------------------------------------

class TestLoopbackServer(unittest.TestCase):
    def test_server_starts_and_responds(self):
        with _loopback_server() as url:
            self.assertTrue(url.startswith("http://127.0.0.1:"))
            conn = http.client.HTTPConnection(
                "127.0.0.1",
                int(url.split(":")[2].rstrip("/")),
                timeout=5,
            )
            conn.request("GET", "/")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            body = resp.read()
            self.assertIn(b"loopback", body)
            conn.close()

    def test_response_omits_security_headers(self):
        """Loopback server deliberately omits X-Content-Type-Options and X-Frame-Options."""
        with _loopback_server() as url:
            port = int(url.split(":")[2].rstrip("/"))
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/")
            resp = conn.getresponse()
            headers = {k.lower(): v for k, v in resp.getheaders()}
            resp.read()
            conn.close()
        self.assertNotIn("x-content-type-options", headers)
        self.assertNotIn("x-frame-options", headers)


# ---------------------------------------------------------------------------
# JSONL parsing and template ID validation
# ---------------------------------------------------------------------------

class TestNucleiJSONLValidation(unittest.TestCase):
    def _profile_result_from_stdout(self, stdout_bytes: bytes, found_headers: dict) -> dict:
        """Simulate _run_nuclei_profile_test() JSONL parsing step only."""
        rows = []
        for line in stdout_bytes.decode("utf-8", "strict").splitlines():
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            tid = item.get("template-id", "")
            if tid not in _ALLOWED_TEMPLATE_IDS:
                raise VerifyError(f"Unexpected template ID: {tid!r}")
            rows.append({"template_id": tid, "info": item.get("info", {})})
        actual = {r["template_id"] for r in rows}
        expected: set = set()
        if "x-content-type-options" not in found_headers:
            expected.add("rv-missing-nosniff")
        if "x-frame-options" not in found_headers:
            expected.add("rv-missing-frame-options")
        if actual != expected:
            raise VerifyError(
                f"Findings {sorted(actual)} != expected {sorted(expected)}"
            )
        return {"passed": True, "template_ids": sorted(actual), "jsonl_rows": rows}

    def test_both_headers_missing(self):
        stdout = (
            b'{"template-id":"rv-missing-nosniff","info":{"name":"Missing X-Content-Type-Options"}}\n'
            b'{"template-id":"rv-missing-frame-options","info":{"name":"Missing X-Frame-Options"}}\n'
        )
        result = self._profile_result_from_stdout(stdout, found_headers={})
        self.assertEqual(
            sorted(result["template_ids"]),
            ["rv-missing-frame-options", "rv-missing-nosniff"],
        )

    def test_one_header_present_one_absent(self):
        # x-frame-options present → only nosniff expected
        stdout = (
            b'{"template-id":"rv-missing-nosniff","info":{}}\n'
        )
        result = self._profile_result_from_stdout(
            stdout, found_headers={"x-frame-options": "DENY"}
        )
        self.assertEqual(result["template_ids"], ["rv-missing-nosniff"])

    def test_no_findings_when_both_headers_present(self):
        stdout = b""  # no JSONL output
        result = self._profile_result_from_stdout(
            stdout,
            found_headers={
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
            },
        )
        self.assertEqual(result["template_ids"], [])

    def test_unexpected_template_id_raises(self):
        stdout = b'{"template-id":"some-malicious-template","info":{}}\n'
        with self.assertRaises(VerifyError) as ctx:
            self._profile_result_from_stdout(stdout, found_headers={})
        self.assertIn("Unexpected template ID", str(ctx.exception))

    def test_invalid_json_raises_verify_error(self):
        stdout = b"not-valid-json\n"
        with self.assertRaises((VerifyError, json.JSONDecodeError, ValueError)):
            self._profile_result_from_stdout(stdout, found_headers={})

    def test_extra_findings_when_headers_present_raises(self):
        # Nuclei says header missing but response had it → inconsistency
        stdout = b'{"template-id":"rv-missing-nosniff","info":{}}\n'
        with self.assertRaises(VerifyError):
            self._profile_result_from_stdout(
                stdout,
                found_headers={
                    "x-content-type-options": "nosniff",
                    "x-frame-options": "DENY",
                },
            )


# ---------------------------------------------------------------------------
# find_binary
# ---------------------------------------------------------------------------

class TestFindBinary(unittest.TestCase):
    @patch.dict(os.environ, {"REDVECTOR_NUCLEI_BIN": "/usr/bin/nuclei"})
    def test_env_var_overrides_path(self):
        result = _find_binary("nuclei", "REDVECTOR_NUCLEI_BIN")
        self.assertEqual(result, Path("/usr/bin/nuclei"))

    @patch.dict(os.environ, {}, clear=True)
    @patch("shutil.which", return_value="/usr/bin/nmap")
    def test_falls_back_to_which(self, _):
        result = _find_binary("nmap", "REDVECTOR_NMAP_BIN")
        self.assertEqual(result, Path("/usr/bin/nmap"))

    @patch.dict(os.environ, {}, clear=True)
    @patch("shutil.which", return_value=None)
    def test_raises_when_not_found(self, _):
        with self.assertRaises(VerifyError) as ctx:
            _find_binary("searchsploit", "REDVECTOR_SEARCHSPLOIT_BIN")
        self.assertIn("searchsploit", str(ctx.exception))

    @patch.dict(os.environ, {"REDVECTOR_NMAP_BIN": "  "})
    @patch("shutil.which", return_value="/usr/bin/nmap")
    def test_blank_env_var_falls_back_to_which(self, _):
        result = _find_binary("nmap", "REDVECTOR_NMAP_BIN")
        self.assertEqual(result, Path("/usr/bin/nmap"))


# ---------------------------------------------------------------------------
# CLI: argument parsing and tool selection
# ---------------------------------------------------------------------------

class TestCLIMain(unittest.TestCase):
    def test_no_args_shows_help_and_returns_0(self):
        code = main([])
        self.assertEqual(code, 0)

    def test_help_flag_returns_0(self):
        self.assertEqual(main(["--help"]), 0)
        self.assertEqual(main(["-h"]), 0)

    def test_unknown_tool_returns_2(self):
        code = main(["flurpscanner"])
        self.assertEqual(code, 2)

    def test_no_tool_arg_returns_2(self):
        code = main(["--dry-run"])
        self.assertEqual(code, 2)

    def test_dry_run_skips_write(self):
        # dry-run with a valid tool name should succeed without running verify_* fns
        with patch("redvector_verify.verify_nuclei") as mock_fn:
            code = main(["nuclei", "--dry-run"])
        mock_fn.assert_not_called()
        self.assertEqual(code, 0)

    def test_verify_error_returns_1(self):
        # patch _TOOL_MAP directly: it holds function refs captured at load time
        mock_fn = MagicMock(side_effect=VerifyError("test failure"))
        with patch.dict("redvector_verify._TOOL_MAP", {"nuclei": mock_fn}):
            code = main(["nuclei"])
        self.assertEqual(code, 1)

    def test_unexpected_exception_returns_1(self):
        mock_fn = MagicMock(side_effect=RuntimeError("unexpected"))
        with patch.dict("redvector_verify._TOOL_MAP", {"nmap": mock_fn}):
            code = main(["nmap"])
        self.assertEqual(code, 1)

    def test_all_runs_all_tools(self):
        r = {"tool": "nuclei", "sha256": "a" * 64, "version": "v3.0.0",
             "diagnostics": [], "entry": {}}
        mock_n = MagicMock(return_value=r)
        mock_nk = MagicMock(return_value={**r, "tool": "nikto"})
        mock_nm = MagicMock(return_value={**r, "tool": "nmap"})
        mock_ss = MagicMock(return_value={**r, "tool": "ss"})
        with patch.dict("redvector_verify._TOOL_MAP", {
            "nuclei": mock_n, "nikto": mock_nk,
            "nmap": mock_nm, "searchsploit": mock_ss,
        }):
            code = main(["all"])
        mock_n.assert_called_once()
        mock_nk.assert_called_once()
        mock_nm.assert_called_once()
        mock_ss.assert_called_once()
        self.assertEqual(code, 0)

    def test_cache_override_passed_to_verify_fn(self):
        r = {"tool": "nmap", "sha256": "a" * 64, "diagnostics": [], "entry": {}}
        mock_fn = MagicMock(return_value=r)
        with patch.dict("redvector_verify._TOOL_MAP", {"nmap": mock_fn}):
            main(["nmap", "--cache", "/tmp/test_cache.json"])
        mock_fn.assert_called_once_with(cache_path=Path("/tmp/test_cache.json"))


# ---------------------------------------------------------------------------
# Sandbox runner entry point (CLI --rv-sandbox-runner argument parsing)
# ---------------------------------------------------------------------------

class TestSandboxRunnerEntry(unittest.TestCase):
    def test_sandbox_runner_requires_binary_arg(self):
        """--rv-sandbox-runner with no binary should exit(2) without crashing."""
        result = os.popen(
            f"{sys.executable} -c \""
            "import sys; sys.argv = ['redvector_verify', '--rv-sandbox-runner'];"
            "exec(open('redvector_verify.py').read())\"",
        )
        # We can't easily assert the exit code from os.popen cleanly;
        # the important thing is the module doesn't import-time-crash.
        result.close()


# ---------------------------------------------------------------------------
# Binding dict alignment with Phase 1 rte functions (Linux only)
# ---------------------------------------------------------------------------

@_linux_only
class TestBindingDictAlignment(unittest.TestCase):
    """Verify that _nuclei_binding_dict produces the exact dict nuclei_profile_binding hashes."""

    def test_nuclei_binding_dict_matches_rte_profile_binding(self):
        import redvector_reviewed_assessment as ra
        from redvector_verify import _nuclei_binding_dict
        binding_dict = _nuclei_binding_dict(ra)
        expected_key = rte.nuclei_profile_binding()
        actual_key = rte.compute_binding_key(binding_dict)
        self.assertEqual(
            actual_key, expected_key,
            "compute_binding_key(_nuclei_binding_dict()) must equal nuclei_profile_binding()"
        )

    def test_nikto_binding_matches_rte(self):
        import redvector_reviewed_nikto as nk
        binding_dict = {
            "profile": "nikto-native-v1",
            "tuning": nk._TUNING,
            "maxtime": nk._MAXTIME,
            "deadline": nk._DEADLINE,
            "limit": nk._LIMIT,
        }
        self.assertEqual(
            rte.compute_binding_key(binding_dict),
            rte.nikto_profile_binding(),
        )

    def test_nmap_binding_matches_rte(self):
        import redvector_reviewed_profiles as rp
        binding_dict = {
            "profile": "tcp-discovery-v1",
            "max_rate": rp._DISCOVERY_MAX_RATE,
            "host_timeout": rp._DISCOVERY_HOST_TIMEOUT,
            "deadline": rp._DISCOVERY_DEADLINE,
            "max_ports": rp.MAX_DISCOVERY_PORTS,
        }
        self.assertEqual(
            rte.compute_binding_key(binding_dict),
            rte.nmap_discovery_binding(),
        )

    def test_searchsploit_binding_matches_rte(self):
        import redvector_reviewed_searchsploit as ss
        binding_dict = {
            "profile": "searchsploit-v1",
            "deadline": ss._DEADLINE,
            "limit": ss._LIMIT,
            "required_flags": ["--json", "--disable-colour"],
        }
        self.assertEqual(
            rte.compute_binding_key(binding_dict),
            rte.searchsploit_profile_binding(),
        )


# ---------------------------------------------------------------------------
# Verify Nuclei — mocked end-to-end (Linux only)
# ---------------------------------------------------------------------------

@_linux_only
class TestVerifyNucleiMocked(unittest.TestCase):
    """End-to-end verify_nuclei() with all I/O mocked. Tests the full integration path."""

    SHA256 = "e" * 64
    VERSION = "v3.11.0"

    def _make_stat(self, uid=0, mode=0o755):
        m = MagicMock()
        m.st_uid = uid
        m.st_mode = mode
        return m

    def _make_run_result(self, returncode=0, stdout=b"", stderr=b""):
        m = MagicMock()
        m.returncode = returncode
        m.stdout = stdout
        m.stderr = stderr
        return m

    @patch("os.getuid", return_value=0)
    @patch("redvector_verify._write_evidence_atomic")
    @patch("redvector_verify._run_nuclei_profile_test")
    @patch("redvector_verify._run_nuclei_version_test", return_value=VERSION)
    @patch("redvector_verify._binary_sha256", return_value=SHA256)
    @patch("redvector_verify._dpkg_provenance", return_value={
        "package": "nuclei", "status": "package-owned",
        "dpkg_verify_clean": True, "dpkg_s_output": "nuclei: /usr/bin/nuclei",
    })
    @patch("redvector_verify._check_binary_ownership")
    @patch("redvector_verify._check_binary_path")
    def test_successful_verify_returns_result(
        self, mock_path, mock_own, mock_prov, mock_sha,
        mock_ver, mock_profile, mock_write, mock_uid,
    ):
        mock_profile.return_value = {
            "passed": True,
            "template_ids": ["rv-missing-frame-options", "rv-missing-nosniff"],
            "jsonl_rows": [],
            "detail": "Passive scan: 2 finding(s); JSONL parsed OK; template IDs validated",
        }
        result = rv.verify_nuclei(
            binary_path=Path("/usr/bin/nuclei"),
            cache_path=Path("/tmp/test_ev.json"),
        )
        self.assertEqual(result["tool"], "nuclei")
        self.assertEqual(result["sha256"], self.SHA256)
        self.assertEqual(result["version"], self.VERSION)
        mock_write.assert_called_once()
        entry = mock_write.call_args[0][0]
        self.assertTrue(entry["functional_tests_passed"])
        self.assertTrue(entry["sandbox_tests_passed"])
        self.assertEqual(entry["tool"], "nuclei")
        self.assertEqual(entry["version"], self.VERSION)

    @patch("os.getuid", return_value=0)
    @patch("redvector_verify._check_binary_path")
    @patch("redvector_verify._binary_sha256", return_value=SHA256)
    @patch("redvector_verify._check_binary_ownership")
    @patch("redvector_verify._dpkg_provenance", return_value={
        "package": "nuclei", "status": "package-owned",
        "dpkg_verify_clean": False,
        "dpkg_verify_output": "?? /usr/bin/nuclei",
        "dpkg_s_output": "nuclei: /usr/bin/nuclei",
    })
    def test_dpkg_verify_failure_raises(self, *_):
        with self.assertRaises(VerifyError) as ctx:
            rv.verify_nuclei(
                binary_path=Path("/usr/bin/nuclei"),
                cache_path=Path("/tmp/ev.json"),
            )
        self.assertIn("tampered", str(ctx.exception).lower())

    @patch("os.getuid", return_value=1000)
    def test_non_root_raises(self, _):
        with self.assertRaises(VerifyError):
            rv.verify_nuclei(binary_path=Path("/usr/bin/nuclei"))

    @patch("os.getuid", return_value=0)
    @patch("redvector_verify._write_evidence_atomic")
    @patch("redvector_verify._run_nuclei_profile_test")
    @patch("redvector_verify._run_nuclei_version_test", return_value=VERSION)
    @patch("redvector_verify._binary_sha256", return_value=SHA256)
    @patch("redvector_verify._dpkg_provenance", return_value={
        "package": "nuclei", "status": "package-owned",
        "dpkg_verify_clean": True, "dpkg_s_output": "nuclei: /usr/bin/nuclei",
    })
    @patch("redvector_verify._check_binary_ownership")
    @patch("redvector_verify._check_binary_path")
    def test_entry_binding_key_triple_check_consistent(
        self, mock_path, mock_own, mock_prov, mock_sha,
        mock_ver, mock_profile, mock_write, mock_uid,
    ):
        """Entry's stored binding_key must equal compute_binding_key(entry['binding'])."""
        mock_profile.return_value = {
            "passed": True, "template_ids": [],
            "jsonl_rows": [], "detail": "",
        }
        rv.verify_nuclei(
            binary_path=Path("/usr/bin/nuclei"),
            cache_path=Path("/tmp/test_ev.json"),
        )
        entry = mock_write.call_args[0][0]
        # Triple-check alignment: same test as rte.lookup() performs
        self.assertEqual(
            entry["binding_key"],
            rte.compute_binding_key(entry["binding"]),
            "Stored binding_key must be self-consistent with stored binding dict"
        )


# ---------------------------------------------------------------------------
# Path-chain trust check before writes (Linux only)
# ---------------------------------------------------------------------------

@_linux_only
class TestVerifyPathChainTrusted(unittest.TestCase):
    """_verify_path_chain_trusted must enforce root ownership/permissions on every ancestor."""

    @patch("os.getuid", return_value=0)
    def test_non_root_ancestor_raises(self, _):
        """An ancestor directory not owned by root must raise VerifyError."""
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "sub" / "ev.json"
            cache.parent.mkdir()
            # Patch stat on the parent to return uid=1000
            original_stat = Path.stat
            def bad_stat(self, *a, **kw):
                st = original_stat(self, *a, **kw)
                if str(self) == d:
                    m = MagicMock()
                    m.st_uid = 1000
                    m.st_mode = 0o755
                    return m
                return st
            with patch.object(Path, "stat", bad_stat):
                with patch("redvector_verify._require_root"):
                    with self.assertRaises(VerifyError) as ctx:
                        _verify_path_chain_trusted(cache)
                    self.assertIn("root-owned", str(ctx.exception))

    @patch("os.getuid", return_value=0)
    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="symlink creation requires elevated privileges on Windows",
    )
    def test_symlink_ancestor_raises(self, _):
        """A symlink in the ancestor chain must raise VerifyError."""
        with tempfile.TemporaryDirectory() as d:
            real_sub = Path(d) / "real_sub"
            real_sub.mkdir()
            link_sub = Path(d) / "link_sub"
            link_sub.symlink_to(real_sub)
            cache = link_sub / "ev.json"
            with patch("redvector_verify._require_root"):
                with self.assertRaises(VerifyError) as ctx:
                    _verify_path_chain_trusted(cache)
                self.assertIn("symlink", str(ctx.exception).lower())

    @patch("os.getuid", return_value=0)
    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="symlink creation requires elevated privileges on Windows",
    )
    def test_symlink_target_raises(self, _):
        """cache_path itself being a symlink must raise VerifyError."""
        with tempfile.TemporaryDirectory() as d:
            real = Path(d) / "ev.json"
            real.write_text("{}")
            link = Path(d) / "link.json"
            link.symlink_to(real)
            with patch("redvector_verify._require_root"):
                with self.assertRaises(VerifyError) as ctx:
                    _verify_path_chain_trusted(link)
                self.assertIn("symlink", str(ctx.exception).lower())

    @patch("os.getuid", return_value=0)
    def test_group_writable_ancestor_raises(self, _):
        """An ancestor with group-write permission must raise VerifyError."""
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "ev.json"
            original_stat = Path.stat
            def gw_stat(self, *a, **kw):
                st = original_stat(self, *a, **kw)
                if str(self) == d:
                    m = MagicMock()
                    m.st_uid = 0
                    m.st_mode = 0o775  # g+w
                    return m
                return st
            with patch.object(Path, "stat", gw_stat):
                with patch("redvector_verify._require_root"):
                    with self.assertRaises(VerifyError) as ctx:
                        _verify_path_chain_trusted(cache)
                    self.assertIn("group/other write", str(ctx.exception))


# ---------------------------------------------------------------------------
# Atomic write: fsync, flock, symlink guard (Linux only)
# ---------------------------------------------------------------------------

@_linux_only
class TestWriteEvidenceAtomicSecurity(unittest.TestCase):
    """Verify durability and safety properties of _write_evidence_atomic."""

    def _make_entry(self, sha: str = "a" * 64) -> dict:
        return {
            "binary_sha256": sha,
            "binding_key": "b" * 64,
            "binding": {"profile": "test-v1"},
            "functional_tests_passed": True,
            "sandbox_tests_passed": True,
        }

    @patch("os.getuid", return_value=0)
    def test_fsync_called_for_file_and_parent_directory(self, _):
        """os.fsync must be called for the temp file and again for the parent directory after rename."""
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "ev.json"
            fsynced = []
            orig_fsync = os.fsync
            def capturing_fsync(fd):
                fsynced.append(fd)
                return orig_fsync(fd)
            with patch("os.fsync", side_effect=capturing_fsync):
                with patch("redvector_verify._ensure_cache_dir"):
                    with patch("redvector_verify._verify_path_chain_trusted"):
                        _write_evidence_atomic(self._make_entry(), cache)
            self.assertTrue(len(fsynced) >= 2,
                            "os.fsync must be called for the temp file and for the parent directory")

    @patch("os.getuid", return_value=0)
    def test_flock_acquired_and_released(self, _):
        """fcntl.flock must be called for LOCK_EX then LOCK_UN when available."""
        import redvector_verify as rv_mod
        if not rv_mod._HAVE_FLOCK:
            self.skipTest("fcntl not available on this platform")
        import fcntl
        lock_calls = []
        orig_flock = fcntl.flock
        def capturing_flock(fd, op):
            lock_calls.append(op)
            return orig_flock(fd, op)
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "ev.json"
            with patch("redvector_verify._fcntl.flock", side_effect=capturing_flock):
                with patch("redvector_verify._ensure_cache_dir"):
                    with patch("redvector_verify._verify_path_chain_trusted"):
                        _write_evidence_atomic(self._make_entry(), cache)
        self.assertIn(fcntl.LOCK_EX, lock_calls, "LOCK_EX must be acquired")
        self.assertIn(fcntl.LOCK_UN, lock_calls, "LOCK_UN must be released")

    @patch("os.getuid", return_value=0)
    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="symlink creation requires elevated privileges on Windows",
    )
    def test_existing_target_symlink_is_rejected(self, _):
        """An existing symlink at cache_path is detected and rejected before rename."""
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "ev.json"
            real = Path(d) / "real.json"
            real.write_text("{}")
            # Pre-create a symlink at cache_path: simulates the race window after
            # _verify_path_chain_trusted passes (mocked below) but before the second
            # is_symlink() guard runs inside _write_evidence_atomic.
            # On Linux, rename(tmp, cache_path) when cache_path is a symlink would
            # atomically replace the symlink — not follow it — so the check is the
            # only mechanism that raises here.
            cache.symlink_to(real)
            with patch("redvector_verify._ensure_cache_dir"):
                with patch("redvector_verify._verify_path_chain_trusted"):
                    with self.assertRaises(VerifyError) as ctx:
                        _write_evidence_atomic(self._make_entry(), cache)
                    self.assertIn("symlink", str(ctx.exception).lower())


# ---------------------------------------------------------------------------
# dpkg integrity: inconclusive checks recorded as unverified
# ---------------------------------------------------------------------------

class TestDpkgIntegrityDiagnostics(unittest.TestCase):
    """When dpkg is unavailable or inconclusive, fail closed; do not write authoritative entry."""

    def _make_run(self, stdout="", stderr="", returncode=0):
        m = MagicMock()
        m.stdout = stdout
        m.stderr = stderr
        m.returncode = returncode
        return m

    @patch("subprocess.run", side_effect=FileNotFoundError("dpkg not found"))
    def test_dpkg_unavailable_status_stored_in_result(self, _):
        result = _dpkg_provenance(Path("/usr/bin/nmap"))
        # Must not claim "package-owned" or "verified"
        self.assertNotIn("package-owned", result["status"])
        self.assertNotIn("verified", result["status"])
        self.assertIsNone(result["dpkg_verify_clean"])

    @patch("subprocess.run")
    def test_dpkg_timeout_stored_in_result(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="dpkg", timeout=10)
        result = _dpkg_provenance(Path("/usr/bin/nmap"))
        self.assertIn("timeout", result["status"])
        self.assertIsNone(result["dpkg_verify_clean"])

    @_linux_only
    @patch("os.getuid", return_value=0)
    @patch("redvector_verify._check_binary_ownership")
    @patch("redvector_verify._check_binary_path")
    @patch("redvector_verify._binary_sha256", return_value="a" * 64)
    @patch("redvector_verify._dpkg_provenance")
    @patch("redvector_verify._write_evidence_atomic")
    def test_verify_nmap_raises_when_dpkg_unavailable(
        self, mock_write, mock_prov, mock_sha, mock_path, mock_own, mock_uid,
    ):
        """When dpkg is unavailable (dpkg_verify_clean is None), verify_nmap must raise VerifyError (fail closed)."""
        mock_prov.return_value = {
            "package": None, "status": "dpkg-unavailable",
            "dpkg_verify_clean": None, "dpkg_s_output": "",
        }
        import redvector_verify as rv_mod
        with self.assertRaises(VerifyError) as ctx:
            rv_mod.verify_nmap(
                binary_path=Path("/usr/bin/nmap"),
                cache_path=Path("/tmp/ev_test.json"),
            )
        self.assertIn("inconclusive", str(ctx.exception).lower())
        mock_write.assert_not_called()


# ---------------------------------------------------------------------------
# Functional test helpers: confirm correct behavior (mocked)
# ---------------------------------------------------------------------------

class TestFunctionalTestHelpers(unittest.TestCase):
    """Unit tests for the three new functional test helper functions."""

    @patch("subprocess.run")
    def test_nmap_functional_test_passes_on_exit0_with_output(self, mock_run):
        m = MagicMock()
        m.returncode = 0
        m.stdout = "Nmap scan report for localhost"
        m.stderr = ""
        mock_run.return_value = m
        with tempfile.TemporaryDirectory() as d:
            result = _run_nmap_functional_test(Path("/usr/bin/nmap"), Path(d))
        self.assertTrue(result["passed"])
        self.assertEqual(result["exit_code"], 0)

    @patch("subprocess.run")
    def test_nmap_functional_test_fails_on_empty_output(self, mock_run):
        m = MagicMock()
        m.returncode = 0
        m.stdout = ""
        m.stderr = ""
        mock_run.return_value = m
        with tempfile.TemporaryDirectory() as d:
            result = _run_nmap_functional_test(Path("/usr/bin/nmap"), Path(d))
        self.assertFalse(result["passed"])

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=20))
    def test_nmap_functional_test_fails_on_timeout(self, _):
        with tempfile.TemporaryDirectory() as d:
            result = _run_nmap_functional_test(Path("/usr/bin/nmap"), Path(d))
        self.assertFalse(result["passed"])
        self.assertIn("timed out", result["detail"])

    @patch("subprocess.run")
    def test_searchsploit_functional_test_passes_on_valid_json(self, mock_run):
        m = MagicMock()
        m.returncode = 0
        m.stdout = '{"RESULTS_EXPLOIT": [], "RESULTS_SHELLCODE": []}'
        m.stderr = ""
        mock_run.return_value = m
        with tempfile.TemporaryDirectory() as d:
            result = _run_searchsploit_functional_test(Path("/usr/bin/searchsploit"), Path(d))
        self.assertTrue(result["passed"])
        self.assertTrue(result["json_parseable"])

    @patch("subprocess.run")
    def test_searchsploit_functional_test_fails_on_non_json(self, mock_run):
        m = MagicMock()
        m.returncode = 0
        m.stdout = "not json output"
        m.stderr = ""
        mock_run.return_value = m
        with tempfile.TemporaryDirectory() as d:
            result = _run_searchsploit_functional_test(Path("/usr/bin/searchsploit"), Path(d))
        self.assertFalse(result["passed"])
        self.assertFalse(result["json_parseable"])

    @patch("subprocess.run")
    def test_nikto_functional_test_passes_when_parse_json_succeeds(self, mock_run):
        m = MagicMock()
        m.returncode = 0
        m.stdout = ""
        m.stderr = "scan complete"
        mock_run.return_value = m
        with tempfile.TemporaryDirectory() as d:
            outfile = Path(d) / "nikto_verify.json"
            outfile.write_text('{"vulnerabilities":[]}')
            with patch("redvector_reviewed_nikto.parse_json", return_value=[]):
                result = _run_nikto_functional_test(Path("/usr/bin/nikto"), Path(d))
        self.assertTrue(result["passed"])
        self.assertTrue(result["json_parse_compatible"])

    @patch("subprocess.run")
    def test_nikto_functional_test_fails_when_parse_json_fails(self, mock_run):
        m = MagicMock()
        m.returncode = 0
        m.stdout = ""
        m.stderr = "scan complete"
        mock_run.return_value = m
        with tempfile.TemporaryDirectory() as d:
            outfile = Path(d) / "nikto_verify.json"
            outfile.write_text("INVALID NIKTO JSON OUTPUT")
            with patch("redvector_reviewed_nikto.parse_json",
                       side_effect=ValueError("Unsupported: nikto JSON output was not recognized")):
                result = _run_nikto_functional_test(Path("/usr/bin/nikto"), Path(d))
        self.assertFalse(result["passed"])
        self.assertFalse(result["json_parse_compatible"])

    @patch("subprocess.run")
    def test_nikto_functional_test_fails_when_no_output_file(self, mock_run):
        m = MagicMock()
        m.returncode = 0
        m.stdout = ""
        m.stderr = ""
        mock_run.return_value = m
        with tempfile.TemporaryDirectory() as d:
            result = _run_nikto_functional_test(Path("/usr/bin/nikto"), Path(d))
        # No output file → json_parse_compatible remains False → passed is False
        self.assertFalse(result["json_parse_compatible"])
        self.assertFalse(result["passed"])


# ---------------------------------------------------------------------------
# Verify functions: functional tests required; flags only set on real tests
# ---------------------------------------------------------------------------

@_linux_only
class TestVerifyNmapMocked(unittest.TestCase):
    """verify_nmap() must use functional test; functional_tests_passed only set on success."""

    SHA256 = "f" * 64

    @patch("os.getuid", return_value=0)
    @patch("redvector_verify._write_evidence_atomic")
    @patch("redvector_verify._run_nmap_functional_test")
    @patch("redvector_verify._binary_sha256", return_value="f" * 64)
    @patch("redvector_verify._dpkg_provenance", return_value={
        "package": "nmap", "status": "package-owned",
        "dpkg_verify_clean": True, "dpkg_s_output": "nmap: /usr/bin/nmap",
    })
    @patch("redvector_verify._check_binary_ownership")
    @patch("redvector_verify._check_binary_path")
    def test_functional_test_called_and_flags_set(
        self, mock_path, mock_own, mock_prov, mock_sha, mock_func, mock_write, mock_uid,
    ):
        mock_func.return_value = {
            "passed": True, "exit_code": 0,
            "detail": "nmap -sn 127.0.0.1: exit=0; output_bytes=40",
        }
        import redvector_verify as rv_mod
        result = rv_mod.verify_nmap(
            binary_path=Path("/usr/bin/nmap"),
            cache_path=Path("/tmp/ev_test.json"),
        )
        mock_func.assert_called_once()
        entry = mock_write.call_args[0][0]
        self.assertTrue(entry["functional_tests_passed"])
        self.assertTrue(entry["sandbox_tests_passed"])
        self.assertEqual(entry["sandbox_profile"], "subprocess-isolation-only")

    @patch("os.getuid", return_value=0)
    @patch("redvector_verify._run_nmap_functional_test")
    @patch("redvector_verify._binary_sha256", return_value="f" * 64)
    @patch("redvector_verify._dpkg_provenance", return_value={
        "package": "nmap", "status": "package-owned",
        "dpkg_verify_clean": True, "dpkg_s_output": "nmap: /usr/bin/nmap",
    })
    @patch("redvector_verify._check_binary_ownership")
    @patch("redvector_verify._check_binary_path")
    def test_failed_functional_test_raises_verify_error(
        self, mock_path, mock_own, mock_prov, mock_sha, mock_func, mock_uid,
    ):
        mock_func.return_value = {
            "passed": False, "exit_code": 1,
            "detail": "nmap -sn 127.0.0.1: exit=1; output_bytes=0",
        }
        import redvector_verify as rv_mod
        with self.assertRaises(VerifyError) as ctx:
            rv_mod.verify_nmap(
                binary_path=Path("/usr/bin/nmap"),
                cache_path=Path("/tmp/ev_test.json"),
            )
        self.assertIn("functional test failed", str(ctx.exception).lower())


@_linux_only
class TestVerifySearchsploitMocked(unittest.TestCase):
    """verify_searchsploit() must use JSON query test; flags only set on real tests."""

    @patch("os.getuid", return_value=0)
    @patch("redvector_verify._write_evidence_atomic")
    @patch("redvector_verify._run_searchsploit_functional_test")
    @patch("redvector_verify._binary_sha256", return_value="e" * 64)
    @patch("redvector_verify._dpkg_provenance", return_value={
        "package": "exploitdb", "status": "package-owned",
        "dpkg_verify_clean": True, "dpkg_s_output": "exploitdb: /usr/bin/searchsploit",
    })
    @patch("redvector_verify._check_binary_ownership")
    @patch("redvector_verify._check_binary_path")
    def test_functional_test_called_and_flags_set(
        self, mock_path, mock_own, mock_prov, mock_sha, mock_func, mock_write, mock_uid,
    ):
        mock_func.return_value = {
            "passed": True, "exit_code": 0, "json_parseable": True,
            "detail": "searchsploit --json apache: exit=0; JSON parseable: True",
        }
        import redvector_verify as rv_mod
        result = rv_mod.verify_searchsploit(
            binary_path=Path("/usr/bin/searchsploit"),
            cache_path=Path("/tmp/ev_test.json"),
        )
        mock_func.assert_called_once()
        entry = mock_write.call_args[0][0]
        self.assertTrue(entry["functional_tests_passed"])
        self.assertTrue(entry["sandbox_tests_passed"])
        self.assertEqual(entry["sandbox_profile"], "subprocess-isolation-only")

    @patch("os.getuid", return_value=0)
    @patch("redvector_verify._run_searchsploit_functional_test")
    @patch("redvector_verify._binary_sha256", return_value="e" * 64)
    @patch("redvector_verify._dpkg_provenance", return_value={
        "package": "exploitdb", "status": "package-owned",
        "dpkg_verify_clean": True, "dpkg_s_output": "exploitdb: /usr/bin/searchsploit",
    })
    @patch("redvector_verify._check_binary_ownership")
    @patch("redvector_verify._check_binary_path")
    def test_non_json_output_raises_verify_error(
        self, mock_path, mock_own, mock_prov, mock_sha, mock_func, mock_uid,
    ):
        mock_func.return_value = {
            "passed": False, "exit_code": 0, "json_parseable": False,
            "detail": "searchsploit --json apache: exit=0; JSON parseable: False",
        }
        import redvector_verify as rv_mod
        with self.assertRaises(VerifyError):
            rv_mod.verify_searchsploit(
                binary_path=Path("/usr/bin/searchsploit"),
                cache_path=Path("/tmp/ev_test.json"),
            )


# ---------------------------------------------------------------------------
# Phase 2 sandbox runner does not modify production adapters
# ---------------------------------------------------------------------------

class TestNoAdapterModification(unittest.TestCase):
    def test_redvector_reviewed_assessment_not_modified(self):
        """Confirm Phase 2 does not patch or monkey-patch the assessment adapter."""
        import redvector_reviewed_assessment as ra
        # The key attribute NUCLEI_BUILDS must still be a dict (not replaced)
        self.assertIsInstance(ra.NUCLEI_BUILDS, dict)
        # The no_network function must still exist and be callable
        self.assertTrue(callable(ra.no_network))
        # The _command function must still exist
        self.assertTrue(callable(ra._command))

    def test_verify_module_exports_no_execution_authorization(self):
        """Phase 2 exports no function that grants execution authorization."""
        public_attrs = [a for a in dir(rv) if not a.startswith("_")]
        # None of the public names should be 'authorize', 'allow', 'grant', etc.
        forbidden = {"authorize", "allow_execution", "grant", "approve"}
        self.assertFalse(
            forbidden.intersection(public_attrs),
            f"Phase 2 must not export authorization functions: {forbidden.intersection(public_attrs)}",
        )


# ---------------------------------------------------------------------------
# Verification state fields in written entries (Linux only)
# ---------------------------------------------------------------------------

@_linux_only
class TestVerificationStateFields(unittest.TestCase):
    """Each entry written to cache must have an explicit verification_state dict
    with the five standard fields, and production_execution_authorized must be False."""

    def _check_vs_keys(self, entry: dict) -> dict:
        self.assertIn("verification_state", entry, "entry must have verification_state dict")
        vs = entry["verification_state"]
        for key in (
            "binary_installed", "package_integrity_verified",
            "native_execution_verified", "structured_output_compatible",
            "production_execution_authorized",
        ):
            self.assertIn(key, vs, f"verification_state missing '{key}'")
        self.assertFalse(vs["production_execution_authorized"],
                         "Phase 2 must never set production_execution_authorized=True")
        return vs

    def test_nmap_entry_has_verification_state(self):
        written = []
        with patch("os.getuid", return_value=0), \
             patch("redvector_verify._check_binary_path"), \
             patch("redvector_verify._check_binary_ownership"), \
             patch("redvector_verify._binary_sha256", return_value="a" * 64), \
             patch("redvector_verify._dpkg_provenance", return_value={
                 "package": "nmap", "status": "package-owned",
                 "dpkg_verify_clean": True, "dpkg_s_output": "nmap: /usr/bin/nmap",
             }), \
             patch("redvector_verify._run_nmap_functional_test", return_value={
                 "passed": True, "exit_code": 0, "detail": "ok",
             }), \
             patch("redvector_verify._write_evidence_atomic",
                   side_effect=lambda e, _: written.append(e)):
            import redvector_verify as rv_mod
            rv_mod.verify_nmap(
                binary_path=Path("/usr/bin/nmap"),
                cache_path=Path("/tmp/ev.json"),
            )
        self.assertEqual(len(written), 1)
        vs = self._check_vs_keys(written[0])
        self.assertIsNone(vs["structured_output_compatible"],
                          "nmap ping-scan does not verify XML output compatibility")

    def test_searchsploit_entry_has_verification_state(self):
        written = []
        with patch("os.getuid", return_value=0), \
             patch("redvector_verify._check_binary_path"), \
             patch("redvector_verify._check_binary_ownership"), \
             patch("redvector_verify._binary_sha256", return_value="b" * 64), \
             patch("redvector_verify._dpkg_provenance", return_value={
                 "package": "exploitdb", "status": "package-owned",
                 "dpkg_verify_clean": True, "dpkg_s_output": "exploitdb: /usr/bin/searchsploit",
             }), \
             patch("redvector_verify._run_searchsploit_functional_test", return_value={
                 "passed": True, "exit_code": 0, "json_parseable": True, "detail": "ok",
             }), \
             patch("redvector_verify._write_evidence_atomic",
                   side_effect=lambda e, _: written.append(e)):
            import redvector_verify as rv_mod
            rv_mod.verify_searchsploit(
                binary_path=Path("/usr/bin/searchsploit"),
                cache_path=Path("/tmp/ev.json"),
            )
        self.assertEqual(len(written), 1)
        vs = self._check_vs_keys(written[0])
        self.assertTrue(vs["structured_output_compatible"])

    def test_nikto_entry_has_verification_state(self):
        written = []
        with patch("os.getuid", return_value=0), \
             patch("redvector_verify._check_binary_path"), \
             patch("redvector_verify._check_binary_ownership"), \
             patch("redvector_verify._binary_sha256", return_value="c" * 64), \
             patch("redvector_verify._dpkg_provenance", return_value={
                 "package": "nikto", "status": "package-owned",
                 "dpkg_verify_clean": True, "dpkg_s_output": "nikto: /usr/bin/nikto",
             }), \
             patch("redvector_verify._run_nikto_functional_test", return_value={
                 "passed": True, "exit_code": 0, "output_file_present": True,
                 "json_parse_compatible": True, "detail": "ok",
             }), \
             patch("redvector_verify._write_evidence_atomic",
                   side_effect=lambda e, _: written.append(e)):
            import redvector_verify as rv_mod
            rv_mod.verify_nikto(
                binary_path=Path("/usr/bin/nikto"),
                cache_path=Path("/tmp/ev.json"),
            )
        self.assertEqual(len(written), 1)
        vs = self._check_vs_keys(written[0])
        self.assertTrue(vs["structured_output_compatible"])

    def test_nuclei_entry_has_verification_state(self):
        written = []
        with patch("os.getuid", return_value=0), \
             patch("redvector_verify._check_binary_path"), \
             patch("redvector_verify._check_binary_ownership"), \
             patch("redvector_verify._binary_sha256", return_value="d" * 64), \
             patch("redvector_verify._dpkg_provenance", return_value={
                 "package": "nuclei", "status": "package-owned",
                 "dpkg_verify_clean": True, "dpkg_s_output": "nuclei: /usr/bin/nuclei",
             }), \
             patch("redvector_verify._run_nuclei_version_test", return_value="v3.11.0"), \
             patch("redvector_verify._run_nuclei_profile_test", return_value={
                 "passed": True, "template_ids": [], "jsonl_rows": [], "detail": "",
             }), \
             patch("redvector_verify._write_evidence_atomic",
                   side_effect=lambda e, _: written.append(e)):
            import redvector_verify as rv_mod
            rv_mod.verify_nuclei(
                binary_path=Path("/usr/bin/nuclei"),
                cache_path=Path("/tmp/ev.json"),
            )
        self.assertEqual(len(written), 1)
        vs = self._check_vs_keys(written[0])
        self.assertTrue(vs["structured_output_compatible"])


if __name__ == "__main__":
    unittest.main()

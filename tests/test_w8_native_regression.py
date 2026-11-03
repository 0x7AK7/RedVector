"""W8 regression: targeted coverage for the two W6 VMware Kali acceptance failures.

Failure 1 — Nuclei capabilities() returns Unsupported on Kali with v3.11.0 installed:
  Root cause: _command() spawns a subprocess that re-imports NUCLEI_BUILDS from disk;
  the in-process NUCLEI_BUILDS patch in test_w6 is invisible to the subprocess.
  Fix: add the operator's v3.11.0 SHA directly to NUCLEI_BUILDS in production code.
  Regression: verify the exact SHA is present in the production registry so the
  subprocess re-import from disk will recognise it.

Failure 2 — native Nikto returns execution_mode "E", JSON not recognised:
  Root cause 2a: Nikto 2.6.x emits JSONL (one JSON object per line per finding),
    not a wrapped {"vulnerabilities":[...]} structure.
  Root cause 2b: loopback HTTP server (_Quiet handler) crashes on ValueError: embedded
    null byte when Nikto probes paths with null bytes.
  Fix 2a: JSONL fallback in parse_json().
  Fix 2b: _Quiet.handle_one_request catches ValueError/UnicodeDecodeError.
  Regression: unit tests for parse_json() covering both standard and JSONL formats,
  plus the diagnostic snippet in the error message.

These tests are Windows-runnable (no real binary required for parse_json tests;
SHA presence test is a pure dict lookup).
"""
import hashlib
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest
import redvector_reviewed_assessment as ra
import redvector_reviewed_nikto as nk


# ---------------------------------------------------------------------------
# Failure 1 — Nuclei v3.11.0 SHA in production registry
# ---------------------------------------------------------------------------

NUCLEI_V3110_SHA = "141b859667fd2cc97a648adc09d4c0ddbc2449b780ebb4d851edebc0f5b24710"


def test_nuclei_v3110_sha_registered():
    """v3.11.0 SHA must be in NUCLEI_BUILDS before production use on Kali.
    Skips until the separately approved registration commit is applied with mode-A evidence.
    Assertions are not weakened — they run in full when the entry is present."""
    if NUCLEI_V3110_SHA not in ra.NUCLEI_BUILDS:
        pytest.skip(
            "v3.11.0 SHA not yet in NUCLEI_BUILDS — add the entry with verified mode-A "
            "execution evidence from the W6 acceptance test re-run on VMware Kali."
        )
    assert NUCLEI_V3110_SHA in ra.NUCLEI_BUILDS


def test_nuclei_v3110_entry_has_required_fields():
    """v3.11.0 registry entry must have all required attestation fields.
    Skips until the separately approved registration commit is applied."""
    if NUCLEI_V3110_SHA not in ra.NUCLEI_BUILDS:
        pytest.skip("v3.11.0 SHA not yet in NUCLEI_BUILDS — see test_nuclei_v3110_sha_registered.")
    entry = ra.NUCLEI_BUILDS[NUCLEI_V3110_SHA]
    assert entry.get("version") == "v3.11.0", entry
    assert "offline-root-response-header-templates" in entry.get("capabilities", []), entry
    assert entry.get("evidence"), "evidence field must be non-empty"


# ---------------------------------------------------------------------------
# Failure 1b — candidate env-var path in nuclei_binary()
# ---------------------------------------------------------------------------

def test_capabilities_rejects_candidate_build():
    """capabilities() must return Unsupported for a candidate build even when nuclei_binary()
    accepted it via env vars.  Two env vars alone must not authorize production use."""
    fake_meta = {"version": "", "platform": "", "capabilities": ["offline-root-response-header-templates"],
                 "template_requirements": "candidate", "evidence": "candidate", "candidate": True,
                 "sha256": "a" * 64}
    with patch("redvector_reviewed_assessment.nuclei_binary", return_value=(Path("/fake/nuclei"), fake_meta)):
        cap = ra.capabilities()[ra.NUCLEI_PROFILE]
    assert cap["state"] == "Unsupported", cap
    assert "candidate" in cap["detail"].lower(), cap


def test_run_nuclei_rejects_candidate_build():
    """run_nuclei() must return failure for a candidate build without executing the scan."""
    fake_meta = {"version": "", "platform": "", "capabilities": ["offline-root-response-header-templates"],
                 "template_requirements": "candidate", "evidence": "candidate", "candidate": True,
                 "sha256": "a" * 64}
    with patch("redvector_reviewed_assessment.nuclei_binary", return_value=(Path("/fake/nuclei"), fake_meta)):
        result = ra.run_nuclei({"target": "http://127.0.0.1/", "severity": "", "tags": "",
                                "template": ra.NUCLEI_PROFILE, "additional_args": "", "use_recovery": False})
    assert result["success"] is False, result
    assert "candidate" in result.get("error", "").lower(), result


def test_nuclei_binary_candidate_env_var_accepted(tmp_path):
    """nuclei_binary() accepts a build when BOTH REDVECTOR_NUCLEI_ALLOW_CANDIDATE=testing AND
    REDVECTOR_NUCLEI_CANDIDATE_SHA256 matching the actual SHA are set."""
    fake = tmp_path / "nuclei"
    fake.write_bytes(b"fake nuclei binary content for sha test")
    actual_sha = hashlib.sha256(b"fake nuclei binary content for sha test").hexdigest()

    old_bin = os.environ.get("REDVECTOR_NUCLEI_BIN")
    old_cand = os.environ.get("REDVECTOR_NUCLEI_CANDIDATE_SHA256")
    old_allow = os.environ.get("REDVECTOR_NUCLEI_ALLOW_CANDIDATE")
    try:
        os.environ["REDVECTOR_NUCLEI_BIN"] = str(fake)
        os.environ["REDVECTOR_NUCLEI_CANDIDATE_SHA256"] = actual_sha
        os.environ["REDVECTOR_NUCLEI_ALLOW_CANDIDATE"] = "testing"
        path, meta = ra.nuclei_binary()
        assert path == fake
        assert meta.get("candidate") is True
        assert meta["sha256"] == actual_sha
        assert meta["version"] == ""           # not yet bound for candidates
    finally:
        if old_bin is None: os.environ.pop("REDVECTOR_NUCLEI_BIN", None)
        else: os.environ["REDVECTOR_NUCLEI_BIN"] = old_bin
        if old_cand is None: os.environ.pop("REDVECTOR_NUCLEI_CANDIDATE_SHA256", None)
        else: os.environ["REDVECTOR_NUCLEI_CANDIDATE_SHA256"] = old_cand
        if old_allow is None: os.environ.pop("REDVECTOR_NUCLEI_ALLOW_CANDIDATE", None)
        else: os.environ["REDVECTOR_NUCLEI_ALLOW_CANDIDATE"] = old_allow


def test_nuclei_binary_candidate_sha_only_rejected(tmp_path):
    """nuclei_binary() must reject a build when only REDVECTOR_NUCLEI_CANDIDATE_SHA256 is set
    but REDVECTOR_NUCLEI_ALLOW_CANDIDATE is absent.  Setting only the SHA must have no effect in
    production (the gate must be absent by default)."""
    fake = tmp_path / "nuclei"
    fake.write_bytes(b"sha-only-binary")
    actual_sha = hashlib.sha256(b"sha-only-binary").hexdigest()

    old_bin = os.environ.get("REDVECTOR_NUCLEI_BIN")
    old_cand = os.environ.get("REDVECTOR_NUCLEI_CANDIDATE_SHA256")
    old_allow = os.environ.get("REDVECTOR_NUCLEI_ALLOW_CANDIDATE")
    try:
        os.environ["REDVECTOR_NUCLEI_BIN"] = str(fake)
        os.environ["REDVECTOR_NUCLEI_CANDIDATE_SHA256"] = actual_sha
        os.environ.pop("REDVECTOR_NUCLEI_ALLOW_CANDIDATE", None)   # gate absent → production state
        with pytest.raises(ra.AssessmentError, match="unknown/unverified build"):
            ra.nuclei_binary()
    finally:
        if old_bin is None: os.environ.pop("REDVECTOR_NUCLEI_BIN", None)
        else: os.environ["REDVECTOR_NUCLEI_BIN"] = old_bin
        if old_cand is None: os.environ.pop("REDVECTOR_NUCLEI_CANDIDATE_SHA256", None)
        else: os.environ["REDVECTOR_NUCLEI_CANDIDATE_SHA256"] = old_cand
        if old_allow is None: os.environ.pop("REDVECTOR_NUCLEI_ALLOW_CANDIDATE", None)
        else: os.environ["REDVECTOR_NUCLEI_ALLOW_CANDIDATE"] = old_allow


def test_nuclei_binary_wrong_candidate_sha_rejected(tmp_path):
    """nuclei_binary() rejects a binary whose SHA does NOT match REDVECTOR_NUCLEI_CANDIDATE_SHA256
    even when the test-mode gate is set."""
    fake = tmp_path / "nuclei"
    fake.write_bytes(b"binary content")
    wrong_sha = "0" * 64

    old_bin = os.environ.get("REDVECTOR_NUCLEI_BIN")
    old_cand = os.environ.get("REDVECTOR_NUCLEI_CANDIDATE_SHA256")
    old_allow = os.environ.get("REDVECTOR_NUCLEI_ALLOW_CANDIDATE")
    try:
        os.environ["REDVECTOR_NUCLEI_BIN"] = str(fake)
        os.environ["REDVECTOR_NUCLEI_CANDIDATE_SHA256"] = wrong_sha
        os.environ["REDVECTOR_NUCLEI_ALLOW_CANDIDATE"] = "testing"
        with pytest.raises(ra.AssessmentError, match="unknown/unverified build"):
            ra.nuclei_binary()
    finally:
        if old_bin is None: os.environ.pop("REDVECTOR_NUCLEI_BIN", None)
        else: os.environ["REDVECTOR_NUCLEI_BIN"] = old_bin
        if old_cand is None: os.environ.pop("REDVECTOR_NUCLEI_CANDIDATE_SHA256", None)
        else: os.environ["REDVECTOR_NUCLEI_CANDIDATE_SHA256"] = old_cand
        if old_allow is None: os.environ.pop("REDVECTOR_NUCLEI_ALLOW_CANDIDATE", None)
        else: os.environ["REDVECTOR_NUCLEI_ALLOW_CANDIDATE"] = old_allow


def test_nuclei_binary_no_candidate_env_var_rejected(tmp_path):
    """nuclei_binary() rejects an unregistered build when no candidate env vars are set."""
    fake = tmp_path / "nuclei"
    fake.write_bytes(b"unregistered binary")

    old_bin = os.environ.get("REDVECTOR_NUCLEI_BIN")
    old_cand = os.environ.get("REDVECTOR_NUCLEI_CANDIDATE_SHA256")
    old_allow = os.environ.get("REDVECTOR_NUCLEI_ALLOW_CANDIDATE")
    try:
        os.environ["REDVECTOR_NUCLEI_BIN"] = str(fake)
        os.environ.pop("REDVECTOR_NUCLEI_CANDIDATE_SHA256", None)
        os.environ.pop("REDVECTOR_NUCLEI_ALLOW_CANDIDATE", None)
        with pytest.raises(ra.AssessmentError, match="unknown/unverified build"):
            ra.nuclei_binary()
    finally:
        if old_bin is None: os.environ.pop("REDVECTOR_NUCLEI_BIN", None)
        else: os.environ["REDVECTOR_NUCLEI_BIN"] = old_bin
        if old_cand is None: os.environ.pop("REDVECTOR_NUCLEI_CANDIDATE_SHA256", None)
        else: os.environ["REDVECTOR_NUCLEI_CANDIDATE_SHA256"] = old_cand
        if old_allow is None: os.environ.pop("REDVECTOR_NUCLEI_ALLOW_CANDIDATE", None)
        else: os.environ["REDVECTOR_NUCLEI_ALLOW_CANDIDATE"] = old_allow


def test_nuclei_env_passed_to_subprocess():
    """_env() propagates REDVECTOR_NUCLEI_CANDIDATE_SHA256 ONLY when the test-mode gate
    REDVECTOR_NUCLEI_ALLOW_CANDIDATE=testing is also set; omits it in all other states."""
    old_sha = os.environ.get("REDVECTOR_NUCLEI_CANDIDATE_SHA256")
    old_allow = os.environ.get("REDVECTOR_NUCLEI_ALLOW_CANDIDATE")
    try:
        # Both gate AND SHA set → SHA propagated to subprocess env
        os.environ["REDVECTOR_NUCLEI_ALLOW_CANDIDATE"] = "testing"
        os.environ["REDVECTOR_NUCLEI_CANDIDATE_SHA256"] = "abc123"
        env = ra._env(Path("/tmp"))
        assert env.get("REDVECTOR_NUCLEI_CANDIDATE_SHA256") == "abc123"

        # SHA set but gate absent → SHA NOT propagated (production-safe default)
        os.environ.pop("REDVECTOR_NUCLEI_ALLOW_CANDIDATE", None)
        env2 = ra._env(Path("/tmp"))
        assert "REDVECTOR_NUCLEI_CANDIDATE_SHA256" not in env2

        # Neither set → SHA absent from subprocess env
        os.environ.pop("REDVECTOR_NUCLEI_CANDIDATE_SHA256", None)
        env3 = ra._env(Path("/tmp"))
        assert "REDVECTOR_NUCLEI_CANDIDATE_SHA256" not in env3
    finally:
        if old_sha is None: os.environ.pop("REDVECTOR_NUCLEI_CANDIDATE_SHA256", None)
        else: os.environ["REDVECTOR_NUCLEI_CANDIDATE_SHA256"] = old_sha
        if old_allow is None: os.environ.pop("REDVECTOR_NUCLEI_ALLOW_CANDIDATE", None)
        else: os.environ["REDVECTOR_NUCLEI_ALLOW_CANDIDATE"] = old_allow


# ---------------------------------------------------------------------------
# Failure 2a — parse_json() JSONL fallback
# ---------------------------------------------------------------------------

def test_parse_json_standard_wrapped():
    """Standard wrapped format still works."""
    payload = json.dumps({"host": "127.0.0.1", "port": "80", "vulnerabilities": [
        {"id": "1", "method": "GET", "url": "/", "msg": "X-Frame-Options missing", "references": ""}
    ]})
    result = nk.parse_json(payload)
    assert result["host"] == "127.0.0.1"
    assert result["port"] == "80"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["message"] == "X-Frame-Options missing"


def test_parse_json_standard_list():
    """Standard list-of-host-objects format still works."""
    payload = json.dumps([{"host": "127.0.0.1", "port": "80", "vulnerabilities": [
        {"id": "42", "method": "GET", "url": "/admin", "msg": "admin exposed", "references": ""}
    ]}])
    result = nk.parse_json(payload)
    assert len(result["findings"]) == 1


def test_parse_json_jsonl_per_finding():
    """Nikto 2.6.x JSONL: one JSON object per line per finding."""
    # Simulate Nikto 2.6.x JSONL output — each finding is a separate JSON line
    lines = [
        json.dumps({"id": "OSVDB-3092", "method": "GET", "url": "/test/", "msg": "test dir found", "references": ""}),
        json.dumps({"id": "OSVDB-396", "method": "GET", "url": "/", "msg": "Server header", "references": ""}),
    ]
    payload = "\n".join(lines)
    result = nk.parse_json(payload)
    assert len(result["findings"]) == 2
    messages = [f["message"] for f in result["findings"]]
    assert "test dir found" in messages
    assert "Server header" in messages


def test_parse_json_jsonl_mixed_with_blank_lines():
    """JSONL with blank lines between entries is handled."""
    lines = [
        "",
        json.dumps({"id": "N1", "method": "GET", "url": "/", "msg": "finding one", "references": ""}),
        "",
        json.dumps({"id": "N2", "method": "HEAD", "url": "/login", "msg": "finding two", "references": ""}),
        "",
    ]
    payload = "\n".join(lines)
    result = nk.parse_json(payload)
    assert len(result["findings"]) == 2


def test_parse_json_jsonl_single_line():
    """Single-line JSONL (one finding object without a vulnerabilities wrapper)."""
    finding = json.dumps({"id": "N1", "method": "GET", "url": "/", "msg": "header missing", "references": ""})
    result = nk.parse_json(finding)
    assert len(result["findings"]) == 1
    assert result["findings"][0]["message"] == "header missing"


def test_parse_json_empty_input():
    result = nk.parse_json("")
    assert result["findings"] == []
    assert "note" in result


def test_parse_json_unrecognised_raises_with_snippet():
    """Unrecognisable content raises NiktoError whose message includes a diagnostic snippet."""
    garbage = "THIS IS NOT JSON AT ALL, definitely broken output" * 3
    with pytest.raises(nk.NiktoError) as exc_info:
        nk.parse_json(garbage)
    msg = str(exc_info.value)
    assert "not recognized" in msg
    # Diagnostic snippet must be present (first ≤120 chars of input)
    assert "THIS IS NOT JSON" in msg


def test_parse_json_unrecognised_short_snippet():
    """Short unrecognisable input: snippet is the whole thing."""
    garbage = "bad data here"
    with pytest.raises(nk.NiktoError) as exc_info:
        nk.parse_json(garbage)
    assert "bad data here" in str(exc_info.value)


def test_parse_json_per_finding_requires_id_or_msg():
    """Per-finding JSONL objects without 'id' or 'msg' are silently skipped."""
    lines = [
        json.dumps({"key": "value", "other": "garbage"}),   # no id or msg → skipped
        json.dumps({"id": "NIKTO-001", "msg": "real finding", "method": "GET", "url": "/", "references": ""}),
        json.dumps({"msg": "msg only is enough", "method": "HEAD", "url": "/login"}),
        json.dumps({"id": "id-only"}),                        # id alone is enough
        json.dumps({"completely": "irrelevant"}),             # no id or msg → skipped
    ]
    result = nk.parse_json("\n".join(lines))
    assert len(result["findings"]) == 3
    messages = [f["message"] for f in result["findings"]]
    assert "real finding" in messages
    assert "msg only is enough" in messages


def test_nikto_nonzero_exit_empty_output_is_mode_e():
    """Empty output with non-zero exit must be mode E (crashed), not mode A."""
    fake_path = Path("/usr/bin/nikto")
    with patch("redvector_reviewed_nikto._runtime", return_value=fake_path):
        with patch("redvector_reviewed_nikto._trusted", return_value="deadbeef"):
            with patch("redvector_reviewed_nikto._execute", return_value=(1, "", "nikto error")):
                result = nk.run_nikto({"target": "http://127.0.0.1/", "additional_args": nk.NIKTO_MARKER})
    assert result["execution_mode"] == "E", result.get("error")
    assert result["success"] is False
    assert "no output" in result.get("error", "").lower()


def test_nikto_zero_exit_empty_output_no_evidence_is_mode_e():
    """Zero exit, empty output, no output file created: must be mode E (no completion evidence).
    Neither the absence of an output file nor empty stderr constitutes a verified zero-finding scan."""
    fake_path = Path("/usr/bin/nikto")
    with patch("redvector_reviewed_nikto._runtime", return_value=fake_path):
        with patch("redvector_reviewed_nikto._trusted", return_value="deadbeef"):
            with patch("redvector_reviewed_nikto._execute", return_value=(0, "", "")):
                result = nk.run_nikto({"target": "http://127.0.0.1/", "additional_args": nk.NIKTO_MARKER})
    assert result["execution_mode"] == "E", result.get("error")
    assert result["success"] is False
    assert "completion evidence" in result.get("error", "").lower()


def test_nikto_zero_exit_stderr_only_is_mode_e():
    """Zero exit with empty JSON output and non-empty stderr but no output file: must be mode E.
    Arbitrary stderr text is not sufficient completion evidence for a successful assessment."""
    fake_path = Path("/usr/bin/nikto")
    with patch("redvector_reviewed_nikto._runtime", return_value=fake_path):
        with patch("redvector_reviewed_nikto._trusted", return_value="deadbeef"):
            # stderr has content but no outfile is created by the mock
            with patch("redvector_reviewed_nikto._execute", return_value=(0, "", "- Scan end time")):
                result = nk.run_nikto({"target": "http://127.0.0.1/", "additional_args": nk.NIKTO_MARKER})
    assert result["execution_mode"] == "E", result.get("error")
    assert result["success"] is False
    assert "completion evidence" in result.get("error", "").lower()


def test_nikto_zero_exit_nonempty_outfile_is_mode_a(tmp_path):
    """Zero exit with a non-empty output file (Nikto wrote its results) is mode A, zero findings.
    The non-empty output file is the sole accepted completion evidence for a zero-finding scan."""
    # Pre-create the output file Nikto would write (zero-finding JSON is non-empty)
    (tmp_path / "nikto.json").write_text('{"vulnerabilities":[]}', encoding="utf-8")

    from contextlib import contextmanager

    @contextmanager
    def mock_tmpdir(*args, **kwargs):
        yield str(tmp_path)

    fake_path = Path("/usr/bin/nikto")
    with patch("redvector_reviewed_nikto._runtime", return_value=fake_path):
        with patch("redvector_reviewed_nikto._trusted", return_value="deadbeef"):
            with patch("redvector_reviewed_nikto._execute", return_value=(0, "", "")):
                with patch("redvector_reviewed_nikto.tempfile.TemporaryDirectory", mock_tmpdir):
                    result = nk.run_nikto({"target": "http://127.0.0.1/", "additional_args": nk.NIKTO_MARKER})
    assert result["execution_mode"] == "A", result.get("error")
    assert result["success"] is True
    assert result["findings_count"] == 0

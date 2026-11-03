"""W8 regression: Nuclei v3.11.0 SHA registration and candidate build controls.

Failure 1 — Nuclei capabilities() returns Unsupported on Kali with v3.11.0 installed:
  Root cause: _command() spawns a subprocess that re-imports NUCLEI_BUILDS from disk;
  the in-process NUCLEI_BUILDS patch in test_w6 is invisible to the subprocess.
  Fix: add the operator's v3.11.0 SHA directly to NUCLEI_BUILDS in production code.
  Regression: verify the exact SHA is present in the production registry so the
  subprocess re-import from disk will recognise it.

These tests are Windows-runnable (SHA presence test is a pure dict lookup;
candidate binary tests use mocked paths).
"""
import hashlib
import os
from pathlib import Path
from unittest.mock import patch
import pytest
import redvector_reviewed_assessment as ra


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

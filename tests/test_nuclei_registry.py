"""Nuclei reviewed-build registry: version parsing, checksum identity, and the separation of
binary identity/integrity from version compatibility. No Kali and no real nuclei binary required;
the binary is a temp file and its digest is substituted. No operator version is a global
requirement — each build is listed on its own verified checksum."""
import os
from pathlib import Path
import pytest
import redvector_reviewed_assessment as a


def test_nuclei_version_parses_across_banners():
    assert a.nuclei_version(b"Nuclei Engine Version: v3.11.0") == "v3.11.0"
    assert a.nuclei_version("projectdiscovery.io\n\tv3.11.1\n") == "v3.11.1"
    assert a.nuclei_version(b"3.12.4") == "v3.12.4"
    assert a.nuclei_version(b"\x1b[36m v3.10.5 \x1b[0m") == "v3.10.5"
    assert a.nuclei_version(b"no version here") == ""


def _bin(tmp_path, data=b"ELFBINARY"):
    path = tmp_path / "nuclei"
    path.write_bytes(data)
    return path


def test_registry_hit_returns_path_and_metadata(tmp_path, monkeypatch):
    binary = _bin(tmp_path)
    known = next(iter(a.NUCLEI_BUILDS))                       # the seeded reviewed build sha
    monkeypatch.setattr(a, "digest", lambda path: known)
    monkeypatch.setenv("REDVECTOR_NUCLEI_BIN", str(binary))
    path, meta = a.nuclei_binary()
    assert path == binary
    assert meta["version"] == a.NUCLEI_BUILDS[known]["version"]
    assert meta["sha256"] == known                            # identity recorded
    assert "capabilities" in meta and "platform" in meta      # compat metadata separate from identity


def test_unknown_checksum_is_unsupported_not_bypassed(tmp_path, monkeypatch):
    binary = _bin(tmp_path)
    monkeypatch.setattr(a, "digest", lambda path: "0" * 64)   # not in the registry
    monkeypatch.setenv("REDVECTOR_NUCLEI_BIN", str(binary))
    with pytest.raises(a.AssessmentError) as exc:
        a.nuclei_binary()
    msg = str(exc.value)
    assert "unknown/unverified build" in msg
    assert "attestation is not bypassed" in msg.lower()


def test_missing_binary_is_missing_dependency(monkeypatch):
    monkeypatch.delenv("REDVECTOR_NUCLEI_BIN", raising=False)
    monkeypatch.setattr(a.shutil, "which", lambda name: None)
    with pytest.raises(a.AssessmentError) as exc:
        a.nuclei_binary()
    assert "Missing Dependency" in str(exc.value)


def test_symlink_or_nonfile_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("REDVECTOR_NUCLEI_BIN", str(tmp_path / "does-not-exist"))
    with pytest.raises(a.AssessmentError) as exc:
        a.nuclei_binary()
    assert "absolute, non-symlink regular-file" in str(exc.value)


def test_multiple_reviewed_builds_resolve_independently(tmp_path, monkeypatch):
    # A second individually-reviewed build (different checksum, different version) is usable on its
    # own merits — not by trusting a version range.
    second = "a" * 64
    registry = dict(a.NUCLEI_BUILDS)
    registry[second] = {"version": "v3.11.0", "platform": "linux/amd64",
                        "capabilities": ["offline-root-response-header-templates"],
                        "template_requirements": "fixed", "evidence": "fixture"}
    monkeypatch.setattr(a, "NUCLEI_BUILDS", registry)
    binary = _bin(tmp_path)
    monkeypatch.setattr(a, "digest", lambda path: second)
    monkeypatch.setenv("REDVECTOR_NUCLEI_BIN", str(binary))
    _, meta = a.nuclei_binary()
    assert meta["version"] == "v3.11.0" and meta["sha256"] == second


def test_version_banner_mismatch_is_detected_in_capabilities(tmp_path, monkeypatch):
    # capabilities() binds the recorded version to the live -version banner; a mismatch fails closed.
    from types import SimpleNamespace
    binary = _bin(tmp_path)
    known = next(iter(a.NUCLEI_BUILDS))
    monkeypatch.setattr(a, "digest", lambda path: known)
    monkeypatch.setenv("REDVECTOR_NUCLEI_BIN", str(binary))
    monkeypatch.setattr(a.sys, "platform", "linux")
    monkeypatch.setattr(a.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(a, "_command", lambda b, args, d: SimpleNamespace(returncode=0, stdout=b"v9.9.9", stderr=b""))
    state = a.capabilities()[a.NUCLEI_PROFILE]
    assert state["state"] == "Unsupported"
    assert "does not match" in state["detail"]

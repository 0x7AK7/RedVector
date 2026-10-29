"""Policy authorization + runtime attestation for the reviewed native Searchsploit adapter.
No target is hardcoded (searchsploit is an offline local DB lookup with no network destination)."""
from pathlib import Path
from unittest.mock import Mock, patch
import pytest
from redvector_ollama_policy import Policy, PolicyError, SEARCHSPLOIT_TOOLS, REVIEWED
from redvector_reviewed_searchsploit import SEARCHSPLOIT_MARKER, PROFILE
from redvector_ollama_backend import BackendProof, BackendReuseError
from redvector_ollama_profiles import attest


def _policy():
    p = Policy()                                   # no scope needed: offline local lookup
    p.profile_status = {PROFILE: {"state": "Ready"}}
    return p


def test_searchsploit_is_a_reviewed_low_impact_tool():
    assert "searchsploit_lookup" in SEARCHSPLOIT_TOOLS
    assert SEARCHSPLOIT_TOOLS <= REVIEWED


def test_authorize_injects_marker_and_forces_read_only_without_prompt():
    p = _policy(); approve = Mock(side_effect=AssertionError("read-only lookup must not prompt"))
    result = p.authorize("searchsploit_lookup", {"query": "apache 2.4", "exact": True}, approve)
    assert result["additional_args"] == SEARCHSPLOIT_MARKER   # reserved marker injected
    assert result["json_output"] is True and result["mirror"] == ""  # forced read-only JSON
    assert result["query"] == "apache 2.4" and result["exact"] is True
    approve.assert_not_called()


def test_authorize_accepts_cve_only_request():
    result = _policy().authorize("searchsploit_lookup", {"cve": "CVE-2021-44228"}, lambda _: True)
    assert result["cve"] == "CVE-2021-44228" and result["additional_args"] == SEARCHSPLOIT_MARKER


@pytest.mark.parametrize("args,needle", [
    ({}, "query or CVE"),                                     # nothing to search
    ({"query": "apache", "mirror": "50383"}, "read-only"),  # mirroring disabled
    ({"query": "apache", "exact": "yes"}, "boolean"),        # non-bool flag
    ({"query": "apache", "unexpected": 1}, "Unexpected"),    # extra arg
])
def test_authorize_rejects_disallowed_inputs(args, needle):
    with pytest.raises(PolicyError) as exc:
        _policy().authorize("searchsploit_lookup", args, lambda _: True)
    assert needle.lower() in str(exc.value).lower()


def test_authorize_blocked_when_profile_not_ready():
    p = Policy(); p.profile_status = {PROFILE: {"state": "Missing Dependency", "detail": "no binary"}}
    with pytest.raises(PolicyError, match="unavailable"):
        p.authorize("searchsploit_lookup", {"query": "apache"}, lambda _: True)


def _proof():
    return BackendProof(1, 2.0, Path("python"), Path("other/redvector_server.py"), Path("other"))


def test_attestation_requires_matching_searchsploit_module_hash():
    p = _proof()
    metadata = {"profiles": {"searchsploit-v1": {"state": "Ready"}}, "module_sha256": b"source".hex(),
                "modules_sha256": {"redvector_reviewed_searchsploit.py": "wrong"}}
    with patch("redvector_ollama_profiles.inspect_backend", return_value=p), \
         patch("redvector_ollama_profiles._source_start_limit", return_value=2), \
         patch("redvector_ollama_profiles._script_path", side_effect=lambda path, s: path), \
         patch("redvector_ollama_profiles._source", return_value=b"source"):
        # a mismatched reviewed-module hash fails closed (never bypassed)
        with pytest.raises(BackendReuseError, match="Searchsploit profile source"):
            attest(p, metadata, Path("."), 8888)
        # a matching hash attests the profile as Ready
        metadata["modules_sha256"]["redvector_reviewed_searchsploit.py"] = b"source".hex()
        states = attest(p, metadata, Path("."), 8888)
        assert states["searchsploit-v1"]["state"] == "Ready"

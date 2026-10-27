"""An explicitly reviewed old backend retains discovery, never new profile trust."""
import hashlib
from pathlib import Path
from unittest.mock import patch
import pytest
import test_ollama_backend as backend_tests
from redvector_ollama_backend import BackendReuseError
from redvector_ollama_profiles import attest

def test_known_legacy_source_does_not_relax_banner_or_unknown_source_checks():
    fixture=backend_tests.CompatibleBackendTests();fixture.setUp()
    try:
        old=b"# explicitly reviewed old backend\n"
        (fixture.other/"redvector_server.py").write_bytes(old)
        digest=hashlib.sha256(old).hexdigest()
        with patch("redvector_ollama_backend.LEGACY_BACKEND_SHA256",digest):
            proof=fixture.inspect()
            assert proof.script.parent==fixture.other
            (fixture.other/"redvector_banner.py").write_bytes(b"# unrelated banner\n")
            with pytest.raises(BackendReuseError):fixture.inspect()
            (fixture.other/"redvector_banner.py").write_bytes(b"# trusted banner\n")
            (fixture.other/"redvector_server.py").write_bytes(old+b"# changed\n")
            with pytest.raises(BackendReuseError):fixture.inspect()
    finally:fixture.doCleanups()

def test_legacy_backend_cannot_claim_new_profile_without_module():
    fixture=backend_tests.CompatibleBackendTests();fixture.setUp()
    try:
        proof=fixture.inspect()
        with patch("redvector_ollama_profiles.inspect_backend",return_value=proof),patch("redvector_ollama_profiles._source_start_limit",return_value=10**12):
            with pytest.raises((BackendReuseError,OSError)):
                attest(proof,{"profiles":{"service-version-v1":{"state":"Ready"}}},fixture.current,8888)
    finally:fixture.doCleanups()

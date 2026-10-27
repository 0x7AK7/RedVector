"""No network in installer regression tests; real pinned binary exercised natively."""
import hashlib
from unittest.mock import patch
import pytest
import tools.install_reviewed_nuclei as install

def test_existing_different_binary_is_never_overwritten(tmp_path):
    target=tmp_path/"nuclei";target.write_bytes(b"existing operator binary")
    with patch.object(install.sys,"platform","linux"),patch.object(install.platform,"machine",return_value="x86_64"),patch.object(install.urllib.request,"urlopen",side_effect=AssertionError("No download")):
        with pytest.raises(ValueError,match="nothing was overwritten"):install.install(tmp_path)
    assert target.read_bytes()==b"existing operator binary"

def test_verified_existing_binary_is_reused_without_download(tmp_path):
    target=tmp_path/"nuclei";payload=b"verified fixture";target.write_bytes(payload);before=target.stat().st_mtime_ns
    with patch.object(install.sys,"platform","linux"),patch.object(install.platform,"machine",return_value="x86_64"),patch.object(install,"BINARY_SHA256",hashlib.sha256(payload).hexdigest()),patch.object(install.urllib.request,"urlopen",side_effect=AssertionError("No download")):
        assert install.install(tmp_path)==target
    assert target.stat().st_mtime_ns==before

"""Expanded application probes remain bounded and source-derived."""
import pytest
import redvector_reviewed_profiles as p

def test_service_profile_supports_128_explicit_ports():
    params=dict(target="192.0.2.15",ports="1-128",scan_type=p.NMAP_PROFILE,additional_args="--version-intensity 1",use_recovery=False)
    assert p._validate("nmap_scan",params)[1].split(",")[-1]=="128"
    params["ports"]="1-129"
    with pytest.raises(p.ProfileError):p._validate("nmap_scan",params)

def test_banner_coverage_does_not_add_protocol_commands():
    assert "ProFTPD" in p._PROBES and "Postfix" in p._PROBES
    assert p._PROBES.count("Probe TCP")==2
    assert "USER " not in p._PROBES and "EHLO " not in p._PROBES

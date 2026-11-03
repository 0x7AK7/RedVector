"""Reviewed full-range TCP discovery profile: XML state parsing, bounds and policy routing."""
import pytest
import redvector_reviewed_profiles as p

SAMPLE_XML=('<?xml version="1.0"?><nmaprun><host><status state="up"/>'
            '<address addr="192.168.5.130" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>'
            '<port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port>'
            '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>'
            '<port protocol="tcp" portid="81"><state state="filtered"/></port>'
            '</ports></host><runstats><finished exit="success" summary="done"/></runstats></nmaprun>')

def test_parse_discovery_states():
    r=p.parse_discovery_xml(SAMPLE_XML)
    assert r["host_state"]=="up" and r["target"]=="192.168.5.130"
    states={e["port"]:e["state"] for e in r["ports"]}
    assert states=={"22":"open","23":"closed","80":"open","81":"filtered"}
    assert {e["port"] for e in r["open_ports"]}=={"22","80"}
    assert r["state_counts"]=={"open":2,"closed":1,"filtered":1}
    assert r["scan_complete"] and all("port-name-guess" in e["confidence"] for e in r["ports"])

def test_parse_discovery_rejects_xxe():
    with pytest.raises(p.ProfileError):
        p.parse_discovery_xml('<!DOCTYPE nmaprun [<!ENTITY x "y">]><nmaprun></nmaprun>')

def test_discovery_validation_bounds():
    base=dict(scan_type=p.DISCOVERY_PROFILE,additional_args="",use_recovery=False)
    t,spec,count,ver=p._validate_discovery("nmap_scan",dict(base,target="192.168.5.130",ports="1-65535"))
    assert spec=="1-65535" and count==65535 and ver==4
    t,spec,count,ver=p._validate_discovery("nmap_scan",dict(base,target="192.168.5.130",ports="-"))
    assert spec=="1-65535" and count==65535
    for bad in [dict(base,target="not-an-ip",ports="1-100"),
                dict(base,target="192.168.5.130",ports=""),
                dict(base,target="192.168.5.130",ports="1-70000"),
                dict(base,target="192.168.5.130",ports="80",additional_args="-sS"),
                dict(base,target="192.168.5.130",ports="80",scan_type="--redvector-profile=service-version-v1")]:
        with pytest.raises(p.ProfileError):p._validate_discovery("nmap_scan",bad)


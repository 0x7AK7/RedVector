"""Dynamic, target-agnostic scope/authorization parsing regression tests.

Uses RFC 5737 TEST-NET and documentation ranges and loopback; no production target is
hardcoded. An operator lab address may be injected via RV_LAB_TARGET purely as an optional
extra acceptance input, never as a constant the tests depend on.
"""
import os
import ipaddress
import pytest
from redvector_ollama_cli import assessment_context, _looks_like_target, _named_unknown_host
from redvector_ollama_policy import Policy

V4="192.0.2.10"            # TEST-NET-1
V4_OTHER="198.51.100.23"   # TEST-NET-2 (out of scope)
CIDR="192.0.2.0/24"
HOST="lab.example"         # documentation hostname
RESOLVE=lambda name:["192.0.2.10"]  # deterministic stub; no real DNS

def ctx(scope,text,resolver=None):
    return assessment_context(text,Policy(scope,resolver=resolver))

@pytest.mark.parametrize("phrase",[
    "do a full port scan of {t} ports 1-65535",
    "scan {t} for all TCP ports 1-65535 and identify services",
    "please perform a comprehensive scan of {t} across all 65535 tcp ports",
    "run a vulnerability assessment against {t}",
    "scan {t} ports 80,443,8080",
])
def test_scoped_ipv4_is_accepted_without_false_rejection(phrase):
    ok,target,clar=ctx([V4],phrase.format(t=V4))
    # Either a scan target was chosen, or (for the non-scan 'assessment' verb) it is not an
    # out-of-scope rejection; never a false scope block for the scoped host.
    assert clar is None or "outside" not in clar
    if ok and "scan" in phrase:assert target==V4

def test_genuinely_out_of_scope_ipv4_is_rejected():
    ok,target,clar=ctx([V4],f"scan {V4_OTHER} for open ports")
    assert target is None and clar and "outside" in clar

def test_second_named_target_is_rejected_not_silently_scanned():
    ok,target,clar=ctx([V4],f"scan {V4} and also scan {V4_OTHER}")
    assert clar and "outside" in clar

@pytest.mark.parametrize("token,is_target",[
    ("65535",False),("1-65535",False),("80,443",False),("of",False),("full",False),
    ("ports:",False),("intranet",False),("7.2p2",False),
    ("192.0.2.10",True),("192.0.2.0/24",True),("lab.example",True),("fe80::1",True),("::1",True),
])
def test_only_destination_shaped_tokens_are_targets(token,is_target):
    assert _looks_like_target(token) is is_target

def test_port_number_65535_is_never_a_host():
    ok,target,clar=ctx([V4],f"scan {V4} for tcp port 65535")
    assert (clar is None or "outside" not in clar) and (target==V4 or target is None)

def test_ordinary_words_do_not_invent_targets():
    # Ordinary words after 'scan' (prepositions/determiners/domain nouns) must not be read as
    # named hosts; only a real label immediately after a scan verb is a named operand.
    assert _named_unknown_host("do a full port scan of the authorized host",set())==[]
    assert _named_unknown_host("scan all 65535 tcp ports and identify services",set())==[]
    assert _named_unknown_host("scan intranet for ports",set())==["intranet"]

def test_named_unknown_single_label_host_is_denied():
    ok,target,clar=ctx([V4],"scan intranet for open ports")
    assert clar and "outside" in clar

def test_host_inside_authorized_cidr_is_accepted():
    ok,target,clar=ctx([CIDR],f"scan {V4} for open ports")
    assert target==V4

def test_ipv6_loopback_scope_round_trips():
    ok,target,clar=ctx(["::1"],"scan ::1 for open ports")
    assert target=="::1"

def test_hostname_scope_accepts_named_host():
    ok,target,clar=ctx([HOST],f"scan {HOST} for open tcp ports",resolver=RESOLVE)
    assert target==HOST and (clar is None or "outside" not in clar)

def test_scope_change_invalidates_stale_authorization_state():
    pol=Policy([V4])
    assert assessment_context(f"scan {V4}",pol)[1]==V4
    pol.replace_scope([V4_OTHER])  # operator re-scopes
    ok,target,clar=assessment_context(f"scan {V4}",pol)  # old host now out of scope
    assert clar and "outside" in clar
    assert assessment_context(f"scan {V4_OTHER}",pol)[1]==V4_OTHER

@pytest.mark.skipif(not os.environ.get("RV_LAB_TARGET"),reason="optional operator lab target not provided")
def test_optional_operator_lab_target_is_accepted_when_scoped():
    lab=os.environ["RV_LAB_TARGET"]
    try:ipaddress.ip_address(lab)
    except ValueError:pytest.skip("RV_LAB_TARGET is not a numeric host")
    ok,target,clar=ctx([lab],f"do a full port scan of {lab} ports 1-65535")
    assert target==lab and (clar is None or "outside" not in clar)

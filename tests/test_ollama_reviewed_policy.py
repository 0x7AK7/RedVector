import io
import json
from unittest.mock import Mock
import pytest
from redvector_ollama_policy import Policy,PolicyError
from redvector_ollama_setup import Terminal
from redvector_ollama_presentation import approval_panel
from redvector_reviewed_profiles import NMAP_PROFILE

HOST="192.0.2.15"

def test_automatic_discovery_keeps_limits_and_no_prompt():
    policy=Policy([HOST],clock=lambda:0)
    approval=Mock(return_value=False)
    result=policy.authorize("nmap_scan",{"target":HOST,"ports":"1-1000"},approval)
    assert policy.last_automatic and policy.auto_count==1
    approval.assert_not_called()
    assert "--max-rate 50" in result["additional_args"]

@pytest.mark.parametrize("settings,words",[
    ({"auto_count":5},"session limit"),
    ({"last_auto":0},"cooldown"),
    ({"auto_discovery":False},"disabled"),
])
def test_additional_approval_explains_actual_reason(settings,words):
    policy=Policy([HOST],clock=lambda:0)
    for key,value in settings.items():setattr(policy,key,value)
    calls=[]
    with pytest.raises(PolicyError):
        policy.authorize("nmap_scan",{"target":HOST,"ports":"80"},lambda operation:calls.append(operation) or False)
    assert words in calls[0]["reason"].lower()
    assert policy.auto_count==settings.get("auto_count",0)

def test_larger_scan_and_unselected_discovery_need_exact_reasons():
    for ports,automatic,word in [("1-1001",True,"1,000"),("80",False,"explicit")]:
        calls=[];policy=Policy([HOST])
        with pytest.raises(PolicyError):
            policy.authorize("nmap_scan",{"target":HOST,"ports":ports},
                lambda op:calls.append(op) or False,allow_automatic=automatic)
        assert word in calls[0]["reason"]

def test_reviewed_service_version_requires_verified_capability_then_runs_under_scope():
    policy=Policy([HOST])
    with pytest.raises(PolicyError,match="profile"):
        policy.authorize("nmap_scan",{"target":HOST,"scan_type":"-sT -sV","ports":"80"},lambda _:True)
    policy.profile_status={"service-version-v1":{"state":"Ready"}}
    policy.version_intensity=2;calls=[]
    # Without a task authorization the reviewed service-version profile prompts (scope alone is not
    # enough); inside a bounded detection task it runs without a repeated prompt.
    actual=policy.authorize("nmap_scan",{"target":HOST,"scan_type":"-sT -sV","ports":"80"},
        lambda operation:calls.append(operation) or True)
    assert actual["scan_type"]==NMAP_PROFILE
    assert actual["additional_args"]=="--version-intensity 2"
    assert actual["use_recovery"] is False
    assert len(calls)==1 and "service-version detection" in calls[0]["reason"].lower()
    policy.begin_task(HOST,1000,{"discovery","service-version"},lambda operation:True,"bounded task")
    calls2=[]
    policy.authorize("nmap_scan",{"target":HOST,"scan_type":"-sT -sV","ports":"80"},
        lambda operation:calls2.append(operation) or True)
    assert calls2==[] and policy.last_automatic is True and policy.auto_count==0
    policy.end_task()

def test_reviewed_service_version_without_scope_still_prompts():
    policy=Policy()                      # no authorized scope
    policy.profile_status={"service-version-v1":{"state":"Ready"}};policy.version_intensity=1;calls=[]
    # _destination requires scope; with no scope the reviewed path refuses before any approval,
    # so the low-impact pre-authorization never applies without an explicit operator scope.
    with pytest.raises(PolicyError):
        policy.authorize("nmap_scan",{"target":HOST,"scan_type":"-sT -sV","ports":"80"},lambda operation:calls.append(operation) or True)

@pytest.mark.parametrize("args",[
    {"scan_type":"-sT -sV","ports":"1-129"},
    {"scan_type":"-sT -sV","ports":""},
    {"scan_type":"-sU","ports":"53"},{"scan_type":"-O","ports":"80"},
    {"scan_type":"-sC","ports":"80"},{"additional_args":"--script vuln","ports":"80"}
])
def test_unsupported_nmap_profiles_stay_blocked(args):
    policy=Policy([HOST]);policy.profile_status={"service-version-v1":{"state":"Ready"}}
    with pytest.raises(PolicyError):policy.authorize("nmap_scan",dict(target=HOST,**args),lambda _:True)

def test_version_does_not_allow_other_target_or_intensity():
    policy=Policy([HOST]);policy.profile_status={"service-version-v1":{"state":"Ready"}}
    policy.version_intensity=3
    for target in [HOST,"192.0.2.99"]:
        with pytest.raises(PolicyError):policy.authorize("nmap_scan",{"target":target,"ports":"80","scan_type":"-sV"},lambda _:True)

def test_approval_panel_is_actionable_without_repetitive_sentence():
    term=Terminal(io.StringIO())
    approval_panel(term,{"tool":"nmap_scan","arguments":{"target":HOST,"ports":"1-1001"},"reason":"Port count exceeds 1,000"})
    text=term.stream.getvalue()
    assert "Port count exceeds 1,000" in text and "APPROVE" in text and "DENY" in text
    assert "Selection is not authorization" not in text

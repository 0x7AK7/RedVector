import pytest
from redvector_ollama_policy import Policy,PolicyError
from redvector_reviewed_assessment import HTTP_PROFILE,NUCLEI_PROFILE
from unittest.mock import Mock

def policy():
    p=Policy(["192.0.2.15","::1"])
    p.profile_status={HTTP_PROFILE:{"state":"Ready"},NUCLEI_PROFILE:{"state":"Ready"},"service-version-v1":{"state":"Ready"}}
    return p

def test_shared_read_profiles_use_exact_scope_without_redundant_approval():
    p=policy();approve=Mock(side_effect=AssertionError)
    for name,args in [("http_framework_test",{"url":"http://192.0.2.15/"}),
                      ("http_repeater",{"request_spec":{"url":"http://[::1]:8080/","method":"HEAD"}}),
                      ("nuclei_scan",{"target":"http://192.0.2.15/"})]:
        actual=p.authorize(name,args,approve)
        assert actual
    approve.assert_not_called()

@pytest.mark.parametrize("name,args",[
 ("nuclei_scan",{"target":"http://192.0.2.99/"}),
 ("nuclei_scan",{"target":"http://192.0.2.15/","template":"/tmp/arbitrary"}),
 ("http_framework_test",{"url":"http://192.0.2.15/","method":"POST"}),
 ("http_repeater",{"request_spec":{"url":"http://192.0.2.15/","headers":{"Authorization":"secret"}}}),
 ("http_framework_test",{"url":"http://192.0.2.15/?q=x"}),
])
def test_scope_and_profile_cannot_be_bypassed(name,args):
    with pytest.raises(PolicyError):policy().authorize(name,args,lambda _:True)

def test_hostname_is_pinned_and_host_authority_preserved():
    p=Policy(["lab.example"],resolver=lambda _:["192.0.2.15"])
    p.profile_status={HTTP_PROFILE:{"state":"Ready"}}
    result=p.authorize("http_framework_test",{"url":"http://lab.example:8080/"},lambda _:False)
    assert result["url"]=="http://192.0.2.15:8080/"
    assert result["headers"]=={"Host":"lab.example:8080"}

def test_advanced_nmap_service_detection_needs_task_authorization():
    p=policy();calls=[]
    # scope alone does not authorize service-version detection: it prompts
    result=p.authorize("nmap_advanced_scan",{"target":"192.0.2.15","ports":"1-128","scan_type":"-sT -sV"},lambda op:calls.append(op) or True)
    assert result["version_detection"] is True and result["timing"]=="T2" and len(calls)==1
    # within a bounded detection task covering service-version, the same bounded call is not re-prompted
    p.begin_task("192.0.2.15",128,{"discovery","service-version"},lambda op:(_ for _ in ()).throw(AssertionError("bounded task must not prompt")),"bounded task")
    calls2=[]
    p.authorize("nmap_advanced_scan",{"target":"192.0.2.15","ports":"80","scan_type":"-sT -sV"},lambda op:calls2.append(op) or True)
    assert calls2==[] and p.last_task_id
    p.end_task()
    # out-of-profile flags are still refused outright
    with pytest.raises(PolicyError):p.authorize("nmap_advanced_scan",{"target":"192.0.2.15","ports":"80","os_detection":True},lambda _:True)

def test_nuclei_retains_authorized_hostname_authority_with_numeric_destination():
    p=Policy(["lab.example"],resolver=lambda _:["192.0.2.15"])
    p.profile_status={NUCLEI_PROFILE:{"state":"Ready"}}
    result=p.authorize("nuclei_scan",{"target":"https://lab.example/"},lambda _:False)
    assert result["target"]=="https://192.0.2.15/"
    assert result["additional_args"]=="--redvector-authority=lab.example"

def test_advanced_explicit_no_version_is_not_upgraded_to_active_probes():
    with pytest.raises(PolicyError,match="version"):
        policy().authorize("nmap_advanced_scan",{"target":"192.0.2.15","ports":"80","scan_type":"-sT","version_detection":False},lambda _:True)

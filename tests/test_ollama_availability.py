"""Availability must distinguish prerequisites from unfinished integrations."""
from redvector_ollama_availability import status
from redvector_ollama_policy import Policy

def test_missing_scanner_dependency_is_not_reported_ready():
    p=Policy()
    p.profile_status={"--redvector-profile=http-headers-v1":{"state":"Missing Dependency","detail":"Missing reviewed Nuclei runtime; install/configure dependency"}}
    state,detail=status("nuclei_scan",p,{"tools_status":{"nuclei":False}},True)
    assert state=="Missing Dependency" and "install/configure" in detail

def test_discovery_requires_verified_runtime_and_scope():
    p=Policy()
    assert status("nmap_scan",p)[0]!="Ready"
    assert status("nmap_scan",p,{"tools_status":{"nmap":True}},True)[0]!="Ready"
    p.replace_scope(["192.0.2.15"])
    assert status("nmap_scan",p,{"tools_status":{"nmap":True}},True)[0]=="Ready"
    p.auto_count=5
    assert status("nmap_scan",p,{"tools_status":{"nmap":True}},True)[0]=="Requires Approval"

def test_offline_reporting_requires_source_evidence():
    p=Policy()
    assert status("create_scan_summary",p)[0]!="Ready"
    assert status("create_scan_summary",p,report_available=True)[0]=="Ready"

def test_unfinished_integration_has_concrete_work():
    p=Policy()
    for tool in ["whois_lookup","ai_vulnerability_assessment","unknown_custom"]:
        state,detail=status(tool,p)
        assert state!="Ready" and ("integration" in detail.lower() or "policy" in detail.lower())

def test_configured_scanner_profile_can_be_ready_without_path_install():
    p=Policy(["192.0.2.15"])
    p.profile_status={"--redvector-profile=http-headers-v1":{"state":"Ready","detail":"Pinned offline scanner verified"}}
    state,detail=status("nuclei_scan",p,{"tools_status":{"nuclei":False}},True)
    assert state=="Ready" and "verified" in detail

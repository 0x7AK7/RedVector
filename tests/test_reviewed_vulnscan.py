"""Staged reviewed vulnerability-assessment orchestrator: staging, ranking, audit, honest gaps."""
import pytest
import redvector_reviewed_vulnscan as v
import redvector_reviewed_profiles as nmapp
import redvector_reviewed_assessment as http
import redvector_reviewed_advisories as adv

def _wire(monkeypatch,nuclei_ok=False):
    monkeypatch.setattr(nmapp,"run_discovery",lambda tool,p:{"success":True,"profile":nmapp.DISCOVERY,
        "parsed":{"open_ports":[{"port":"22"},{"port":"80"}]}})
    def run_profile(tool,p):
        return {"success":True,"profile":nmapp.PROFILE,"parsed":{"services":[
            {"port":"22","service":"ssh","product":"OpenSSH","version":"7.2p2","confidence":"identified","method":"probed"},
            {"port":"80","service":"http","product":"","version":"","confidence":"inconclusive","method":"table"}]}}
    monkeypatch.setattr(nmapp,"run_profile",run_profile)
    monkeypatch.setattr(http,"run_http_assessment",lambda tool,p:{"success":True,"tool":tool,
        "findings":[{"id":"rv-missing-x-frame-options","title":"Missing X-Frame-Options response header","severity":"info","evidence":{"header":"X-Frame-Options"}}]})
    monkeypatch.setattr(http,"run_nuclei",lambda p:({"success":True,"findings":[{"id":"rv-missing-nosniff","title":"Missing X-Content-Type-Options response header","severity":"info","evidence":{}}]}
        if nuclei_ok else {"success":False,"error":"Missing Dependency: configure REDVECTOR_NUCLEI_BIN"}))
    monkeypatch.setattr(adv,"run",lambda p:{"success":True,"advisories":[
        {"id":"CVE-2016-0777","provider_cvss_score":7.5,"provider_severity":"HIGH","reference":"https://nvd.nist.gov/vuln/detail/CVE-2016-0777"}]})

def test_staged_assessment_ranks_and_audits(monkeypatch):
    _wire(monkeypatch,nuclei_ok=False)
    out=v.run_assessment({"target":"192.168.5.130","focus_areas":"all"})
    assert out["success"] and out["target"]=="192.168.5.130"
    assert out["open_ports"]==["22","80"]
    classes=[f["classification"] for f in out["findings"]]
    # taxonomy ordering: Strongly supported (OpenSSH -sV) before Candidate CVE before Informational
    assert classes==sorted(classes,key=v._ORDER.index)
    assert any(f.get("product")=="OpenSSH" and f["classification"]=="Strongly supported" for f in out["findings"])
    assert any(f["classification"]=="Candidate CVE (requires validation)" and f.get("cve")=="CVE-2016-0777" for f in out["findings"])
    assert any(f["classification"]=="Informational" and f.get("title","").startswith("Missing X-Frame") for f in out["findings"])
    stages={a["stage"]:a["status"] for a in out["audit_trail"]}
    assert stages.get("discovery")=="ok" and stages.get("service-version")=="ok"
    assert stages.get("nuclei-passive")=="unavailable"  # honest: verified binary absent, not faked
    assert "no fabricated findings" in out["limitations"].lower()

def test_nuclei_available_adds_header_finding(monkeypatch):
    _wire(monkeypatch,nuclei_ok=True)
    out=v.run_assessment({"target":"192.168.5.130"})
    assert any(a["stage"]=="nuclei-passive" and a["status"]=="ok" for a in out["audit_trail"])

def test_invalid_target_refused(monkeypatch):
    _wire(monkeypatch)
    assert v.run_assessment({"target":"not-an-ip"})["success"] is False
    assert v.run_assessment({"target":"192.168.5.130","bogus":1})["success"] is False

def test_policy_prepare_pins_scope_and_gates_capability():
    from redvector_ollama_policy import Policy,PolicyError
    pol=Policy(["192.168.5.130"]);pol.profile_status={"tcp-discovery-v1":{"state":"Ready"}}
    out=pol._prepare("ai_vulnerability_assessment",{"target":"192.168.5.130","focus_areas":"web"})
    assert out=={"target":"192.168.5.130","focus_areas":"web"}
    norm=pol._prepare("ai_vulnerability_assessment",{"target":"192.168.5.130","focus_areas":"bogus"})
    assert norm["focus_areas"]=="all"
    with pytest.raises(PolicyError):pol._prepare("ai_vulnerability_assessment",{"target":"10.0.0.9"})  # out of scope
    pol.profile_status={"tcp-discovery-v1":{"state":"Unsupported"}}
    with pytest.raises(PolicyError):pol._prepare("ai_vulnerability_assessment",{"target":"192.168.5.130"})

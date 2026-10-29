"""Assessment severity/classification taxonomy: candidate CVEs are surfaced by CVSS severity
and tracked as candidates, never hidden under Unknown nor marked Confirmed. Dimensions stay
separate. Uses the orchestrator finding schema; no hardcoded targets."""
import json
from redvector_ollama_views import normalize

def _norm(payload):
    data={"source":"mcp","isError":False,"structuredContent":payload,
          "content":[{"type":"text","text":json.dumps(payload)}]}
    return normalize("ai_vulnerability_assessment","fixture-target",{},data,1.0)

# Orchestrator-shaped findings: a critical candidate CVE, a strongly-supported service, and an
# informational web-config item — none carry a flat "severity" field.
PAYLOAD={"success":True,"profile":"ollama-assessment-v1","findings":[
    {"classification":"Candidate CVE (requires validation)","cve":"CVE-2011-2523","cvss":10.0,
     "provider_severity":"CRITICAL","service":"vsftpd"},
    {"classification":"Candidate CVE (requires validation)","cve":"CVE-2010-0000","provider_severity":"HIGH","service":"apache"},
    {"classification":"Strongly supported","service":"ssh","product":"OpenSSH","version":"7.2p2"},
    {"classification":"Informational","title":"Missing X-Frame-Options response header","service":"http"}]}

def test_candidate_critical_is_surfaced_not_unknown_and_not_confirmed():
    r=_norm(PAYLOAD)
    assert r["severity"]["Critical"]==1 and r["severity"]["High"]==1   # CVSS/provider severity surfaced
    assert r["severity"]["Unknown"]==0                                  # not hidden under Unknown
    assert r["confirmed"]==0                                            # candidates are NOT confirmed
    assert r["candidate"]==2
    assert r["classification"].get("Candidate CVE (requires validation)")==2
    assert r["classification"].get("Strongly supported")==1 and r["classification"].get("Informational")==1
    assert r["finding_count"]==4

def test_services_and_info_do_not_inflate_severity_histogram():
    r=_norm({"success":True,"findings":[
        {"classification":"Strongly supported","service":"ssh"},
        {"classification":"Informational","title":"weak header"}]})
    assert sum(r["severity"].values())==0            # no CVSS-bearing findings -> empty histogram
    assert r["confirmed"]==0 and r["candidate"]==0
    assert r["classification"]=={"Strongly supported":1,"Informational":1}

def test_confirmed_classification_counts_as_confirmed():
    r=_norm({"success":True,"findings":[{"classification":"Confirmed","title":"x","cvss":9.1}]})
    assert r["confirmed"]==1 and r["severity"]["Critical"]==1 and r["candidate"]==0

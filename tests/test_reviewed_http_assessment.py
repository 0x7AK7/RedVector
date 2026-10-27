"""Reviewed passive HTTP assessment adapters: marker gating, analyzers and policy pinning."""
import pytest
import redvector_reviewed_assessment as a

BASE={"status_code":200,
      "headers":{"server":"OwnedHTTP/1.2","x-powered-by":"PHP/8.2.1","content-type":"text/html","set-cookie":"sid=abc; Path=/"},
      "body":"<html><head><title>Owned Lab</title></head><body>It works!</body></html>","raw":"","redirect_followed":False}

def _patch(monkeypatch,headers=None,body=None):
    cap=dict(BASE,headers=dict(BASE["headers"],**(headers or {})))
    if body is not None:cap["body"]=body
    monkeypatch.setattr(a,"fetch",lambda url,method="GET",headers=None:dict(cap,headers=dict(cap["headers"])))

def test_marker_is_required(monkeypatch):
    _patch(monkeypatch)
    out=a.run_http_assessment("httpx_probe",{"target":"http://127.0.0.1/"})
    assert out["success"] is False and "marker" in out["error"].lower()

def test_unknown_tool_and_unexpected_args_refused(monkeypatch):
    _patch(monkeypatch)
    assert a.run_http_assessment("nope",{"additional_args":a.HTTP_ASSESS_MARKER})["success"] is False
    assert a.run_http_assessment("httpx_probe",{"target":"http://127.0.0.1/","evil":1,"additional_args":a.HTTP_ASSESS_MARKER})["success"] is False

def test_httpx_probe_reports_real_observations(monkeypatch):
    _patch(monkeypatch)
    out=a.run_http_assessment("httpx_probe",{"target":"http://127.0.0.1/","additional_args":a.HTTP_ASSESS_MARKER})
    assert out["success"] and out["probe"]["title"]=="Owned Lab"
    assert out["probe"]["webserver"]=="OwnedHTTP/1.2" and "PHP" in out["probe"]["powered_by"]
    assert "PHP" in out["probe"]["technologies"]
    assert out["scanner"]["name"]=="httpx" and "no external scanner" in out["scanner"]["mode"].lower()

def test_wafw00f_detects_header_signature_and_honest_absence(monkeypatch):
    _patch(monkeypatch,headers={"server":"cloudflare","cf-ray":"7a"})
    hit=a.run_http_assessment("wafw00f_scan",{"target":"http://127.0.0.1/","additional_args":a.HTTP_ASSESS_MARKER})
    assert hit["success"] and hit["waf"]["detected"] and any(v["name"]=="Cloudflare" for v in hit["waf"]["vendors"])
    _patch(monkeypatch)
    clean=a.run_http_assessment("wafw00f_scan",{"target":"http://127.0.0.1/","additional_args":a.HTTP_ASSESS_MARKER})
    assert clean["success"] and clean["waf"]["detected"] is False

def test_nikto_passive_config_findings(monkeypatch):
    _patch(monkeypatch)
    out=a.run_http_assessment("nikto_scan",{"target":"http://127.0.0.1/","additional_args":a.HTTP_ASSESS_MARKER})
    ids={f["id"] for f in out["findings"]}
    assert {"rv-server-banner","rv-powered-by","rv-missing-x-frame-options","rv-missing-content-security-policy","rv-cookie-secure","rv-cookie-httponly"}<=ids
    assert "rv-missing-strict-transport-security" not in ids  # http scheme: HSTS not flagged
    assert all(f["validation"].startswith("Observed") for f in out["findings"])

def test_jaeles_passive_signatures(monkeypatch):
    _patch(monkeypatch)
    out=a.run_http_assessment("jaeles_vulnerability_scan",{"url":"http://127.0.0.1/","additional_args":a.HTTP_ASSESS_MARKER})
    ids={m["id"] for m in out["matches"]}
    assert "rv-info-powered-by" in ids and "rv-default-page" in ids
    assert out["signatures_evaluated"]==len(a._JAELES_SIGNATURES)
    assert all("not an active exploit" in m["validation"] for m in out["matches"])

def test_policy_pins_destination_and_injects_marker():
    from redvector_ollama_policy import Policy
    from redvector_reviewed_assessment import HTTP_PROFILE,HTTP_ASSESS_MARKER
    pol=Policy(["127.0.0.1"]);pol.profile_status={HTTP_PROFILE:{"state":"Ready"}}
    out=pol._prepare("httpx_probe",{"target":"http://127.0.0.1:8080/"})
    assert out=={"target":"http://127.0.0.1:8080/","additional_args":HTTP_ASSESS_MARKER}
    j=pol._prepare("jaeles_vulnerability_scan",{"url":"http://127.0.0.1/"})
    assert j=={"url":"http://127.0.0.1/","additional_args":HTTP_ASSESS_MARKER}

def test_policy_refuses_nonroot_credentials_and_extra_args():
    from redvector_ollama_policy import Policy,PolicyError
    from redvector_reviewed_assessment import HTTP_PROFILE,HTTP_ASSESS_MARKER
    pol=Policy(["127.0.0.1"]);pol.profile_status={HTTP_PROFILE:{"state":"Ready"}}
    for bad in ({"target":"http://127.0.0.1/path"},{"target":"http://127.0.0.1/?q=1"},
                {"target":"http://u:p@127.0.0.1/"}):
        with pytest.raises(PolicyError):pol._prepare("httpx_probe",bad)
    # Benign model-supplied additional_args are ignored (not a hard failure) and the fixed
    # passive marker is injected, so the workflow is not blocked.
    ok=pol._prepare("httpx_probe",{"target":"http://127.0.0.1/","additional_args":"-x"})
    assert ok["additional_args"]==HTTP_ASSESS_MARKER

def test_policy_requires_ready_capability():
    from redvector_ollama_policy import Policy,PolicyError
    pol=Policy(["127.0.0.1"]);pol.profile_status={}
    with pytest.raises(PolicyError):pol._prepare("nikto_scan",{"target":"http://127.0.0.1/"})

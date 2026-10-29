"""Pure-logic tests (no Kali, no network) for NSE XML parsing, CPE->CVE applicability and the
cross-engine evidence schema + deduplication. Uses realistic fixtures. No target is hardcoded in
product code; 127.0.0.1 here is only test data."""
import redvector_reviewed_profiles as prof
import redvector_cve_correlation as corr
import redvector_evidence as ev


# ---- NSE XML parsing --------------------------------------------------------------------------

_NSE_XML = """<?xml version="1.0"?><nmaprun>
<host><address addr="127.0.0.1"/>
 <hostscript><script id="smb-vuln-ms17-010" output="VULNERABLE: Remote Code Execution (ms17-010)">
   <table key="CVE-2017-0143"><elem key="state">VULNERABLE</elem></table></script></hostscript>
 <ports>
  <port protocol="tcp" portid="443"><state state="open"/>
    <script id="ssl-poodle" output="| VULNERABLE: SSL POODLE (CVE-2014-3566)">
      <table key="CVE-2014-3566"><elem key="state">VULNERABLE</elem></table></script></port>
  <port protocol="tcp" portid="80"><state state="open"/>
    <script id="http-server-header" output="Server: nginx/1.18.0"/></port>
 </ports></host>
<runstats><finished exit="success"/></runstats></nmaprun>"""


def test_parse_nse_xml_extracts_scripts_states_and_cves():
    parsed = prof.parse_nse_xml(_NSE_XML)
    assert parsed["target"] == "127.0.0.1" and parsed["scan_complete"] is True
    by_id = {s["script_id"]: s for s in parsed["scripts"]}
    assert by_id["smb-vuln-ms17-010"]["port"] == "" and by_id["smb-vuln-ms17-010"]["protocol"] == "host"
    assert by_id["smb-vuln-ms17-010"]["state"] == "VULNERABLE"
    assert by_id["smb-vuln-ms17-010"]["cve_ids"] == ["CVE-2017-0143"]
    assert by_id["ssl-poodle"]["port"] == "443" and by_id["ssl-poodle"]["cve_ids"] == ["CVE-2014-3566"]
    assert by_id["http-server-header"]["state"] == ""      # non-vuln script: no state asserted


def test_parse_nse_xml_rejects_entities_and_bad_root():
    import pytest
    with pytest.raises(prof.ProfileError):
        prof.parse_nse_xml('<!DOCTYPE x [<!ENTITY a "b">]><nmaprun></nmaprun>')
    with pytest.raises(prof.ProfileError):
        prof.parse_nse_xml("<notnmap/>")


# ---- CPE parsing + applicability --------------------------------------------------------------

def test_parse_cpe_22_and_23():
    assert corr.parse_cpe("cpe:/a:igor_sysoev:nginx:1.18.0") == {
        "part": "a", "vendor": "igor_sysoev", "product": "nginx", "version": "1.18.0"}
    assert corr.parse_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")["product"] == "http_server"
    assert corr.parse_cpe("not-a-cpe") is None


def test_applicability_exact_version_is_applicable():
    service = {"product": "nginx", "version": "1.18.0", "cpe": ["cpe:/a:igor_sysoev:nginx:1.18.0"]}
    advisory = {"cpe": ["cpe:/a:igor_sysoev:nginx:1.18.0"]}
    applic, _ = corr.applicability(service, advisory)
    assert applic == "applicable"
    assert corr.classify(applic, "cve-correlation") == "Strongly supported"


def test_applicability_product_match_version_unknown_is_candidate():
    service = {"product": "nginx", "version": "", "cpe": []}
    advisory = {"product": "nginx", "versions": ["1.20.0"]}
    applic, _ = corr.applicability(service, advisory)
    assert applic == "candidate"
    assert corr.classify(applic, "cve-correlation") == "Candidate CVE (requires validation)"


def test_applicability_version_not_in_set_is_candidate_not_hidden():
    service = {"product": "nginx", "version": "1.18.0"}
    advisory = {"product": "nginx", "versions": ["1.20.0", "1.21.0"]}
    applic, reason = corr.applicability(service, advisory)
    assert applic == "candidate" and "not in the listed affected versions" in reason


def test_applicability_product_mismatch_is_dropped():
    service = {"product": "nginx", "version": "1.18.0"}
    advisory = {"product": "apache", "versions": ["2.4.49"]}
    assert corr.applicability(service, advisory)[0] == "not_applicable"


def test_correlate_keeps_high_severity_candidate_and_drops_mismatch():
    service = {"product": "nginx", "version": "1.18.0", "cpe": ["cpe:/a:igor_sysoev:nginx:1.18.0"]}
    advisories = [
        {"cve": "CVE-2021-23017", "product": "nginx", "provider_severity": "CRITICAL", "provider_cvss_score": 9.8},
        {"cve": "CVE-9999-0001", "product": "apache", "provider_severity": "CRITICAL"},
    ]
    out = corr.correlate(service, advisories)
    assert [o["cve"] for o in out] == ["CVE-2021-23017"]            # apache dropped, nginx kept
    assert out[0]["classification"] == "Candidate CVE (requires validation)"
    assert out[0]["provider_severity"] == "CRITICAL"               # high severity still visible


# ---- evidence schema + cross-engine dedup -----------------------------------------------------

def test_evidence_has_all_section7_fields():
    rec = ev.evidence(target="127.0.0.1", port="443", cve="CVE-2014-3566", tool="nmap-nse")
    for field in ev.FIELDS:
        assert field in rec
    assert rec["references"] == [] and rec["cve"] == "CVE-2014-3566"


def test_same_cve_same_host_port_merges_keeping_strongest_and_max_cvss():
    nse = ev.evidence(target="127.0.0.1", port="443", protocol="tcp", cve="CVE-2014-3566",
                      tool="nmap-nse", classification="Strongly supported", cvss="4.3",
                      cvss_source="nse", references=["https://nvd/CVE-2014-3566"], verification_method="nse ssl-poodle")
    nvd = ev.evidence(target="127.0.0.1", port="443", protocol="tcp", cve="CVE-2014-3566",
                      tool="nvd", classification="Candidate CVE (requires validation)", cvss="6.8",
                      cvss_source="nvd", references=["https://cve.org/CVE-2014-3566"], verification_method="nvd keyword")
    merged = ev.merge([nvd, nse])
    assert len(merged) == 1
    rec = merged[0]
    assert rec["classification"] == "Strongly supported"           # strongest wins
    assert rec["cvss"] == "6.8" and rec["cvss_source"] == "nvd"     # highest CVSS kept
    assert set(rec["tools"]) == {"nmap-nse", "nvd"}                 # contributing tools unioned
    assert len(rec["references"]) == 2                              # references unioned


def test_different_ports_do_not_merge():
    a = ev.evidence(target="127.0.0.1", port="443", cve="CVE-1", tool="x")
    b = ev.evidence(target="127.0.0.1", port="8443", cve="CVE-1", tool="x")
    assert len(ev.merge([a, b])) == 2


def test_findings_without_cve_dedup_by_tool_signature():
    n1 = ev.evidence(target="127.0.0.1", port="80", tool="nikto", evidence_ref="missing X-Frame-Options",
                     classification="Informational")
    n2 = ev.evidence(target="127.0.0.1", port="80", tool="nikto", evidence_ref="missing X-Frame-Options",
                     classification="Informational")
    n3 = ev.evidence(target="127.0.0.1", port="80", tool="nikto", evidence_ref="directory indexing",
                     classification="Informational")
    assert len(ev.merge([n1, n2, n3])) == 2


def test_summarize_does_not_inflate_confirmed():
    recs = ev.merge([
        ev.evidence(target="t", port="443", cve="CVE-A", classification="Strongly supported", tool="nse"),
        ev.evidence(target="t", port="443", cve="CVE-B", classification="Candidate CVE (requires validation)", tool="nvd"),
        ev.evidence(target="t", port="80", tool="nikto", evidence_ref="hdr", classification="Informational"),
    ])
    summary = ev.summarize(recs)
    assert summary["confirmed"] == 0                               # nothing exploit-confirmed
    assert summary["candidate_cves"] == 1 and summary["total"] == 3

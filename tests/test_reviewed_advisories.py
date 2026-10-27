"""Provider payload fixtures are validation tests, never counted as real execution."""
import pytest
import redvector_reviewed_advisories as a

def test_query_rejects_unbounded_or_injected_parameters():
    assert a.validate({"hours":24,"severity_filter":"ALL","keywords":""})[0]==24
    for params in [{"hours":0},{"hours":169},{"keywords":"https://untrusted.invalid/"},{"severity_filter":"UNKNOWN"}]:
        with pytest.raises(a.AdvisoryError):a.validate(params)

def test_provider_records_are_advisories_not_observed_vulnerabilities():
    body={"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-12345","published":"2026-10-25T01:00:00","lastModified":"2026-10-25T01:00:00","descriptions":[{"lang":"en","value":"Provider advisory fixture"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseSeverity":"HIGH","baseScore":8.0}}]}}}]}
    rows,total=a.parse(body)
    assert total==1 and rows[0]["id"]=="CVE-2026-12345"
    assert rows[0]["applicability"]=="Not assessed"
    with pytest.raises(a.AdvisoryError):a.parse({"error":"upstream error"})

def test_no_missing_payload_is_reported_as_clean():
    for body in [{},{"totalResults":1,"vulnerabilities":[]},{"totalResults":0,"vulnerabilities":"bad"}]:
        with pytest.raises(a.AdvisoryError):a.parse(body)

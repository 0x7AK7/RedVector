"""W5: deterministic evidence-based vulnerability-detection task (Agent.assess). Model-free doubles of
the MCP session: they assert ONE task authorization, discovery before service identification,
Searchsploit references classified as candidates (never proof), honest engine identity (passive
collector is not native Nikto; native Nikto/NSE reported as not run), and no fabricated findings.
These do NOT prove native Kali execution; see tests/test_w6_native_acceptance.py."""
import unittest
from unittest.mock import AsyncMock, patch
import test_ollama_staged_assessment as staged
from test_ollama_staged_assessment import _discovery, _result, TARGET
from types import SimpleNamespace
from redvector_nl_router import classify

_SCHEMAS = {
    "searchsploit_lookup": {"query": "string", "cve": "string", "exact": "boolean", "title_only": "boolean",
                            "exclude": "string", "json_output": "boolean", "mirror": "string", "additional_args": "string"},
    "nikto_scan": {"target": "string", "additional_args": "string"},
    "monitor_cve_feeds": {"hours": "integer", "severity_filter": "string", "keywords": "string"},
    "nuclei_scan": {"target": "string", "severity": "string", "tags": "string", "template": "string", "additional_args": "string"},
}


def _service_with_products():
    payload = staged._service([(22, "ssh", "OpenSSH 7.2p2"), (80, "http", "Apache httpd 2.4.49")])
    payload["parsed"]["services"] = [
        {"port": "22", "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "7.2p2",
         "cpe": [], "confidence": "identified"},
        {"port": "80", "protocol": "tcp", "service": "http", "product": "Apache httpd", "version": "2.4.49",
         "cpe": [], "confidence": "identified"}]
    return payload


def _searchsploit(rows):
    return {"success": True, "execution_mode": "A", "profile": "searchsploit-v1", "binary": "/usr/bin/searchsploit",
            "execution_time": 0.4, "parsed": {"search": "", "results": rows, "shellcode": []}}


_PASSIVE = {"success": True, "findings": [{"id": "rv-missing-x-frame-options", "title": "Missing X-Frame-Options response header",
                                          "severity": "info"}]}


class W5(unittest.IsolatedAsyncioTestCase):
    setUp = staged.StagedAssessment.setUp

    def _agent(self, results, ready=("searchsploit-v1", "redvector-http-read-v1")):
        agent, api, session = staged.StagedAssessment._agent(self, results)
        for name, fields in _SCHEMAS.items():
            agent.catalog[name] = SimpleNamespace(name=name, description="", inputSchema={
                "type": "object", "properties": {k: {"type": v} for k, v in fields.items()}})
        for name in ready:
            agent.policy.profile_status[name] = {"state": "Ready", "detail": "fixture"}
        agent.refresh_profiles = AsyncMock(return_value=agent.policy.profile_status)
        return agent, api, session

    def test_router_sends_find_vulnerabilities_to_assess(self):
        assert classify("Find critical and high vulnerability candidates using verified native Kali scanners.")[0] == "assess"

    async def test_assessment_runs_one_task_and_classifies_references_as_candidates(self):
        results = [_result(_discovery([(22, "open", "ssh"), (80, "open", "http")])), _result(_service_with_products()),
                   _result(_searchsploit([])),                                            # Apache httpd 2.4.49
                   _result(_searchsploit([{"title": "OpenSSH 7.2p2 - Username Enumeration", "edb_id": "40136"},
                                          {"title": "Dropbear SSH 2016 - Unrelated", "edb_id": "1"}])),
                   _result(_PASSIVE)]
        agent, api, session = self._agent(results)
        approvals = []
        agent.approve = lambda operation: approvals.append(operation) or True
        answer = await agent.assess("Find critical and high vulnerability candidates on " + TARGET + ".")
        calls = [c.args[0] if c.args else c.kwargs.get("name") for c in session.call_tool.await_args_list]
        assert calls[:2] == ["nmap_scan", "nmap_scan"] and "searchsploit_lookup" in calls and "nikto_scan" in calls
        assert session.call_tool.await_args_list[1].kwargs["arguments"]["ports"] == "22,80"   # discovered ports only
        assert approvals == []                                   # bounded task, no public provider: no prompt
        assert api.async_chat.await_count == 0
        report = agent.last_task["report"]
        refs = [f for f in report["findings"] if f["source"] == "searchsploit (native)"]
        assert len(refs) == 1 and refs[0]["classification"] == "Candidate CVE"
        assert refs[0]["validation"].startswith("exploit reference only — not proof")
        assert not any(f["classification"] in ("Validated Vulnerability", "Demonstrated Impact") for f in report["findings"])
        passive = [f for f in report["findings"] if f["tool"] == "passive-http"]
        assert passive and all(f["classification"] == "Observed Exposure" for f in passive)
        engines = {row["engine"]: row for row in report["execution"]}
        assert engines["RedVector passive HTTP collector (NOT native Nikto)"]["native_executed"] is False
        assert engines["native Nikto"]["status"].startswith("not enabled")
        assert engines["Nmap NSE vulnerability scripts"]["status"].startswith("not run")
        assert engines["native searchsploit (offline Exploit-DB)"]["binary"] == "/usr/bin/searchsploit"
        assert report["status"] == "Partial"                     # native Nikto/NSE/Nuclei did not run
        assert "not confirmed" in answer

    async def test_public_provider_is_confirmed_once_with_the_task(self):
        advisory = {"success": True, "profile": "nvd-advisory-v1", "advisories": [
            {"id": "CVE-2016-6210", "description": "sshd in OpenSSH before 7.3 ...", "provider_cvss_score": 5.9,
             "provider_severity": "MEDIUM", "reference": "https://nvd.nist.gov/vuln/detail/CVE-2016-6210"}]}
        empty_advisory = {"success": True, "profile": "nvd-advisory-v1", "advisories": []}
        results = [_result(_discovery([(22, "open", "ssh")])), _result(staged._service([(22, "ssh", "OpenSSH 7.2p2")]))]
        results[1].structuredContent["parsed"]["services"] = [{"port": "22", "service": "ssh", "product": "OpenSSH",
                                                               "version": "7.2p2", "confidence": "identified"}]
        import json
        results[1].content[0].text = json.dumps(results[1].structuredContent)
        results += [_result(_searchsploit([])), _result(advisory)]
        agent, api, session = self._agent(results, ready=("searchsploit-v1", "nvd-advisory-v1"))
        approvals = []
        agent.approve = lambda operation: approvals.append(operation) or True
        with patch("redvector_ollama_artifacts.require_backend", lambda session: None):
            await agent.assess("Find vulnerabilities on " + TARGET)
        assert len(approvals) == 1 and approvals[0]["tool"] == "detection task"
        cves = [f for f in agent.last_task["report"]["findings"] if f.get("cve") == "CVE-2016-6210"]
        assert cves and cves[0]["classification"] == "Candidate CVE" and "not validated" in cves[0]["validation"]
        assert empty_advisory  # unused second-provider fixture documents the shape

    async def test_terminal_shows_one_report_without_raw_json(self):
        import io
        from redvector_ollama_setup import Terminal
        results = [_result(_discovery([(22, "open", "ssh"), (80, "open", "http")])), _result(_service_with_products()),
                   _result(_searchsploit([])), _result(_searchsploit([])), _result(_PASSIVE)]
        agent, api, session = self._agent(results)
        stream = io.StringIO()
        agent.terminal = Terminal(stream)
        answer = await agent.assess("Find vulnerabilities on " + TARGET)
        out = stream.getvalue()
        assert out.count("SECURITY ASSESSMENT") == 1                 # per-stage records are not re-rendered
        assert "VULNERABILITIES" in out and "NEXT STEPS" in out and "not proof" in " ".join(out.split())
        assert '"parsed"' not in out and "result.findings[" not in out
        assert "native tools actually executed" in answer

    async def test_declined_task_runs_nothing(self):
        agent, api, session = self._agent([], ready=("nvd-advisory-v1",))
        agent.approve = lambda operation: False
        answer = await agent.assess("Find vulnerabilities on " + TARGET)
        assert session.call_tool.await_count == 0 and "declined" in answer.lower()

    async def test_no_scope_asks_for_target(self):
        agent, api, session = self._agent([])
        agent.policy = type(agent.policy)([])
        answer = await agent.assess("Find vulnerabilities")
        assert "No target has been authorized" in answer and session.call_tool.await_count == 0

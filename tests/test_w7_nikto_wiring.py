"""W7-B: Native Nikto wiring in assess().

Tests that:
  - when nikto-native-v1 is Ready, run_nikto() is called directly (not the MCP passive collector)
  - findings from native Nikto are classified as Scanner-Detected Vulnerability
  - the engine row reports native_executed: True and execution_mode A
  - when nikto-native-v1 is NOT Ready, the passive HTTP collector (MCP) is used instead
  - the passive-fallback engine row reports native_executed: False and the tool is labeled correctly
  - no mode-A claim is made for the passive collector under any circumstances

These are Windows-testable via mocks; they do NOT prove native Kali execution —
see tests/test_w6_native_acceptance.py (N2) for the live evidence requirement.
"""
import unittest
from unittest.mock import AsyncMock, patch, MagicMock
import test_ollama_staged_assessment as staged
from test_ollama_staged_assessment import _discovery, _result, TARGET
from tests.test_w5_assessment import _service_with_products, _PASSIVE


_NIKTO_SUCCESS = {
    "success": True,
    "execution_mode": "A",
    "execution_mode_detail": "native binary executed",
    "profile": "nikto-native-v1",
    "engine": "native nikto (reviewed non-destructive tuning)",
    "runtime_sha256": "abc123",
    "binary": "/usr/bin/nikto",
    "return_code": 0,
    "target": "127.0.0.1:80",
    "ssl": False,
    "parsed": {"host": "127.0.0.1", "port": "80", "findings": [
        {"id": "NIKTO-999042", "method": "GET", "url": "/", "message": "X-Frame-Options header is not set.", "references": ""},
    ]},
    "findings_count": 1,
    "execution_time": 1.5,
}

_NIKTO_UNSUPPORTED = {
    "success": False,
    "execution_mode": "E",
    "execution_mode_detail": "unsupported",
    "profile": "nikto-native-v1",
    "error": "Unsupported: reviewed native Nikto requires native Linux",
    "execution_time": 0.01,
}


class W7NiktoWiring(unittest.IsolatedAsyncioTestCase):
    setUp = staged.StagedAssessment.setUp

    def _agent(self, results, ready_profiles=()):
        from tests.test_w5_assessment import _SCHEMAS
        from types import SimpleNamespace
        agent, api, session = staged.StagedAssessment._agent(self, results)
        for name, fields in _SCHEMAS.items():
            agent.catalog[name] = SimpleNamespace(name=name, description="", inputSchema={
                "type": "object", "properties": {k: {"type": v} for k, v in fields.items()}})
        for name in ready_profiles:
            agent.policy.profile_status[name] = {"state": "Ready", "detail": "fixture"}
        agent.refresh_profiles = AsyncMock(return_value=agent.policy.profile_status)
        return agent, api, session

    async def test_native_nikto_called_when_ready(self):
        """When nikto-native-v1 is Ready, run_nikto() is called; mode A reported; finding classified."""
        results = [
            _result(_discovery([(80, "open", "http")])),
            _result(_service_with_products()),
            _result({"success": True, "execution_mode": "A", "profile": "searchsploit-v1",
                     "binary": "/usr/bin/searchsploit", "execution_time": 0.1,
                     "parsed": {"search": "", "results": [], "shellcode": []}}),
        ]
        agent, api, session = self._agent(
            results, ready_profiles=("searchsploit-v1", "nikto-native-v1"))
        agent.approve = lambda operation: True

        with patch("redvector_reviewed_nikto.run_nikto", return_value=_NIKTO_SUCCESS) as mock_run:
            await agent.assess("Find vulnerabilities on " + TARGET)

        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert call_args.get("additional_args") == "--redvector-nikto-native-v1", call_args

        report = agent.last_task["report"]
        engines = {row["engine"]: row for row in report["execution"]}
        nikto_row = engines.get("native Nikto (reviewed non-destructive tuning)")
        assert nikto_row is not None, "expected native Nikto engine row; got: {}".format(list(engines))
        assert nikto_row["native_executed"] is True
        assert nikto_row["status"] == "ok"

        # Finding classified as Scanner-Detected Vulnerability
        nikto_findings = [f for f in report["findings"] if f.get("tool") == "nikto"]
        assert len(nikto_findings) == 1
        assert nikto_findings[0]["classification"] == "Scanner-Detected Vulnerability"
        assert "nikto" in nikto_findings[0]["source"].lower()

        # Passive collector must NOT appear
        assert "RedVector passive HTTP collector (NOT native Nikto)" not in engines

    async def test_passive_fallback_when_nikto_not_ready(self):
        """When nikto-native-v1 is NOT Ready, passive HTTP collector is used; no mode-A claim."""
        results = [
            _result(_discovery([(80, "open", "http")])),
            _result(_service_with_products()),
            _result({"success": True, "execution_mode": "A", "profile": "searchsploit-v1",
                     "binary": "/usr/bin/searchsploit", "execution_time": 0.1,
                     "parsed": {"search": "", "results": [], "shellcode": []}}),
            _result(_PASSIVE),
        ]
        agent, api, session = self._agent(
            results, ready_profiles=("searchsploit-v1", "redvector-http-read-v1"))
        agent.approve = lambda operation: True

        with patch("redvector_reviewed_nikto.run_nikto") as mock_run:
            await agent.assess("Find vulnerabilities on " + TARGET)

        mock_run.assert_not_called()

        report = agent.last_task["report"]
        engines = {row["engine"]: row for row in report["execution"]}

        # Passive collector present, not labeled as native
        passive_row = engines.get("RedVector passive HTTP collector (NOT native Nikto)")
        assert passive_row is not None, list(engines)
        assert passive_row["native_executed"] is False

        # Unavailability row present for native Nikto
        nikto_unavail = engines.get("native Nikto")
        assert nikto_unavail is not None, list(engines)
        assert nikto_unavail["native_executed"] is False
        assert not nikto_unavail["status"].startswith("ok")

    async def test_nikto_ready_host_but_profile_not_activated(self):
        """Nikto binary installed and adapter says Ready on host, but nikto-native-v1 is NOT in the
        active profile set for this assessment (only passive HTTP ready).  The 'native Nikto' row must
        say 'not run: profile not activated ...' — never 'ready' — so operators see a clear action."""
        results = [
            _result(_discovery([(80, "open", "http")])),
            _result(_service_with_products()),
            _result({"success": True, "execution_mode": "A", "profile": "searchsploit-v1",
                     "binary": "/usr/bin/searchsploit", "execution_time": 0.1,
                     "parsed": {"search": "", "results": [], "shellcode": []}}),
            _result(_PASSIVE),
        ]
        # Profile set: searchsploit + passive HTTP only — no nikto-native-v1
        agent, api, session = self._agent(
            results, ready_profiles=("searchsploit-v1", "redvector-http-read-v1"))
        agent.approve = lambda operation: True

        # Host reports Nikto is Ready (simulates real VMware Kali with nikto installed)
        _host_ready = {
            "nmap": {"display": "native Nmap", "execution_class": "detection",
                     "install_hint": "sudo apt-get install nmap",
                     "profiles": {"tcp-discovery-v1": {"state": "Ready", "detail": ""},
                                  "service-version-v1": {"state": "Ready", "detail": ""},
                                  "nse-vuln-v1": {"state": "Unsupported",
                                                  "detail": "NSE vuln script allowlist not yet curated from live nmap --script-help; nse-vuln-v1 disabled"}}},
            "nuclei": {"display": "native Nuclei (reviewed offline header profile)", "execution_class": "web-scan",
                       "install_hint": "...", "profiles": {"--redvector-profile=http-headers-v1": {"state": "Unsupported", "detail": "SHA not registered"}}},
            "nikto": {"display": "native Nikto (reviewed non-destructive tuning)", "execution_class": "web-scan",
                      "install_hint": "sudo apt-get install nikto",
                      "profiles": {"nikto-native-v1": {"state": "Ready", "detail": ""}}},
            "searchsploit": {"display": "native Searchsploit (offline Exploit-DB, read-only)", "execution_class": "exploit-db",
                             "install_hint": "sudo apt-get install exploitdb",
                             "profiles": {"searchsploit-v1": {"state": "Ready", "detail": ""}}},
        }
        with patch("redvector_tool_manager.discover_tools", return_value=_host_ready):
            with patch("redvector_reviewed_nikto.run_nikto") as mock_run:
                await agent.assess("Find vulnerabilities on " + TARGET)

        mock_run.assert_not_called()

        report = agent.last_task["report"]
        engines = {row["engine"]: row for row in report["execution"]}
        nikto_row = engines.get("native Nikto")
        assert nikto_row is not None, list(engines)
        assert nikto_row["native_executed"] is False
        # Must NOT be "ready" — binary being Ready on host is not the same as executing in this task
        assert nikto_row["status"] != "ready", nikto_row["status"]
        # Must explain that the profile was not activated
        assert nikto_row["status"].startswith("not run:"), nikto_row["status"]

    async def test_nikto_mode_e_reported_honestly(self):
        """If run_nikto() returns mode E (unsupported), native_executed is False and status is not ok."""
        results = [
            _result(_discovery([(80, "open", "http")])),
            _result(_service_with_products()),
            _result({"success": True, "execution_mode": "A", "profile": "searchsploit-v1",
                     "binary": "/usr/bin/searchsploit", "execution_time": 0.1,
                     "parsed": {"search": "", "results": [], "shellcode": []}}),
        ]
        agent, api, session = self._agent(
            results, ready_profiles=("searchsploit-v1", "nikto-native-v1"))
        agent.approve = lambda operation: True

        with patch("redvector_reviewed_nikto.run_nikto", return_value=_NIKTO_UNSUPPORTED):
            await agent.assess("Find vulnerabilities on " + TARGET)

        report = agent.last_task["report"]
        engines = {row["engine"]: row for row in report["execution"]}
        nikto_row = engines.get("native Nikto (reviewed non-destructive tuning)")
        assert nikto_row is not None
        assert nikto_row["native_executed"] is False
        assert nikto_row["status"] != "ok"
        # No findings fabricated from a failed run
        nikto_findings = [f for f in report["findings"] if f.get("tool") == "nikto"]
        assert nikto_findings == []

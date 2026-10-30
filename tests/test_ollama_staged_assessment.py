"""Area 9 — staged combined full-range discovery -> service/version identification.

These are model-boundary doubles (no real scan): a mocked MCP session returns a full-range
discovery payload, then a service-version payload confined to the discovered open ports. They
assert the workflow is STAGED and NOT truncated (discovery runs 1-65535; service-ID runs only on
the discovered open ports), that evidence for every stage is preserved, and that no automatic AI
pass is started. No target is hardcoded: the loopback scope is a test fixture, not product code.
Real native execution of this workflow is covered by tests/test_ollama_fullrange_live.py."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, AsyncMock, patch
from types import SimpleNamespace
from redvector_ollama_agent import Agent
from redvector_ollama_policy import Policy
from redvector_ollama_results import ResultsStore
from redvector_ollama_setup import Terminal
from redvector_ollama_cli import (requests_full_range, requests_service_identification,
                                   requests_combined_discovery_service)
from test_ollama_agent_responses import tool

TARGET = "127.0.0.1"  # loopback test fixture only; never a product constant


def _result(payload):
    return SimpleNamespace(isError=False, structuredContent=payload,
                           content=[SimpleNamespace(type="text", text=json.dumps(payload))],
                           model_dump=lambda **kw: {"wire": payload})


def _discovery(ports):
    rows = [{"port": str(p), "protocol": "tcp", "state": s, "service": svc} for p, s, svc in ports]
    stdout = "PORT STATE SERVICE\n" + "\n".join(str(p) + "/tcp " + s + " " + svc for p, s, svc in ports) + "\n"
    return {"success": True, "profile": "tcp-discovery-v1",
            "scan_type": "--redvector-profile=tcp-discovery-v1",
            "parsed": {"target": TARGET, "ports": rows},
            "reviewed_profile": {"ports_count": 65535}, "stdout": stdout, "return_code": 0}


def _service(rows):
    body = "PORT STATE SERVICE VERSION\n" + "\n".join(
        str(p) + "/tcp open " + svc + " " + ver for p, svc, ver in rows) + "\n"
    parsed = [{"port": str(p), "protocol": "tcp", "state": "open", "service": svc,
               "version": ver, "version_verified": True} for p, svc, ver in rows]
    return {"success": True, "profile": "service-version-v1",
            "parsed": {"target": TARGET, "ports": parsed}, "stdout": body, "return_code": 0}


class StagedAssessment(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        env = patch.dict(os.environ, {"XDG_CONFIG_HOME": str(Path(self.temp.name) / "config")})
        env.start(); self.addCleanup(env.stop)

    def _agent(self, call_results):
        api = Mock(); api.async_chat = AsyncMock()
        session = Mock(); session.call_tool = AsyncMock(side_effect=list(call_results))
        policy = Policy([TARGET]); policy.version_intensity = 1
        policy.profile_status = {"tcp-discovery-v1": {"state": "Ready", "detail": "fixture"},
                                 "service-version-v1": {"state": "Ready", "detail": "fixture"}}
        agent = Agent(api, "fixture-model", session, {"nmap_scan": tool("nmap_scan")}, policy,
                      lambda operation: True, lambda _text: None,
                      results=ResultsStore(Path(self.temp.name) / "evidence"), terminal=None)
        agent.automatic_task = True
        return agent, api, session

    def test_detectors_classify_combined_versus_discovery_only(self):
        assert requests_combined_discovery_service("Scan all 65535 TCP ports on " + TARGET + ". Identify services.")
        assert requests_full_range("scan every tcp port") and not requests_service_identification("scan every tcp port")
        # discovery-only is never reclassified as a combined (service) request
        assert not requests_combined_discovery_service("Scan all TCP ports on " + TARGET)
        # a bounded service request is not full-range, so it is not a staged combined request
        assert not requests_full_range("identify service versions on ports 80,443")
        assert not requests_combined_discovery_service("identify service versions on ports 80,443")

    async def test_full_range_discovery_then_service_id_not_truncated(self):
        disc = _discovery([(22, "open", "ssh"), (80, "open", "http"), (443, "closed", "https")])
        svc = _service([(22, "ssh", "OpenSSH 8.9"), (80, "http", "nginx 1.18")])
        agent, api, session = self._agent([_result(disc), _result(svc)])
        answer = await agent.staged_discovery_service(TARGET)
        # exactly two MCP calls: full-range discovery, then one bounded service-ID scan
        self.assertEqual(session.call_tool.await_count, 2)
        first = session.call_tool.await_args_list[0].kwargs["arguments"]
        second = session.call_tool.await_args_list[1].kwargs["arguments"]
        self.assertEqual(first["ports"], "1-65535")                      # stage 1 NOT truncated
        self.assertEqual(first["scan_type"], "--redvector-profile=tcp-discovery-v1")
        self.assertEqual(second["ports"], "22,80")                       # stage 2 only discovered open ports
        self.assertNotEqual(second["scan_type"], "--redvector-profile=tcp-discovery-v1")
        # deterministic summary; no automatic AI analysis
        self.assertEqual(api.async_chat.await_count, 0)
        self.assertIn("STAGED ASSESSMENT COMPLETED", answer)
        self.assertIn("full-range discovery (1-65535, not truncated)", answer)
        self.assertIn("open TCP ports 2", answer)
        self.assertIn("no AI analysis run", answer)
        self.assertIn("2 open service(s) examined, 2 with an identified version", answer)
        # both stages' evidence is retrievable (discovery + service-ID records persisted)
        self.assertGreaterEqual(len(agent.results.ids()), 2)
        self.assertIn("Service evidence:", answer)

    async def test_many_open_ports_are_chunked_not_dropped(self):
        ports = [(p, "open", "svc") for p in range(1000, 1200)]  # 200 open ports -> 2 service chunks
        disc = _discovery(ports)
        svc1 = _service([(p, "svc", "v1") for p in range(1000, 1128)])
        svc2 = _service([(p, "svc", "v1") for p in range(1128, 1200)])
        agent, api, session = self._agent([_result(disc), _result(svc1), _result(svc2)])
        answer = await agent.staged_discovery_service(TARGET)
        self.assertEqual(session.call_tool.await_count, 3)  # discovery + two <=128 service chunks
        chunk_a = session.call_tool.await_args_list[1].kwargs["arguments"]["ports"].split(",")
        chunk_b = session.call_tool.await_args_list[2].kwargs["arguments"]["ports"].split(",")
        self.assertEqual(len(chunk_a), 128)
        self.assertEqual(len(chunk_b), 72)
        self.assertEqual(len(chunk_a) + len(chunk_b), 200)  # every discovered open port covered
        self.assertIn("2 scan(s), <=128 ports each", answer)

    async def test_terminal_renders_professional_report(self):
        disc = _discovery([(22, "open", "ssh"), (80, "open", "http")])
        svc = _service([(22, "ssh", "OpenSSH 8.9"), (80, "http", "nginx 1.18")])
        agent, api, session = self._agent([_result(disc), _result(svc)])
        stream = io.StringIO()
        agent.terminal = Terminal(stream)
        answer = await agent.staged_discovery_service(TARGET)
        out = stream.getvalue()
        assert "REDVECTOR AI" in out and "SECURITY ASSESSMENT" in out
        assert "SERVICES" in out and "EXECUTION EVIDENCE" in out
        assert "ssh" in out and "nginx 1.18" in out
        assert "nmap" in out                                                    # native engine evidence (may be width-truncated)
        assert "result.findings[" not in out and ".classification" not in out   # no flattened dump
        assert "export the report as JSON" in answer                            # concise pointer returned

    async def test_turn_routes_combined_request_to_staged_workflow(self):
        # End-to-end routing: a natural-language combined request reaches the staged workflow
        # (two scans) rather than the single truncated version scan, with no model tool loop.
        disc = _discovery([(22, "open", "ssh"), (80, "open", "http")])
        svc = _service([(22, "ssh", "OpenSSH 8.9"), (80, "http", "nginx 1.18")])
        agent, api, session = self._agent([_result(disc), _result(svc)])
        agent.refresh_profiles = AsyncMock(return_value=None)  # skip real backend attestation
        answer = await agent.turn("Scan all 65535 TCP ports on " + TARGET + " and identify running services on the open ports.")
        self.assertEqual(session.call_tool.await_count, 2)
        self.assertEqual(session.call_tool.await_args_list[0].kwargs["arguments"]["ports"], "1-65535")
        self.assertEqual(session.call_tool.await_args_list[1].kwargs["arguments"]["ports"], "22,80")
        self.assertEqual(api.async_chat.await_count, 0)  # deterministic staging; no model loop
        self.assertIn("STAGED ASSESSMENT COMPLETED", answer)

    async def test_turn_discovery_only_is_not_staged_as_version(self):
        # A discovery-only request must NOT be reclassified: it goes through the normal model
        # loop (not the staged discovery+service path).
        disc = _discovery([(22, "open", "ssh")])
        agent, api, session = self._agent([_result(disc)])
        agent.refresh_profiles = AsyncMock(return_value=None)
        api.async_chat = AsyncMock(return_value={"role": "assistant", "content": "done", "tool_calls": []})
        await agent.turn("Scan all TCP ports on " + TARGET)
        self.assertGreaterEqual(api.async_chat.await_count, 1)  # used the model loop, not staging

    async def test_chained_low_impact_stages_do_not_reprompt(self):
        # Inc E: an authorized scope + explicit task runs discovery AND each service-version stage
        # without a redundant approval, so the orchestrated workflow is not interrupted per stage.
        disc = _discovery([(22, "open", "ssh"), (80, "open", "http")])
        svc = _service([(22, "ssh", "OpenSSH 8.9"), (80, "http", "nginx 1.18")])
        api = Mock(); api.async_chat = AsyncMock()
        session = Mock(); session.call_tool = AsyncMock(side_effect=[_result(disc), _result(svc)])
        policy = Policy([TARGET]); policy.version_intensity = 1
        policy.profile_status = {"tcp-discovery-v1": {"state": "Ready", "detail": "fixture"},
                                 "service-version-v1": {"state": "Ready", "detail": "fixture"}}
        approvals = []
        agent = Agent(api, "fixture-model", session, {"nmap_scan": tool("nmap_scan")}, policy,
                      lambda operation: approvals.append(operation) or True, lambda _t: None,
                      results=ResultsStore(Path(self.temp.name) / "ev2"), terminal=None)
        agent.automatic_task = True
        await agent.staged_discovery_service(TARGET)
        assert approvals == []                                   # no redundant APPROVE prompts
        assert policy.last_automatic is True

    async def test_no_open_ports_skips_service_stage(self):
        disc = _discovery([(22, "closed", "ssh"), (80, "filtered", "http")])
        agent, api, session = self._agent([_result(disc)])
        answer = await agent.staged_discovery_service(TARGET)
        self.assertEqual(session.call_tool.await_count, 1)  # discovery only; no service scan
        self.assertIn("open TCP ports 0", answer)
        self.assertIn("Stage 2 — service identification skipped: no open ports were discovered.", answer)
        self.assertEqual(api.async_chat.await_count, 0)


if __name__ == "__main__":
    unittest.main()

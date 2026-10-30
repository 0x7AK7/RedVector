"""W2: discovery-before-service invariant and honest coverage. The 128-port limit applies only to
service-version batches; discovery uses the full range when asked, an explicit range when given, or
the bounded default 1-10000 (disclosed, never presented as full). Model-free; RFC 5737 addresses."""
import unittest
import pytest
from unittest.mock import AsyncMock
from redvector_ollama_cli import discovery_range, port_count
import test_ollama_staged_assessment as staged
from test_ollama_staged_assessment import _discovery, _service, _result, TARGET


@pytest.mark.parametrize("text,expected", [
    ("Scan all 65535 TCP ports using native Kali Nmap and identify services.", ("1-65535", "full")),
    ("Identify service versions on ports 22,80,443.", ("22,80,443", "explicit")),
    ("Discover services on ports 1-2000.", ("1-2000", "explicit")),
    ("Identify open ports and service versions on my lab target.", ("1-10000", "bounded-default")),
])
def test_discovery_range_selection(text, expected):
    assert discovery_range(text) == expected


def test_port_count():
    assert port_count("1-65535") == 65535 and port_count("22,80,1000-1002") == 5 and port_count("1-128") == 128
    assert port_count("80-22") == 0 and port_count("x") == 0


class W2(unittest.IsolatedAsyncioTestCase):
    # reuse only the fixture helpers (not StagedAssessment's tests)
    setUp = staged.StagedAssessment.setUp
    _agent = staged.StagedAssessment._agent

    async def test_unspecified_range_runs_bounded_discovery_and_discloses_coverage(self):
        disc = _discovery([(22, "open", "ssh"), (80, "open", "http")])
        svc = _service([(22, "ssh", "OpenSSH 8.9"), (80, "http", "nginx 1.18")])
        agent, api, session = self._agent([_result(disc), _result(svc)])
        agent.refresh_profiles = AsyncMock(return_value=None)
        answer = await agent.turn("Identify open ports and service versions on " + TARGET + ".")
        first = session.call_tool.await_args_list[0].kwargs["arguments"]
        second = session.call_tool.await_args_list[1].kwargs["arguments"]
        assert first["ports"] == "1-10000" and first["scan_type"] == "--redvector-profile=tcp-discovery-v1"
        assert second["ports"] == "22,80"                       # version only on discovered open ports
        assert "10,000 of 10,000 requested TCP ports completed" in answer
        assert "this is not all 65,535 TCP ports" in answer       # bounded coverage never shown as full
        assert api.async_chat.await_count == 0
        assert agent.last_task["coverage"]["state"] == "complete"

    async def test_acceptance_phrase_asks_once_and_runs_all_stages(self):
        # "Do not exploit anything" used to void detection authorization (prompt at every stage).
        disc = _discovery([(22, "open", "ssh"), (80, "open", "http")])
        svc = _service([(22, "ssh", "OpenSSH 8.9"), (80, "http", "nginx 1.18")])
        agent, api, session = self._agent([_result(disc), _result(svc)])
        agent.refresh_profiles = AsyncMock(return_value=None)
        approvals = []
        agent.approve = lambda operation: approvals.append(operation) or True
        await agent.turn("Scan all 65535 TCP ports on " + TARGET + " using native Kali Nmap. Identify open ports and "
                         "service versions and show the findings. Do not exploit anything.")
        assert len(approvals) == 1 and approvals[0]["tool"] == "detection task"
        assert session.call_tool.await_count == 2
        assert session.call_tool.await_args_list[0].kwargs["arguments"]["ports"] == "1-65535"
        assert api.async_chat.await_count == 0

    async def test_full_range_records_complete_coverage(self):
        disc = _discovery([(22, "open", "ssh")])
        svc = _service([(22, "ssh", "OpenSSH 8.9")])
        agent, api, session = self._agent([_result(disc), _result(svc)])
        await agent.staged_discovery_service(TARGET)
        cov = agent.last_task["coverage"]
        assert cov["requested"] == 65535 and cov["completed"] == 65535 and cov["open"] == 1
        assert agent.discovered_open[TARGET] == {22}
        assert len(agent.last_task["evidence"]) == 2

    async def test_failed_discovery_is_partial_and_runs_no_service_stage(self):
        failed = {"success": False, "error": "Reviewed discovery did not complete successfully",
                  "parsed": {"target": TARGET, "ports": []}}
        agent, api, session = self._agent([_result(failed)])
        answer = await agent.staged_discovery_service(TARGET)
        assert session.call_tool.await_count == 1                # no version stage after a failed discovery
        assert agent.last_task["coverage"]["state"] in ("partial", "failed")
        assert "0 of 65,535 requested TCP ports completed" in answer
        assert "STAGED ASSESSMENT COMPLETED" not in answer

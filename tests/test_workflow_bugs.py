"""Regression tests for real Kali workflow bugs fixed in this branch.

Bug A  — staged_discovery_service reuses prior discovery instead of re-scanning.
Bug 2  — vulnscan_detection (assess) re-ran full discovery+service when evidence existed.
Bug 4  — automatic_task was never set on the assess path (APPROVE prompt on every call).
Bug B  — _render_evidence showed only the latest single record, not all session stages.
Bug 1  — _render_provenance grid omitted the MCP tool interface name column.

Tests mock agent.execute directly to avoid the pre-existing MCP preflight issue in the
Windows/test environment (same mock boundary as the existing passing tests for these areas).
No real network scan is performed."""

import io
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch
from types import SimpleNamespace

from redvector_ollama_agent import Agent, _render_evidence, _render_provenance
from redvector_ollama_policy import Policy
from redvector_ollama_results import ResultsStore
from redvector_ollama_setup import Terminal

TARGET = "127.0.0.1"   # loopback fixture only


def _disc_payload(ports_open):
    """Discovery nmap payload with the given list of open (port, service) tuples."""
    rows = [{"port": str(p), "protocol": "tcp", "state": "open", "service": svc}
            for p, svc in ports_open]
    return {"success": True, "profile": "tcp-discovery-v1",
            "scan_type": "--redvector-profile=tcp-discovery-v1",
            "parsed": {"target": TARGET, "ports": rows},
            "reviewed_profile": {"ports_count": 65535}, "stdout": "", "return_code": 0}


def _svc_payload(rows):
    """Service-version nmap payload for (port, service, version) tuples."""
    parsed = [{"port": str(p), "protocol": "tcp", "state": "open",
               "service": svc, "version": ver, "version_verified": True}
              for p, svc, ver in rows]
    return {"success": True, "profile": "service-version-v1",
            "parsed": {"target": TARGET, "ports": parsed}, "stdout": "", "return_code": 0}


def _tool(name):
    return SimpleNamespace(
        inputSchema={"type": "object", "properties": {}, "additionalProperties": True},
        name=name, description="fixture",
    )


def _execute_data(payload):
    """Wrap a payload dict as the dict execute() would return."""
    import json as _json
    return {"source": "mcp", "isError": False,
            "content": [{"type": "text", "text": _json.dumps(payload)}],
            "structuredContent": payload}


class WorkflowBugRegressionTests(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        env = patch.dict(os.environ, {"XDG_CONFIG_HOME": str(Path(self.temp.name) / "config")})
        env.start(); self.addCleanup(env.stop)

    def _agent(self, extra_tools=None):
        api = Mock(); api.async_chat = AsyncMock()
        session = Mock(); session.call_tool = AsyncMock()
        policy = Policy([TARGET]); policy.version_intensity = 1
        policy.profile_status = {
            "tcp-discovery-v1": {"state": "Ready", "detail": "fixture"},
            "service-version-v1": {"state": "Ready", "detail": "fixture"},
            "searchsploit-v1": {"state": "Ready", "detail": "fixture"},
        }
        catalog = {"nmap_scan": _tool("nmap_scan"), **(extra_tools or {})}
        agent = Agent(api, "fixture-model", session, catalog, policy,
                      lambda operation: True, lambda _text: None,
                      results=ResultsStore(Path(self.temp.name) / "evidence"),
                      terminal=None)
        agent.automatic_task = True
        return agent

    def _mock_execute(self, agent, disc_payload, svc_payload=None):
        """Return an execute mock that:
        - Saves a real record to agent.results (gives a 32-char ID loadable later)
        - Sets agent.last_result_id to that ID
        - Returns the right payload based on scan_type
        - Tracks call args for assertions
        The record is saved in _execute_data() format so payloads() can extract structured content.
        """
        calls = []

        async def fake_execute(name, args, exposed):
            scan_type = args.get("scan_type", "")
            if scan_type == "--redvector-profile=tcp-discovery-v1":
                payload = disc_payload
            elif svc_payload is not None and "-sV" in str(scan_type):
                payload = svc_payload
            else:
                payload = {"success": True, "parsed": {}}
            wrapped = _execute_data(payload)
            rec = agent.results.save(name, args.get("target", TARGET), args,
                                     wrapped, {"wire": payload}, 1.0)
            agent.last_result_id = rec["id"]
            calls.append({"name": name, "args": dict(args)})
            return wrapped

        agent.execute = fake_execute
        return calls

    # ------------------------------------------------------------------
    # Bug A — service identification skips re-discovery when ports known
    # ------------------------------------------------------------------

    async def test_bug_a_service_reuses_prior_discovery_skips_rescan(self):
        """Second staged_discovery_service call on same target must skip discovery re-scan."""
        agent = self._agent()
        disc = _disc_payload([(22, "ssh"), (80, "http")])
        svc = _svc_payload([(22, "ssh", "OpenSSH 8.9"), (80, "http", "nginx 1.18")])
        calls = self._mock_execute(agent, disc, svc)

        # First call: discovery + service
        await agent.staged_discovery_service(TARGET, identify=True)
        discovery_calls_first = [c for c in calls
                                  if c["args"].get("scan_type") == "--redvector-profile=tcp-discovery-v1"]
        self.assertEqual(len(discovery_calls_first), 1,
                         "first call must run discovery exactly once")

        calls.clear()
        # Second call: prior evidence exists — must skip discovery
        await agent.staged_discovery_service(TARGET, identify=True)
        discovery_calls_second = [c for c in calls
                                   if c["args"].get("scan_type") == "--redvector-profile=tcp-discovery-v1"]
        self.assertEqual(len(discovery_calls_second), 0,
                         "second call must skip re-discovery when prior evidence exists")

    async def test_bug_a_discovery_runs_for_fresh_agent(self):
        """Discovery must run normally when no prior evidence exists."""
        agent = self._agent()
        disc = _disc_payload([(22, "ssh")])
        svc = _svc_payload([(22, "ssh", "OpenSSH 8.9")])
        calls = self._mock_execute(agent, disc, svc)

        await agent.staged_discovery_service(TARGET, identify=True)

        disc_calls = [c for c in calls
                      if c["args"].get("scan_type") == "--redvector-profile=tcp-discovery-v1"]
        self.assertEqual(len(disc_calls), 1,
                         "fresh agent must run discovery once")
        # confirmed discovered_open is populated
        canonical = agent.policy.destination(TARGET)
        self.assertIn(22, agent.discovered_open.get(canonical, set()))

    # ------------------------------------------------------------------
    # Bug 2 — vulnscan_detection skips re-scan when disc+service evidence exists
    # ------------------------------------------------------------------

    async def test_bug_2_assess_skips_rescan_when_prior_evidence_exists(self):
        """assess() must not re-run nmap discovery/service when last_task already has evidence."""
        import redvector_tool_manager as _tm
        agent = self._agent(extra_tools={"searchsploit_lookup": _tool("searchsploit_lookup")})
        agent.refresh_profiles = AsyncMock(return_value=None)   # keep profile_status from setUp
        disc = _disc_payload([(22, "ssh")])
        svc = _svc_payload([(22, "ssh", "OpenSSH 8.9")])

        ss_payload = {"execution_mode": "A", "binary": "/usr/bin/searchsploit",
                      "execution_time": 0.5, "parsed": {"results": []}}
        calls = self._mock_execute(agent, disc, svc)

        # Patch searchsploit calls too
        orig_execute = agent.execute

        async def execute_with_ss(name, args, exposed):
            if name == "searchsploit_lookup":
                wrapped = _execute_data(ss_payload)
                rec = agent.results.save(name, args.get("target", TARGET), args,
                                         wrapped, {"wire": ss_payload}, 0.5)
                agent.last_result_id = rec["id"]
                calls.append({"name": name, "args": dict(args)})
                return wrapped
            return await orig_execute(name, args, exposed)

        agent.execute = execute_with_ss

        # Prime disc+service evidence
        await agent.staged_discovery_service(TARGET, identify=True)
        disc_calls_before = len([c for c in calls
                                  if c["args"].get("scan_type") == "--redvector-profile=tcp-discovery-v1"])
        self.assertEqual(disc_calls_before, 1)

        calls.clear()
        # Now run vulnerability assessment
        with patch.object(_tm, "discover_tools", return_value={}):
            await agent.assess("Find vulnerabilities on " + TARGET)

        nmap_rescans = [c for c in calls
                        if c["args"].get("scan_type") in (
                            "--redvector-profile=tcp-discovery-v1", "-sT -sV")]
        self.assertEqual(len(nmap_rescans), 0,
                         "assess must not re-run nmap after prior disc+service evidence exists")

    # ------------------------------------------------------------------
    # Bug 4 — automatic_task is set on the assess path (no redundant APPROVE)
    # ------------------------------------------------------------------

    async def test_bug_4_automatic_task_set_on_assess_path(self):
        """assess() must not issue a per-call APPROVE prompt for each native scan stage.
        automatic_task is set True after begin_task() and reset in finally — the test verifies
        that no per-call approvals were issued beyond the one task confirmation."""
        import redvector_tool_manager as _tm
        approvals = []
        agent = self._agent(extra_tools={"searchsploit_lookup": _tool("searchsploit_lookup")})
        agent.refresh_profiles = AsyncMock(return_value=None)   # keep profile_status from setUp
        agent.approve = lambda operation: approvals.append(operation) or True
        disc = _disc_payload([(22, "ssh")])
        svc = _svc_payload([(22, "ssh", "OpenSSH 8.9")])
        self._mock_execute(agent, disc, svc)

        with patch.object(_tm, "discover_tools", return_value={}):
            await agent.assess("Find vulnerabilities on " + TARGET)

        # automatic_task is correctly reset to False after the task exits
        self.assertFalse(agent.automatic_task,
                         "automatic_task must be reset to False in the assess() finally block")
        # No per-call approve prompts should occur (bounded task needs no task confirmation either)
        per_scan_approvals = [op for op in approvals
                              if op.get("tool") not in ("detection task",)]
        self.assertEqual(len(per_scan_approvals), 0,
                         "no per-call approve prompts should occur when automatic_task is set")

    # ------------------------------------------------------------------
    # Bug B — _render_evidence shows session overview, not single record
    # ------------------------------------------------------------------

    def _make_agent_with_last_task(self):
        """Agent with last_task pre-populated with two fake evidence records."""
        agent = self._agent()
        disc = _disc_payload([(22, "ssh")])
        svc = _svc_payload([(22, "ssh", "OpenSSH 8.9")])
        disc_id = agent.results.save("nmap_scan", TARGET, {"target": TARGET},
                                     disc, {"wire": disc}, 1.1)["id"]
        svc_id = agent.results.save("nmap_scan", TARGET, {"target": TARGET, "scan_type": "-sV"},
                                    svc, {"wire": svc}, 0.8)["id"]
        agent.last_task = {"target": TARGET, "evidence": [disc_id, svc_id],
                           "coverage": {"requested": 65535, "completed": 65535,
                                        "open": 1, "state": "complete"}}
        return agent, disc_id, svc_id

    def test_bug_b_render_evidence_shows_all_session_stages_when_no_ident(self):
        """_render_evidence(agent, ident=None) must show all last_task evidence stages."""
        stream = io.StringIO()
        term = Terminal(stream)
        agent, disc_id, svc_id = self._make_agent_with_last_task()

        _render_evidence(term, agent, ident=None)

        out = stream.getvalue()
        self.assertIn("SESSION ASSESSMENT EVIDENCE OVERVIEW", out,
                      "session overview header must appear")
        # Evidence IDs appear truncated in the grid — check prefix
        self.assertIn(disc_id[:8], out, "discovery evidence ID prefix must appear")
        self.assertIn(svc_id[:8], out, "service evidence ID prefix must appear")
        self.assertIn("MCP TOOL", out, "MCP TOOL column header must appear")
        self.assertNotIn("No saved evidence matches", out)

    def test_bug_b_render_evidence_single_record_when_ident_given(self):
        """_render_evidence with a specific ident still shows single-record detail."""
        stream = io.StringIO()
        term = Terminal(stream)
        agent, disc_id, _ = self._make_agent_with_last_task()

        _render_evidence(term, agent, ident=disc_id)

        out = stream.getvalue()
        self.assertIn("EVIDENCE OVERVIEW", out)
        self.assertNotIn("SESSION ASSESSMENT EVIDENCE OVERVIEW", out)

    # ------------------------------------------------------------------
    # Bug 1 — _render_provenance includes MCP TOOL column
    # ------------------------------------------------------------------

    def test_bug_1_render_provenance_shows_mcp_tool_column_header(self):
        """_render_provenance must include the MCP TOOL column header in its grid."""
        stream = io.StringIO()
        term = Terminal(stream)
        agent, _, _ = self._make_agent_with_last_task()

        _render_provenance(term, agent)

        out = stream.getvalue()
        self.assertIn("MCP TOOL", out,
                      "MCP TOOL column header must appear in provenance grid")

    def test_bug_1_render_provenance_mcp_tool_value_truncated_but_present(self):
        """The nmap_scan tool name appears in the provenance output (may be column-truncated)."""
        stream = io.StringIO()
        term = Terminal(stream)
        agent, _, _ = self._make_agent_with_last_task()

        _render_provenance(term, agent)

        out = stream.getvalue()
        # Terminal may truncate column values; "nmap_sc" is the minimal recognizable prefix
        self.assertIn("nmap_sc", out,
                      "nmap_scan tool name (possibly truncated) must appear in provenance output")


class AuthorizationAndIsolationRegressionTests(unittest.IsolatedAsyncioTestCase):
    """Security regression tests: authorization preservation, cross-target isolation,
    stale evidence rejection, and Searchsploit-only follow-up path."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        env = patch.dict(os.environ, {"XDG_CONFIG_HOME": str(Path(self.temp.name) / "config")})
        env.start(); self.addCleanup(env.stop)

    def _agent(self, targets=None, extra_tools=None):
        api = Mock(); api.async_chat = AsyncMock()
        session = Mock(); session.call_tool = AsyncMock()
        policy = Policy(targets or [TARGET]); policy.version_intensity = 1
        policy.profile_status = {
            "tcp-discovery-v1": {"state": "Ready", "detail": "fixture"},
            "service-version-v1": {"state": "Ready", "detail": "fixture"},
            "searchsploit-v1": {"state": "Ready", "detail": "fixture"},
        }
        catalog = {"nmap_scan": _tool("nmap_scan"), **(extra_tools or {})}
        agent = Agent(api, "fixture-model", session, catalog, policy,
                      lambda operation: True, lambda _text: None,
                      results=ResultsStore(Path(self.temp.name) / "evidence"),
                      terminal=None)
        agent.automatic_task = True
        return agent

    def _mock_execute(self, agent, disc_payload, svc_payload=None):
        calls = []

        async def fake_execute(name, args, exposed):
            scan_type = args.get("scan_type", "")
            if scan_type == "--redvector-profile=tcp-discovery-v1":
                payload = disc_payload
            elif svc_payload is not None and "-sV" in str(scan_type):
                payload = svc_payload
            else:
                payload = {"success": True, "parsed": {}}
            wrapped = _execute_data(payload)
            rec = agent.results.save(name, args.get("target", TARGET), args,
                                     wrapped, {"wire": payload}, 1.0)
            agent.last_result_id = rec["id"]
            calls.append({"name": name, "args": dict(args)})
            return wrapped

        agent.execute = fake_execute
        return calls

    # ------------------------------------------------------------------
    # Authorization preservation: automatic_task must not leak
    # ------------------------------------------------------------------

    async def test_automatic_task_not_set_before_begin_task(self):
        """automatic_task must NOT be set when begin_task() raises PolicyError (e.g. operator declined).
        This prevents the flag leaking into subsequent execute() calls."""
        import redvector_tool_manager as _tm
        from redvector_ollama_policy import PolicyError as PE
        agent = self._agent(extra_tools={"searchsploit_lookup": _tool("searchsploit_lookup")})
        agent.refresh_profiles = AsyncMock(return_value=None)
        agent.automatic_task = False

        disc = _disc_payload([(22, "ssh")])
        svc = _svc_payload([(22, "ssh", "OpenSSH 8.9")])
        self._mock_execute(agent, disc, svc)

        # Force begin_task() to raise PolicyError (operator declined)
        with patch.object(agent.policy, "begin_task", side_effect=PE("Operator declined.")):
            with patch.object(_tm, "discover_tools", return_value={}):
                result = await agent.assess("Find vulnerabilities on " + TARGET)

        # automatic_task must remain False — it was never set because begin_task failed
        self.assertFalse(agent.automatic_task,
                         "automatic_task must NOT be set when begin_task() was declined")
        # assess() must have returned the PolicyError message
        self.assertIn("Operator declined", result)

    async def test_automatic_task_reset_after_assess_completes(self):
        """automatic_task must be False when assess() exits (even on success)."""
        import redvector_tool_manager as _tm
        agent = self._agent(extra_tools={"searchsploit_lookup": _tool("searchsploit_lookup")})
        agent.refresh_profiles = AsyncMock(return_value=None)
        disc = _disc_payload([(22, "ssh")])
        svc = _svc_payload([(22, "ssh", "OpenSSH 8.9")])
        self._mock_execute(agent, disc, svc)

        with patch.object(_tm, "discover_tools", return_value={}):
            await agent.assess("Find vulnerabilities on " + TARGET)

        self.assertFalse(agent.automatic_task,
                         "automatic_task must be reset to False in the assess() finally block")

    # ------------------------------------------------------------------
    # Cross-target evidence isolation
    # ------------------------------------------------------------------

    async def test_prior_evidence_not_reused_for_different_target(self):
        """Prior discovery evidence for TARGET_A must not be used when scanning TARGET_B."""
        TARGET_A = "127.0.0.1"
        TARGET_B = "127.0.0.2"
        agent = self._agent(targets=[TARGET_A, TARGET_B])
        disc = _disc_payload([(22, "ssh")])
        svc = _svc_payload([(22, "ssh", "OpenSSH 8.9")])
        calls = self._mock_execute(agent, disc, svc)

        # Establish evidence for TARGET_A
        await agent.staged_discovery_service(TARGET_A, identify=True)
        disc_calls_a = len([c for c in calls
                             if c["args"].get("scan_type") == "--redvector-profile=tcp-discovery-v1"])
        self.assertEqual(disc_calls_a, 1)

        calls.clear()
        # Scan TARGET_B — must run a fresh discovery, not reuse TARGET_A evidence
        await agent.staged_discovery_service(TARGET_B, identify=True)
        disc_calls_b = [c for c in calls
                        if c["args"].get("scan_type") == "--redvector-profile=tcp-discovery-v1"]
        self.assertEqual(len(disc_calls_b), 1,
                         "discovery must run for TARGET_B even when TARGET_A has prior evidence")

    # ------------------------------------------------------------------
    # Stale/incomplete evidence rejection
    # ------------------------------------------------------------------

    async def test_incomplete_prior_coverage_triggers_fresh_discovery(self):
        """If prior coverage state is not 'complete', re-scan must be triggered."""
        agent = self._agent()
        disc = _disc_payload([(22, "ssh")])
        svc = _svc_payload([(22, "ssh", "OpenSSH 8.9")])
        calls = self._mock_execute(agent, disc, svc)

        # Run once to populate discovered_open
        await agent.staged_discovery_service(TARGET, identify=True)
        disc_calls_first = len([c for c in calls
                                 if c["args"].get("scan_type") == "--redvector-profile=tcp-discovery-v1"])
        self.assertEqual(disc_calls_first, 1)

        # Artificially mark coverage as partial (simulates a timed-out or interrupted scan)
        agent.last_task["coverage"]["state"] = "partial"
        calls.clear()

        # Second call: coverage is NOT complete — must re-discover
        await agent.staged_discovery_service(TARGET, identify=True)
        disc_calls_second = [c for c in calls
                              if c["args"].get("scan_type") == "--redvector-profile=tcp-discovery-v1"]
        self.assertEqual(len(disc_calls_second), 1,
                         "partial coverage must trigger a fresh discovery scan")

    async def test_different_port_range_triggers_fresh_discovery(self):
        """Prior discovery on ports '1-65535' must NOT be reused for a request on '1-1000'."""
        agent = self._agent()
        disc = _disc_payload([(22, "ssh")])
        svc = _svc_payload([(22, "ssh", "OpenSSH 8.9")])
        calls = self._mock_execute(agent, disc, svc)

        # Run with full range
        await agent.staged_discovery_service(TARGET, ports="1-65535", identify=True)
        calls.clear()

        # Request a narrower range — must NOT reuse full-range discovery
        await agent.staged_discovery_service(TARGET, ports="1-1000", kind="explicit", identify=True)
        disc_calls = [c for c in calls
                      if c["args"].get("scan_type") == "--redvector-profile=tcp-discovery-v1"]
        self.assertEqual(len(disc_calls), 1,
                         "different port range must trigger fresh discovery, not reuse prior")

    # ------------------------------------------------------------------
    # Searchsploit-only follow-up (Bug 2 functional correctness)
    # ------------------------------------------------------------------

    async def test_assess_runs_searchsploit_when_disc_and_service_already_present(self):
        """assess() with prior disc+service evidence must run searchsploit but skip nmap re-scan."""
        import redvector_tool_manager as _tm
        agent = self._agent(extra_tools={"searchsploit_lookup": _tool("searchsploit_lookup")})
        agent.refresh_profiles = AsyncMock(return_value=None)
        disc = _disc_payload([(22, "ssh")])
        # Use parsed["services"] format so _staged_report() extracts a non-empty product field,
        # which is required for the searchsploit branch to run.
        svc = {"success": True, "profile": "service-version-v1",
               "parsed": {"target": TARGET,
                          "services": [{"port": "22", "protocol": "tcp", "state": "open",
                                        "service": "ssh", "product": "OpenSSH",
                                        "version": "8.9", "confidence": "identified", "cpe": []}]},
               "stdout": "", "return_code": 0}
        ss_payload = {"execution_mode": "A", "binary": "/usr/bin/searchsploit",
                      "execution_time": 0.5, "parsed": {"results": []}}
        calls = self._mock_execute(agent, disc, svc)

        orig_execute = agent.execute

        async def execute_with_ss(name, args, exposed):
            if name == "searchsploit_lookup":
                wrapped = _execute_data(ss_payload)
                rec = agent.results.save(name, args.get("target", TARGET), args,
                                         wrapped, {"wire": ss_payload}, 0.5)
                agent.last_result_id = rec["id"]
                calls.append({"name": name, "args": dict(args)})
                return wrapped
            return await orig_execute(name, args, exposed)

        agent.execute = execute_with_ss

        # Prime disc+service evidence with complete coverage
        await agent.staged_discovery_service(TARGET, identify=True)
        self.assertEqual(agent.last_task["coverage"]["state"], "complete")
        calls.clear()

        # Now run the full assessment — only searchsploit and web stages should run
        with patch.object(_tm, "discover_tools", return_value={}):
            await agent.assess("Find vulnerabilities on " + TARGET)

        nmap_rescans = [c for c in calls
                        if c["args"].get("scan_type") in (
                            "--redvector-profile=tcp-discovery-v1",
                            "--redvector-profile=service-version-v1")]
        ss_calls = [c for c in calls if c["name"] == "searchsploit_lookup"]
        self.assertEqual(len(nmap_rescans), 0,
                         "assess must not re-run nmap when prior evidence is complete")
        self.assertGreater(len(ss_calls), 0,
                           "assess must run searchsploit even when nmap evidence is reused")

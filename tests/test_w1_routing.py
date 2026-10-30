"""W1: deterministic routing of the real acceptance phrases. Composite "authorize ... and scan ..."
continues to the task after validated authorization; provenance tolerates adjectives; "find
vulnerabilities" is a deterministic assessment task; "original evidence" is a readable overview and
raw JSON only on explicit request. Addresses are RFC 5737 test values, never product constants."""
import asyncio
import io
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
import redvector_nl_router as nl
from redvector_ollama_agent import nl_dispatch
from redvector_ollama_policy import Policy
from redvector_ollama_results import ResultsStore
from redvector_ollama_setup import Terminal, Wizard

T = "198.51.100.7"


def test_acceptance_phrases_route_deterministically():
    assert nl.classify("Authorize " + T + " as my lab target.")[0] == "authorize"
    assert nl.classify("Which native tools actually executed?")[0] == "provenance"
    assert nl.classify("Show the original execution evidence without scanning again.")[0] == "evidence"
    assert nl.classify("Find critical and high vulnerability candidates using verified native Kali scanners.")[0] == "assess"
    assert nl.classify("Export the latest assessment as JSON.")[0] == "export"
    assert nl.classify("Scan all 65535 TCP ports using native Nmap and identify services.")[0] == "task"


def test_composite_authorization_carries_a_task():
    text = "Authorize " + T + " as my lab target and scan all 65535 TCP ports using native Kali Nmap. Do not exploit anything."
    assert nl.classify(text)[0] == "authorize" and nl.has_task(text) is True
    assert nl.classify(nl.task_part(text))[0] == "task"
    assert nl.classify("Authorize my lab target and scan all 65535 TCP ports.")[0] == "authorize_needs_target"
    # a pure authorization statement is not a task
    assert nl.has_task("I have permission to assess " + T + ".") is False
    # composite authorization + vulnerability task routes the remainder to the assessment
    assert nl.classify(nl.task_part("Authorize " + T + " as my lab target and find critical vulnerabilities."))[0] == "assess"


def test_exploitation_still_wins_over_assessment():
    assert nl.classify("Find high vulnerabilities and exploit one to obtain a shell.")[0] == "exploitation"


def test_vulnerability_request_without_scanning_analyzes_existing_evidence():
    assert nl.classify("Find vulnerabilities in the latest results but do not launch another scan.")[0] == "analyze"


def _session(tmp_path, scope=()):
    term = Terminal(io.StringIO())
    agent = SimpleNamespace(policy=Policy(list(scope)), history=[], results=ResultsStore(tmp_path / "ev"),
                            select=Mock(return_value=[]), execute=AsyncMock(), summarize_saved=AsyncMock())
    return term, agent, Wizard(Mock(), term, lambda: "")


def test_dispatch_composite_authorizes_then_hands_task_to_turn(tmp_path):
    term, agent, wizard = _session(tmp_path)
    out = asyncio.run(nl_dispatch("Authorize " + T + " as my lab target and scan all TCP ports and identify services.", agent, wizard))
    assert T in agent.policy.snapshot()           # validated scope applied
    assert out is None                             # None -> the interactive loop runs the scan task via turn()


def test_dispatch_invalid_authorization_never_continues_to_task(tmp_path):
    # a destination-shaped but invalid target (multicast) is rejected by the validated scope path,
    # and the scan part of the instruction is NOT continued
    term, agent, wizard = _session(tmp_path)
    out = asyncio.run(nl_dispatch("Authorize 224.0.0.1 as my lab target and scan all TCP ports.", agent, wizard))
    assert out == "handled" and not agent.policy.snapshot()
    assert "Invalid authorized target scope" in term.stream.getvalue()


def test_dispatch_needs_target_continues_only_with_single_scope(tmp_path):
    term, agent, wizard = _session(tmp_path, scope=[T])
    assert asyncio.run(nl_dispatch("Authorize my lab target and scan all TCP ports.", agent, wizard)) is None
    term2, agent2, wizard2 = _session(tmp_path)
    assert asyncio.run(nl_dispatch("Authorize my lab target and scan all TCP ports.", agent2, wizard2)) == "handled"
    assert "No target has been authorized yet" in term2.stream.getvalue()


def test_evidence_overview_has_no_raw_json(tmp_path):
    term, agent, wizard = _session(tmp_path, scope=[T])
    payload = {"success": True, "stdout": "22/tcp open ssh", "parsed": {"target": T, "ports": []},
               "reviewed_profile": {"engine": "native nmap -sT connect discovery", "binary": "/fixture/nmap",
                                    "version": "7.99", "runtime_sha256": "a" * 64}}
    data = {"source": "mcp", "isError": False, "content": [{"type": "text", "text": json.dumps(payload)}], "structuredContent": payload}
    agent.results.save("nmap_scan", T, {"target": T}, data, {"wire": "x"}, 1.0)
    assert asyncio.run(nl_dispatch("Show the original evidence.", agent, wizard)) == "handled"
    out = term.stream.getvalue()
    assert "EVIDENCE OVERVIEW" in out and "/fixture/nmap" in out and "7.99" in out
    assert '"structuredContent"' not in out and '"content"' not in out      # no raw JSON dump

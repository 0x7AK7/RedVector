"""Scope regression fixtures never authorize a real network scan."""
import asyncio
import io
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock,Mock
import pytest
from redvector_ollama_agent import Agent
from redvector_ollama_cli import assessment_context,handle_command
from redvector_ollama_policy import Policy
from redvector_ollama_results import ResultsStore
from redvector_ollama_setup import Terminal,Wizard

LAB="192.168.5.130"  # Explicit reported-case fixture, never a production default.
REPORTED="Scan "+LAB+" for open ports and identify the services and versions running on them."

def test_reported_exact_target_is_policy_restriction_not_scope_denial():
    policy=Policy([LAB])
    assessment,chosen,message=assessment_context(REPORTED,policy)
    assert assessment and chosen==LAB
    assert "execution policy" in message.lower()
    assert "version" in message.lower()
    assert "not in the authorized scope" not in message
    assert policy.snapshot()==(LAB,)

@pytest.mark.parametrize("prompt",[
    "Scan {target} for open ports and identify services running on them.",
    "Scan {target} for open TCP ports and report what is running on it.",
    "Scan {target} and identify services on those ports.",
])
def test_pronouns_do_not_become_destinations(prompt):
    policy=Policy([LAB])
    assert assessment_context(prompt.format(target=LAB),policy)==(True,LAB,None)

@pytest.mark.parametrize("scope,target",[
    (["192.0.2.0/24"],"192.0.2.15"),
    (["2001:db8::/64"],"2001:0db8:0000:0000::15"),
    (["::1","2001:db8::8"],"::1"),
    (["lab.example"],"LAB.EXAMPLE"),
])
def test_cli_and_policy_share_canonical_authorization(scope,target):
    policy=Policy(scope,resolver=lambda _:["192.0.2.15"])
    before=policy.snapshot()
    assessment,chosen,message=assessment_context("Scan "+target+" for open TCP ports and report services on them.",policy)
    assert assessment and chosen and message is None
    assert policy.contains(chosen)
    actual=policy.authorize("nmap_scan",{"target":chosen,"ports":"80"},lambda _:False)
    assert actual["scan_type"] in ("-sT","-6 -sT")
    assert policy.snapshot()==before

@pytest.mark.parametrize("prompt",[
    "Scan 192.0.2.99 for open ports",
    "Scan unapproved.example for ports",
    "Scan intranet for ports",
    "Scan "+LAB+" and scan anotherhost for open ports",
    "Scan "+LAB+" and scan 2001:db8::99 for ports",
])
def test_unauthorized_explicit_destinations_remain_denied(prompt):
    assert assessment_context(prompt,Policy([LAB]))[2] is not None

def test_authorized_network_is_not_automatically_scanned():
    value=assessment_context("Scan 192.0.2.17/24 for ports",Policy(["192.0.2.0/24"]))
    assert "one authorized host" in value[2]
    assert "not in" not in value[2]

def test_session_scope_persists_across_denial_help_and_multiple_requests(tmp_path):
    asyncio.run(_session(tmp_path))

async def _session(tmp_path):
    from test_ollama_agent_responses import tool
    session=Mock()
    session.call_tool=AsyncMock(return_value=SimpleNamespace(isError=False,content=[],
        structuredContent={"success":True,"parsed":{"open_ports":[]}}))
    api=Mock()
    async def chat(model,messages,schemas):
        if not schemas:return {"content":'{"status":"COMPLETED","open_ports":[]}'}
        return {"content":"","tool_calls":[{"function":{"name":"nmap_scan","arguments":{"target":LAB,"ports":"80"}}}]}
    api.async_chat=AsyncMock(side_effect=chat)
    ticks=[0]
    policy=Policy(clock=lambda:ticks[0])
    terminal=Terminal(io.StringIO());wizard=Wizard(Mock(),terminal,lambda:"")
    agent=Agent(api,"fixture-model",session,{"nmap_scan":tool("nmap_scan")},policy,lambda _:False,lambda _:None,
                terminal=terminal,results=ResultsStore(tmp_path/"evidence"))
    await handle_command("/scope "+LAB,agent,wizard)
    trusted=agent.policy
    for number in range(2):
        denied=await agent.turn("Scan 192.0.2.99 for ports")
        assert "scope" in denied.lower()
        restricted=await agent.turn(REPORTED)
        assert "service-version execution unavailable" in restricted.lower()
        assert "scope" not in restricted.lower()
        await handle_command("/help scope",agent,wizard)
        # Service identification now always runs discovery-first (never on model-chosen ports); a plain
        # discovery request keeps exercising scope persistence through the model loop.
        answer=await agent.turn("Scan "+LAB+" for open TCP ports.")
        assert "COMPLETED" in answer
        assert agent.policy is trusted and policy.snapshot()==(LAB,)
        ticks[0]+=31
    scans=[call for call in session.call_tool.call_args_list if call.args[0]=="nmap_scan"]
    health=[call for call in session.call_tool.call_args_list if call.args[0]=="server_health"]
    assert len(scans)==2 and len(health)==2
    assert policy.auto_count==2
    assert all(call.kwargs["arguments"]["target"]==LAB for call in scans)

@pytest.mark.parametrize("suffix",[
    "for open TCP ports: 22, 80 and 443",
    "for open ports and scan only ports 22 and 80",
    "for open TCP ports without -sV",
    "for open TCP ports; do not use -sV",
    "for open TCP ports without active service version detection",
])
def test_prose_modifiers_and_excluded_flags_are_not_destinations_or_actions(suffix):
    assert assessment_context("Scan "+LAB+" "+suffix,Policy([LAB]))==(True,LAB,None)

def test_negation_cannot_hide_a_positive_version_request():
    value=assessment_context("Scan "+LAB+" without -sV, then run -sV",Policy([LAB]))
    assert value[1]==LAB and "execution policy" in value[2].lower()

@pytest.mark.parametrize("network",["192.0.2.0/25","192.0.2.99/25"])
def test_authorized_subnet_request_reports_single_host_restriction(network):
    value=assessment_context("Scan "+network+" for ports",Policy(["192.0.2.0/24"]))
    assert "one authorized host" in value[2]
    assert "outside" not in value[2]

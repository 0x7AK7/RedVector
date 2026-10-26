import asyncio
import io
from types import SimpleNamespace
from unittest.mock import AsyncMock,Mock
from redvector_ollama_agent import Agent
from redvector_ollama_policy import Policy
from redvector_ollama_results import ResultsStore
from redvector_ollama_setup import Terminal
from redvector_ollama_presentation import render_result

def test_saved_report_retains_operator_scope_without_granting_more(tmp_path):
    asyncio.run(_report(tmp_path))

async def _report(tmp_path):
    session=Mock();session.call_tool=AsyncMock(return_value=SimpleNamespace(isError=False,content=[],
        structuredContent={"status":"healthy"},model_dump=lambda **kwargs:{"original":"wire"}))
    tool=SimpleNamespace(inputSchema={"type":"object","properties":{}},name="server_health",description="health")
    agent=Agent(Mock(),"installed",session,{"server_health":tool},Policy(["192.0.2.44"]),lambda _:False,lambda _:None,
                results=ResultsStore(tmp_path/"evidence"),terminal=Terminal(io.StringIO()))
    await agent.execute("server_health",{},{"server_health"})
    record=agent.results.load()
    assert record["authorization"]["scope"]==["192.0.2.44"]
    assert record["authorization"]["approval"]=="Not required: read-only diagnostic"
    stream=io.StringIO();render_result(Terminal(stream),record,80)
    assert "192.0.2.44" in stream.getvalue()
    assert "AUTHORIZATION" in stream.getvalue()
    assert agent.policy.snapshot()==("192.0.2.44",)

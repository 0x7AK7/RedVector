"""Offline model-boundary tests; MCP wire/backend smoke is separate."""
from ollama_test_helpers import model_api
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock,Mock
from redvector_ollama_agent import Agent, discover, verify_tools, tool_schema, AgentError
from redvector_ollama_policy import Policy

def tool(name):
    return SimpleNamespace(name=name,description="Read status",inputSchema={"type":"object","properties":{}})

class AgentTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_session_discovery_paginates(self):
        session=Mock()
        session.list_tools=AsyncMock(side_effect=[SimpleNamespace(tools=[tool("server_health")],nextCursor="next"),
                                                  SimpleNamespace(tools=[tool("get_cache_stats")],nextCursor=None)])
        catalog=await discover(session)
        self.assertEqual(set(catalog),{"server_health","get_cache_stats"})
        session.list_tools.assert_any_await(cursor="next")
    async def test_duplicate_or_invalid_schema_fails(self):
        for tools in ([tool("server_health"),tool("server_health")],
                      [SimpleNamespace(name="bad",description="",inputSchema={"type":"wrong"})]):
            session=Mock();session.list_tools=AsyncMock(return_value=SimpleNamespace(tools=tools,nextCursor=None))
            with self.assertRaises(AgentError):await discover(session)
    async def test_structured_tool_result_and_multiple_steps(self):
        api=model_api();api.chat.side_effect=[
            {"role":"assistant","content":"","tool_calls":[{"function":{"name":"server_health","arguments":{}}}]},
            {"role":"assistant","content":"Backend reported healthy."}]
        session=Mock();session.call_tool=AsyncMock(return_value=SimpleNamespace(isError=False,content=[SimpleNamespace(type="text",text='{"status":"healthy"}')],structuredContent=None))
        rendered=[]
        agent=Agent(api,"local:latest",session,{"server_health":tool("server_health")},Policy(),lambda _:False,rendered.append)
        answer=await agent.turn("Check health")
        self.assertEqual(answer,"Backend reported healthy.")
        self.assertIn("healthy",str(rendered))
        self.assertEqual(api.chat.call_args.args[1][-1]["role"],"tool")
    async def test_unknown_tool_never_dispatched(self):
        api=model_api();api.chat.side_effect=[
            {"role":"assistant","content":"","tool_calls":[{"function":{"name":"execute_command","arguments":{"command":"id"}}}]},
            {"role":"assistant","content":"Denied"}]
        session=Mock();session.call_tool=AsyncMock()
        agent=Agent(api,"local",session,{"server_health":tool("server_health")},Policy(),lambda _:True,lambda _:None)
        await agent.turn("Run command")
        session.call_tool.assert_not_awaited()
    async def test_tool_error_remains_error(self):
        api=model_api();api.chat.side_effect=[
            {"role":"assistant","content":"","tool_calls":[{"function":{"name":"server_health","arguments":{}}}]},
            {"role":"assistant","content":"Failed"}]
        session=Mock();session.call_tool=AsyncMock(return_value=SimpleNamespace(isError=True,content=[SimpleNamespace(type="text",text="unavailable")],structuredContent=None))
        out=[];agent=Agent(api,"local",session,{"server_health":tool("server_health")},Policy(),lambda _:False,out.append)
        await agent.turn("Check health")
        self.assertIn('"isError": true',out[0])
    async def test_rounds_are_bounded(self):
        api=model_api();api.chat.return_value={"role":"assistant","content":"","tool_calls":[{"function":{"name":"discover_tools","arguments":{"query":"health"}}}]}
        agent=Agent(api,"local",Mock(),{"server_health":tool("server_health")},Policy(),lambda _:False,lambda _:None)
        with self.assertRaises(AgentError):await agent.turn("health")
        self.assertLessEqual(api.chat.call_count,8)
    async def test_unsupported_model_is_blocked(self):
        api=model_api();api.show.return_value={"capabilities":["completion"]}
        with self.assertRaises(AgentError):await verify_tools(api,"dolphin-llama3:8b")
        api.chat.assert_not_called()
    async def test_probe_must_make_valid_tool_call(self):
        api=model_api();api.show.return_value={"capabilities":["completion","tools"]}
        api.chat.return_value={"role":"assistant","content":"pong"}
        with self.assertRaises(AgentError):await verify_tools(api,"local")
    async def test_successful_probe_never_executes_real_tools(self):
        api=model_api();api.show.return_value={"capabilities":["tools"]}
        api.chat.return_value={"role":"assistant","content":"","tool_calls":[{"function":{"name":"connection_probe","arguments":{"nonce":"redvector-local"}}}]}
        await verify_tools(api,"local")

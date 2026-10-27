"""Model-boundary doubles; actual network scans belong to native loopback acceptance."""
import io
import json
import os
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock,Mock,patch
from redvector_ollama_agent import Agent,AgentError
from redvector_ollama_policy import Policy
from redvector_ollama_setup import SetupError

def tool(name,description=""):
    fields={"target":{"type":"string"},"scan_type":{"type":"string"},"ports":{"type":"string"},
            "additional_args":{"type":"string"},"use_recovery":{"type":"boolean"}}
    schema={"type":"object","properties":fields,"required":["target"]} if name=="nmap_scan" else {"type":"object","properties":{}}
    return SimpleNamespace(name=name,description=description,inputSchema=schema)

class Responses(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        directory=tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        environment=patch.dict(os.environ,{"XDG_CONFIG_HOME":directory.name})
        environment.start()
        self.addCleanup(environment.stop)
    def agent(self,scope=()):
        api=Mock();api.async_chat=AsyncMock(return_value={"role":"assistant","content":""})
        session=Mock();session.call_tool=AsyncMock(return_value=SimpleNamespace(isError=False,
            content=[SimpleNamespace(type="text",text='{"success":true,"stdout":"Controlled fixture output"}')],structuredContent=None))
        outputs=[]
        catalog={name:tool(name,description) for name,description in [
            ("nmap_scan","TCP ports and services"),("nmap_advanced_scan","Nmap advanced"),
            ("cctv_scan","Also mentions nmap"),("server_health","Health")]}
        return Agent(api,"local",session,catalog,Policy(scope),lambda _:True,outputs.append),outputs

    async def test_incomplete_scan_has_clarification_without_a_model_call(self):
        agent,_=self.agent(["192.0.2.4"])
        agent.api.async_chat.side_effect=AssertionError("Incomplete tasks must not reach model")
        self.assertIn("Please specify",await agent.turn("scan my"))

    async def test_no_scope_has_actionable_instruction(self):
        agent,_=self.agent()
        agent.api.async_chat.side_effect=AssertionError("Missing scope must not reach model")
        self.assertIn("Use /scope TARGET",await agent.turn("Scan my authorized target for open TCP ports"))

    async def test_ambiguous_scope_requires_operator_choice(self):
        agent,_=self.agent(["192.0.2.4","192.0.2.5"])
        agent.api.async_chat.side_effect=AssertionError("Ambiguous tasks must not reach model")
        self.assertIn("Specify",await agent.turn("Scan my authorized target for open TCP ports"))

    async def test_explicit_out_of_scope_request_does_not_fall_back_to_authorized_host(self):
        agent,_=self.agent(["192.0.2.4"])
        agent.api.async_chat.side_effect=AssertionError("Out-of-scope tasks must not reach model")
        self.assertIn("outside",await agent.turn("Scan 192.0.2.9 for open ports"))

    async def test_empty_and_thinking_only_responses_are_actionable(self):
        for message in ({"role":"assistant","content":""},{"role":"assistant","thinking":"working","content":None}):
            agent,_=self.agent();agent.api.async_chat.return_value=message
            answer=await agent.turn("Hello")
            self.assertIn("no final",answer.lower())
            self.assertNotIn("Model response:",answer)

    async def test_authorized_nmap_is_exposed_and_actual_result_returns_to_model(self):
        agent,outputs=self.agent(["192.0.2.4"])
        def chat(model,messages,schemas):
            if not schemas:
                facts=json.loads(messages[-1]["content"])
                self.assertNotIn("Controlled fixture output",str(messages))
                return {"role":"assistant","content":json.dumps({"status":facts["status"],"open_ports":facts["open_ports"]})}
            self.assertIn("192.0.2.4",str(messages))
            self.assertIn("nmap_scan",str(schemas))
            return {"role":"assistant","content":"","tool_calls":[{"function":{"name":"nmap_scan","arguments":{"target":"192.0.2.4","ports":"54321"}}}]}
        agent.api.async_chat.side_effect=chat
        answer=await agent.turn("Scan my authorized target for open TCP ports and services.")
        self.assertIn("actual MCP",answer)
        actual=agent.session.call_tool.await_args.kwargs["arguments"]
        self.assertEqual(actual["target"],"192.0.2.4")
        self.assertIs(actual["use_recovery"],False)
        self.assertIn("Controlled fixture output",str(outputs))

    async def test_disabled_tool_is_explained_without_model_or_fallback(self):
        agent,_=self.agent(["192.0.2.4"])
        agent.api.async_chat.side_effect=AssertionError("Disabled tool must not be offered to model")
        answer=await agent.turn("Run cctv_scan on my target")
        self.assertIn("Missing client integration: cctv_scan",answer)
        self.assertIn("real authorized workflow test",answer)
        self.assertIn("No operation was performed",answer)
        agent.session.call_tool.assert_not_called()

    async def test_model_output_is_stored_without_application_labels(self):
        agent,_=self.agent();agent.api.async_chat.return_value={"role":"assistant","content":"Hello"}
        await agent.turn("Hello")
        self.assertEqual(agent.history[-1]["content"],"Hello")
        answer=await agent.turn("Hello again")
        self.assertNotIn("Model response:",answer)

    async def test_mcp_error_does_not_expose_exception_credentials(self):
        agent,_=self.agent()
        agent.session.call_tool.side_effect=RuntimeError("Bearer TOP_SECRET")
        data=await agent.execute("server_health",{},{"server_health"})
        self.assertTrue(data["isError"])
        self.assertEqual(data["execution_status"],"unknown")
        self.assertNotIn("TOP_SECRET",str(data))

    async def test_api_error_does_not_expose_exception_credentials(self):
        agent,_=self.agent();agent.api.async_chat.side_effect=SetupError("Bearer TOP_SECRET")
        with self.assertRaises(AgentError) as caught:await agent.turn("Hello")
        self.assertNotIn("TOP_SECRET",str(caught.exception))

    async def test_specific_tool_discovery_does_not_include_description_only_matches(self):
        agent,_=self.agent()
        self.assertEqual([row["name"] for row in agent.select("nmap")],["nmap_scan","nmap_advanced_scan"])

    async def test_model_cannot_replace_the_selected_target_with_another_scoped_host(self):
        agent,_=self.agent(["192.0.2.4","192.0.2.5"])
        approvals=[]
        agent.approve=lambda operation:approvals.append(operation) or True
        agent.api.async_chat.side_effect=[
            {"role":"assistant","content":"","tool_calls":[{"function":{"name":"nmap_scan","arguments":{"target":"192.0.2.5"}}}]},
            {"role":"assistant","content":"Scan succeeded"}]
        await agent.turn("Scan 192.0.2.4 for open ports")
        self.assertEqual(agent.session.call_tool.await_count,0)
        self.assertEqual(approvals,[])

    async def test_no_scan_or_diagnostics_only_cannot_support_model_scan_claims(self):
        for diagnostics in (False,True):
            agent,_=self.agent(["192.0.2.4"])
            claim={"role":"assistant","content":"Nmap scan completed successfully, port 22 is open."}
            agent.api.async_chat.side_effect=([{"role":"assistant","content":"","tool_calls":[{"function":{"name":"server_health","arguments":{}}}]},claim] if diagnostics else [claim])
            answer=await agent.turn("Scan my authorized target for open TCP ports")
            self.assertNotIn("port 22 is open",answer)
            self.assertIn("No",answer)

    async def test_polite_and_explicit_tool_requests_cannot_choose_another_scoped_host(self):
        for request in ("Can you scan 192.0.2.4 for open ports?","Run nmap_scan on 192.0.2.4"):
            agent,_=self.agent(["192.0.2.4","192.0.2.5"])
            agent.api.async_chat.side_effect=[
                {"role":"assistant","content":"","tool_calls":[{"function":{"name":"nmap_scan","arguments":{"target":"192.0.2.5"}}}]},
                {"role":"assistant","content":"Nmap completed. Port 22 is open."}]
            answer=await agent.turn(request)
            self.assertEqual(agent.session.call_tool.await_count,0)
            self.assertNotIn("Port 22 is open",answer)

    async def test_unknown_single_label_hostname_does_not_fall_back_to_scoped_host(self):
        agent,_=self.agent()
        agent.policy=Policy(["lab.example"],resolver=lambda _:["192.0.2.4"])
        agent.api.async_chat.side_effect=AssertionError("Unrecognized explicit host needs clarification")
        self.assertIn("scope",await agent.turn("Scan intranet"))

    async def test_general_chat_cannot_expose_or_execute_nmap_without_task_selection(self):
        agent,_=self.agent(["192.0.2.4"])
        agent.select("nmap")
        self.assertNotIn("nmap_scan",[entry["function"]["name"] for entry in agent.schemas()])
        data=await agent.execute("nmap_scan",{"target":"192.0.2.4"},{"nmap_scan"})
        self.assertTrue(data["isError"])
        self.assertEqual(agent.session.call_tool.await_count,0)

    async def test_scan_with_tool_call_instructions_does_not_parse_exactly_as_hostname(self):
        agent,_=self.agent(["192.0.2.4"])
        agent.api.async_chat.side_effect=[
            {"role":"assistant","content":"","tool_calls":[{"function":{"name":"nmap_scan","arguments":{"target":"192.0.2.4","ports":"54321"}}}]},
            {"role":"assistant","content":""}]
        answer=await agent.turn("Can you scan my authorized target for open TCP port 54321. Call nmap_scan exactly once, then summarize the actual result.")
        self.assertEqual(agent.session.call_tool.await_count,1)
        self.assertIn("actual MCP",answer)

    async def test_a_blocked_attempt_does_not_erase_a_later_actual_scan_result(self):
        agent,_=self.agent(["192.0.2.4"])
        agent.api.async_chat.side_effect=[
            {"role":"assistant","content":"","tool_calls":[{"function":{"name":"execute_command","arguments":{}}}]},
            {"role":"assistant","content":"","tool_calls":[{"function":{"name":"nmap_scan","arguments":{"target":"192.0.2.4","ports":"54321"}}}]},
            {"role":"assistant","content":"Scan succeeded"}]
        answer=await agent.turn("Scan my authorized target for open TCP ports")
        self.assertEqual(agent.session.call_tool.await_count,1)
        self.assertNotIn("no successful scan is confirmed",answer.lower())
        self.assertIn("actual MCP",answer)


    async def test_diagnostic_with_explicit_no_scan_reaches_real_mcp_boundary(self):
        agent,_=self.agent()
        agent.api.async_chat.side_effect=[
            {"role":"assistant","content":"","tool_calls":[{"function":{"name":"server_health","arguments":{}}}]},
            {"role":"assistant","content":"Diagnostic completed."}]
        answer=await agent.turn("Call the read-only server_health tool once. Then summarize the actual server status and exact version returned by that tool. Do not scan a target, call other assessment tools, or invent results.")
        agent.session.call_tool.assert_awaited_once_with("server_health",arguments={})
        self.assertNotIn("No authorized target",answer)
        self.assertEqual(agent.policy.snapshot(),())

    async def test_negation_does_not_hide_a_subsequent_positive_scan_request(self):
        agent,_=self.agent()
        for text in ("Do not scan logs; scan my authorized target.", "Never scan logs. Run nmap_scan against my target.",
                     "Do not scan logs but scan my target.", "Call server_health then scan my target."):
            self.assertIn("Use /scope TARGET",await agent.turn(text))
        agent.api.async_chat.assert_not_called()
        agent.session.call_tool.assert_not_called()

    async def test_negated_scan_never_grants_assessment_execution_context(self):
        agent,_=self.agent(["192.0.2.4"])
        agent.api.async_chat.side_effect=[
            {"role":"assistant","tool_calls":[{"function":{"name":"nmap_scan","arguments":{"target":"192.0.2.4"}}}]},
            {"role":"assistant","content":"Done."}]
        await agent.turn("Call server_health. Do not scan a target.")
        agent.session.call_tool.assert_not_called()
        self.assertIsNone(agent.assessment_target)

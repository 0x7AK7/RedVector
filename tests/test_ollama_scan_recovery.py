import asyncio
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,AsyncMock,patch
from test_ollama_agent_responses import tool
from test_ollama_results import response
from redvector_ollama_agent import Agent
from redvector_ollama_policy import Policy
from redvector_ollama_results import ResultsStore
from redvector_ollama_setup import Terminal,OllamaTimeout,OllamaContextError

class Recovery(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        environment=patch.dict("os.environ",{"XDG_CONFIG_HOME":str(Path(self.temp.name)/"config")})
        environment.start();self.addCleanup(environment.stop)
        self.api=Mock();self.api.async_chat=AsyncMock()
        data=response()
        self.session=Mock()
        self.session.call_tool=AsyncMock(return_value=Mock(isError=False,
            content=[Mock(type="text",text=data["content"][0]["text"])],
            structuredContent=data["structuredContent"],model_dump=lambda **kw:{"unknown_wire_field":"preserved"}))
        self.term=Terminal(io.StringIO());self.outputs=[]
        self.agent=Agent(self.api,"custom-model",self.session,{"nmap_scan":tool("nmap_scan")},Policy(["192.0.2.8"]),
                         lambda operation:False,self.outputs.append,results=ResultsStore(Path(self.temp.name)/"results"),terminal=self.term)
        self.call={"role":"assistant","content":"","tool_calls":[{"function":{"name":"nmap_scan","arguments":{"target":"192.0.2.8","ports":"22,80"}}}]}

    async def test_success_then_timeout_preserves_scan_and_retry_has_no_tools(self):
        self.api.async_chat.side_effect=[self.call,OllamaTimeout("timeout")]
        answer=await self.agent.turn("Scan 192.0.2.8 ports 22,80")
        self.assertIn("SCAN COMPLETED SUCCESSFULLY",answer)
        self.assertIn("no AI analysis run",answer)  # area 5: no automatic post-scan AI pass
        self.assertEqual(self.api.async_chat.await_count,1)  # only the tool-selection chat; no auto-AI
        record=self.agent.results.load()
        self.assertEqual(record["findings"]["status"],"COMPLETED")
        self.assertTrue(record["persisted"])
        self.assertEqual(record["wire"],{"unknown_wire_field":"preserved"})
        self.api.async_chat.side_effect=None
        self.api.async_chat.return_value={"content":json.dumps({"status":"COMPLETED","open_ports":["22/tcp","80/tcp"]})}
        answer=await self.agent.summarize_saved()
        self.assertIn("AI verified",answer)
        self.session.call_tool.assert_awaited_once()
        self.assertEqual(self.api.async_chat.call_args.args[2],[])
        self.assertIn("NETWORK SCAN RESULTS",self.term.stream.getvalue())
        self.assertIn("VERIFIED TOOL RESULTS",self.term.stream.getvalue())
        self.assertNotIn("structuredContent",self.term.stream.getvalue())

    async def test_context_model_error_and_cancel_do_not_destroy_evidence(self):
        for failure in (OllamaContextError("overflow"),RuntimeError("secret"),asyncio.CancelledError()):
            self.agent.policy.last_auto=float("-inf")
            self.api.async_chat.side_effect=[copy.deepcopy(self.call),failure]
            answer=await self.agent.turn("Scan 192.0.2.8 ports 22,80")
            self.assertIn("SCAN COMPLETED SUCCESSFULLY",answer)
            self.assertNotIn("secret",answer)
            self.assertEqual(self.agent.results.load()["findings"]["status"],"COMPLETED")
        self.assertEqual(self.session.call_tool.await_count,3)

    async def test_genuine_rpc_failure_is_unknown_and_not_retried(self):
        self.session.call_tool.side_effect=RuntimeError("connection")
        self.api.async_chat.side_effect=[self.call]
        answer=await self.agent.turn("Scan 192.0.2.8 ports 22,80")
        self.assertIn("UNKNOWN",answer)
        self.assertNotIn("COMPLETED SUCCESSFULLY",answer)
        self.session.call_tool.assert_awaited_once()
        self.assertEqual(self.agent.results.load()["findings"]["status"],"UNKNOWN")

    async def test_cancelled_rpc_preserves_unknown_state(self):
        self.session.call_tool.side_effect=asyncio.CancelledError()
        self.agent.assessment_target="192.0.2.8";self.agent.automatic_task=True
        with self.assertRaises(asyncio.CancelledError):await self.agent.execute("nmap_scan",{"target":"192.0.2.8","ports":"80"},{"nmap_scan"})
        self.assertEqual(self.agent.results.load()["findings"]["status"],"UNKNOWN")

    async def test_natural_saved_result_analysis_never_dispatches_a_new_scan(self):
        self.api.async_chat.side_effect=[self.call,OllamaTimeout("timeout")]
        await self.agent.turn("Scan 192.0.2.8 ports 22,80")
        self.api.async_chat.side_effect=None
        self.api.async_chat.return_value={"content":json.dumps({"status":"COMPLETED","open_ports":["22/tcp","80/tcp"]})}
        self.agent.policy.last_auto=float("-inf")
        for prompt in ("Please summarize my previous scan results","Could you summarize the last scan?","I would like you to analyze previous findings"):
            answer=await self.agent.turn(prompt)
            self.assertIn("AI verified",answer)
        self.session.call_tool.assert_awaited_once()
        self.assertEqual(self.api.async_chat.call_args.args[2],[])

    async def test_invalid_analysis_settings_and_page_keep_the_session_results(self):
        self.api.async_chat.side_effect=[self.call,OllamaTimeout("timeout")]
        await self.agent.turn("Scan 192.0.2.8 ports 22,80")
        with patch.dict("os.environ",{"REDVECTOR_OLLAMA_CONTEXT":"invalid"}):
            answer=await self.agent.summarize_saved()
        self.assertIn("configuration",answer)
        self.assertEqual(self.agent.results.load()["findings"]["status"],"COMPLETED")
        answer=await self.agent.summarize_saved(page=999)
        self.assertIn("page",answer)
        self.session.call_tool.assert_awaited_once()


    async def test_unrecognized_negative_scan_language_never_qualifies_for_automation(self):
        self.api.async_chat.side_effect=[self.call,{"role":"assistant","content":"Done"}]
        await self.agent.turn("Do not do a scan.")
        self.session.call_tool.assert_not_called()

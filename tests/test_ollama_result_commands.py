import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock,Mock
from redvector_ollama_results import ResultsStore
from redvector_ollama_setup import Terminal,Wizard
from redvector_ollama_cli import handle_command
from test_ollama_results import response

class ResultCommands(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.store=ResultsStore(Path(self.temp.name)/"results")
        self.record=self.store.save("nmap_scan","fixture",{},response(),{"original":True},1)
        self.agent=SimpleNamespace(results=self.store,summarize_saved=AsyncMock(return_value="AI verified saved facts"),execute=AsyncMock())
        self.term=Terminal(io.StringIO());self.wizard=Wizard(Mock(),self.term,lambda:"")
    async def test_results_raw_export_never_call_network_executor(self):
        for command in ("/results","/results list","/raw","/export"):
            self.assertEqual(await handle_command(command,self.agent,self.wizard),"handled")
        self.agent.execute.assert_not_called();self.agent.summarize_saved.assert_not_called()
        self.assertIn("NETWORK SCAN RESULTS",self.term.stream.getvalue())
        self.assertIn('"original": true',self.term.stream.getvalue())
        self.assertTrue(list(self.store.directory.glob("export-*.json")))
    async def test_summary_retry_is_not_an_agent_turn_or_tool_action(self):
        await handle_command("/summary "+self.record["id"]+" 2",self.agent,self.wizard)
        self.agent.summarize_saved.assert_awaited_once_with(self.record["id"],2)
        self.agent.execute.assert_not_called()
    async def test_invalid_result_commands_are_handled_without_model_or_traceback(self):
        for command in ("/raw ../secret","/summary a zero","/results missing","/export a b c"):
            self.assertEqual(await handle_command(command,self.agent,self.wizard),"handled")
        self.agent.summarize_saved.assert_not_called()
        self.agent.execute.assert_not_called()

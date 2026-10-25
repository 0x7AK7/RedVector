"""Edge cases at the installer, model API and MCP boundaries (offline doubles)."""
from ollama_test_helpers import model_api
from contextlib import asynccontextmanager
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import io,json,os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,AsyncMock,patch
from redvector_ollama_setup import Ollama,Wizard,Terminal,SetupError,plain,save_model,load_model
from redvector_ollama_policy import Policy,PolicyError
from redvector_ollama_storage import StorageInfo
from redvector_ollama_capacity import CapacityAssessment,CapacitySnapshot
from redvector_ollama_agent import Agent,AgentError,discover,verify_tools,connection_test,result_data

class LocalHTTPTests(unittest.TestCase):
    def test_redirects_and_invalid_responses_are_rejected(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path=="/api/version":
                    self.send_response(302);self.send_header("Location","http://example.com/");body=b""
                else:
                    self.send_response(200);body=b"not-json"
                self.end_headers();self.wfile.write(body)
            def log_message(self,*a):pass
        server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
        thread=threading.Thread(target=server.serve_forever);thread.start()
        try:
            api=Ollama(f"http://127.0.0.1:{server.server_port}")
            self.assertFalse(api.healthy())
            with self.assertRaises(SetupError):api.models()
            self.assertFalse(api.session.trust_env)
        finally:server.shutdown();server.server_close();thread.join()

    def test_zero_port_is_not_silently_changed(self):
        with self.assertRaises(SetupError):Ollama("http://127.0.0.1:0")

    def test_closed_service_reports_unavailable(self):
        with socket.socket() as probe:probe.bind(("127.0.0.1",0));port=probe.getsockname()[1]
        self.assertFalse(Ollama(f"http://127.0.0.1:{port}").healthy())

class InstallerEdges(unittest.TestCase):
    def wizard(self,answers,api=None):
        return Wizard(api or Mock(),Terminal(io.StringIO()),iter(answers).__next__)
    def test_disk_check_enforces_actual_free_bytes(self):
        api=model_api();api.manifest_size.return_value=4_700_000_000
        wizard=self.wizard([],api)
        with tempfile.TemporaryDirectory() as d,patch.object(wizard,"storage_location",return_value=StorageInfo(Path(d),"OS fixture")),patch("redvector_ollama_setup.probe_storage",return_value=CapacityAssessment(CapacitySnapshot("verified",available_bytes=4_000_000_000),CapacitySnapshot("verified",available_bytes=4_000_000_000))):
            with self.assertRaisesRegex(SetupError,"Insufficient storage"):wizard.resource_budget("dolphin-llama3:8b",4.7)
    def test_resource_check_reports_memory_gpu_and_requires_confirmation(self):
        api=model_api();api.manifest_size.return_value=1000
        wizard=self.wizard(["n"],api)
        with tempfile.TemporaryDirectory() as d,patch.object(wizard,"storage_location",return_value=StorageInfo(Path(d),"OS fixture")),patch("redvector_ollama_setup.probe_storage",return_value=CapacityAssessment(CapacitySnapshot("verified",available_bytes=20_000_000_000),CapacitySnapshot("verified",available_bytes=20_000_000_000))),patch("shutil.which",return_value=None):
            with self.assertRaisesRegex(SetupError,"cancelled"):wizard.resource_budget("custom")
            self.assertIn("RAM:",wizard.term.stream.getvalue())
            self.assertIn("GPU",wizard.term.stream.getvalue())
    def test_unknown_size_requires_budget_before_downloading(self):
        api=model_api();api.manifest_size.return_value=None
        with self.assertRaises(SetupError):self.wizard(["nan"],api).resource_budget("custom")
        api.pull.assert_not_called()
    def test_empty_installed_selection_and_back(self):
        api=model_api();api.models.return_value=[]
        with self.assertRaises(SetupError):self.wizard(["5"],api).select_model()
        self.assertIsNone(self.wizard(["6"],api).select_model())
    def test_failed_model_verification_does_not_return_selected_model(self):
        api=model_api();api.models.return_value=[{"name":"local:latest"}];api.show.side_effect=SetupError("missing")
        with self.assertRaises(SetupError):self.wizard(["5","1"],api).select_model()
    def test_failed_configuration_write_preserves_old_model(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"config.json";save_model("old:latest",path)
            with patch("os.replace",side_effect=OSError("disk error")),self.assertRaises(OSError):save_model("new:latest",path)
            self.assertEqual(load_model(path),"old:latest")
    def test_installer_requires_confirmation_before_execution(self):
        api=model_api();api.healthy.return_value=False
        wizard=self.wizard(["1","n","CANCEL"],api)
        def run(argv,**kwargs):
            if "--output" in argv:Path(argv[argv.index("--output")+1]).write_text("#!/bin/sh\nexit 0\n")
            return SimpleNamespace(returncode=0)
        with patch("shutil.which",side_effect=lambda name:None if name=="ollama" else "/usr/bin/curl"),patch("sys.platform","linux"),patch("subprocess.run",side_effect=run) as runner:
            self.assertFalse(wizard.install_ollama())
            self.assertEqual(len(runner.call_args_list),1)
            self.assertIn("https://ollama.com/install.sh",runner.call_args.args[0])
    def test_native_pull_failure_reports_error_and_uses_local_endpoint(self):
        api=Ollama()
        with patch("shutil.which",return_value="/usr/bin/ollama"),patch("subprocess.run",return_value=SimpleNamespace(returncode=1)) as runner:
            with self.assertRaises(SetupError):api.pull("qwen3-coder:30b")
            self.assertEqual(runner.call_args.args[0],["/usr/bin/ollama","pull","qwen3-coder:30b"])
            self.assertEqual(runner.call_args.kwargs["env"]["OLLAMA_HOST"],"http://127.0.0.1:11434")
    def test_terminal_removes_c1_and_escape_sequences(self):
        self.assertEqual(plain("\x1b[31mred\x1b[0m\x9b31m"),"red31m")

class AgentEdges(unittest.IsolatedAsyncioTestCase):
    async def test_repeated_cursor_is_blocked(self):
        session=Mock();session.list_tools=AsyncMock(return_value=SimpleNamespace(tools=[],nextCursor="same"))
        with self.assertRaises(AgentError):await discover(session)
    async def test_external_schema_reference_is_blocked(self):
        bad=SimpleNamespace(name="bad",description="",inputSchema={"type":"object","properties":{"x":{"$ref":"http://example.com/schema"}}})
        session=Mock();session.list_tools=AsyncMock(return_value=SimpleNamespace(tools=[bad],nextCursor=None))
        with self.assertRaises(AgentError):await discover(session)
    async def test_malformed_probe_reports_actionable_error(self):
        api=model_api();api.show.return_value={"capabilities":["tools"]};api.chat.return_value={"tool_calls":[None]}
        with self.assertRaises(AgentError):await verify_tools(api,"local")
    async def test_denied_approval_and_bad_args_never_dispatch(self):
        tool=SimpleNamespace(name="nmap_scan",description="",inputSchema={"type":"object","properties":{"target":{"type":"string"},"scan_type":{"type":"string"},"ports":{"type":"string"},"additional_args":{"type":"string"}},"required":["target"]})
        session=Mock();session.call_tool=AsyncMock()
        agent=Agent(Mock(),"local",session,{"nmap_scan":tool},Policy(["127.0.0.1"]),lambda _:False,lambda _:None)
        for args in ({"target":"127.0.0.1"},{"target":"127.0.0.1;id"},{"target":13}):
            self.assertTrue((await agent.execute("nmap_scan",args,{"nmap_scan"}))["isError"])
        session.call_tool.assert_not_awaited()
    async def test_backend_error_inside_mcp_content_is_not_success(self):
        data=result_data(SimpleNamespace(isError=False,content=[SimpleNamespace(type="text",text='{"success":false,"error":"unavailable"}')],structuredContent=None))
        self.assertTrue(data["isError"])
    async def test_diagnostics_fail_when_real_health_payload_is_unhealthy(self):
        session=Mock();session.call_tool=AsyncMock(return_value=SimpleNamespace(isError=False,content=[SimpleNamespace(type="text",text='{"status":"unhealthy"}')],structuredContent=None))
        @asynccontextmanager
        async def connection():yield session,{"server_health":object()}
        with patch("redvector_ollama_agent.bridge",connection),self.assertRaises(AgentError):
            await connection_test(Terminal(io.StringIO()))
    async def test_model_only_claim_is_labeled_as_unexecuted(self):
        api=model_api();api.chat.return_value={"role":"assistant","content":"Scan succeeded."}
        agent=Agent(api,"local",Mock(),{},Policy(),lambda _:False,lambda _:None)
        self.assertIn("No MCP operation was executed",await agent.turn("Scan something"))

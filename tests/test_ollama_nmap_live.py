"""Actual native Nmap/MCP/backend; model boundary isolated, only test-owned loopback."""
import asyncio
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import patch,AsyncMock,Mock
ROOT=Path(__file__).resolve().parents[1]

@unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("REDVECTOR_RUN_SMOKE")=="1",
                     "Requires native Linux and REDVECTOR_RUN_SMOKE=1")
class NativeNmap(unittest.TestCase):
    def test_authorized_request_runs_real_nmap_only_against_owned_listener(self):
        import psutil
        from redvector_ollama_agent import bridge,Agent
        from redvector_ollama_policy import Policy
        from test_ollama_linux_bridge import capture_started_backends
        self.assertTrue(shutil.which("nmap"),"Real Nmap unavailable; do not simulate scan success")
        with socket.socket() as available:
            available.bind(("127.0.0.1",0));backend_port=available.getsockname()[1]
        with socket.socket() as target:
            target.bind(("127.0.0.1",0));target.listen()
            host,scan_port=target.getsockname()
            with tempfile.TemporaryDirectory(prefix="rv scoped nmap ",dir=ROOT) as d:
                directory=Path(d);bindir=directory/"bin";bindir.mkdir()
                python=bindir/"python3"
                python.write_text('#!/bin/bash\nexec "'+sys.executable+'" "$@"\n');python.chmod(0o755)
                env={"REDVECTOR_HOST":"127.0.0.1","REDVECTOR_PORT":str(backend_port),
                     "REDVECTOR_API_TOKEN":secrets.token_hex(24),"XDG_CONFIG_HOME":str(directory/"config"),
                     "PATH":str(bindir)+os.pathsep+os.environ["PATH"]}
                started=time.time();owned={}
                try:
                    with patch.dict(os.environ,env):
                        async def run():
                            async with bridge() as (session,catalog):
                                self.assertEqual(len(catalog),328)
                                api=Mock();exchanges=[];outputs=[];approvals=[]
                                async def chat(model,messages,schemas):
                                    exchanges.append(messages)
                                    if not schemas:
                                        facts=json.loads(messages[-1]["content"])
                                        return {"role":"assistant","content":json.dumps({"status":facts["status"],"open_ports":facts["open_ports"]})}
                                    return {"role":"assistant","content":"","tool_calls":[{"function":{"name":"nmap_scan",
                                        "arguments":{"target":host,"ports":str(scan_port)}}}]}
                                api.async_chat=AsyncMock(side_effect=chat)
                                agent=Agent(api,"boundary-double",session,catalog,Policy([host]),
                                    lambda operation:approvals.append(operation) or True,outputs.append)
                                answer=await agent.turn("Scan "+host+" for open TCP port "+str(scan_port))
                                self.assertIn("actual MCP",answer)
                                self.assertEqual(len(approvals),0)
                                actual=[json.loads(value) for value in outputs if json.loads(value).get("source")=="mcp"]
                                self.assertEqual(len(actual),1)
                                payload=json.loads(actual[0]["content"][0]["text"])
                                self.assertTrue(payload.get("success"),payload)
                                self.assertIn(str(scan_port)+"/tcp",payload["stdout"])
                                self.assertIn("open",payload["stdout"])
                                self.assertFalse(payload.get("recovery_info",{}).get("recovery_applied",False))
                                self.assertFalse(agent.last_invocation[1]["use_recovery"])
                                self.assertIn("--max-rate 50",agent.last_invocation[1]["additional_args"])
                                compact=json.loads(exchanges[-1][-1]["content"])
                                self.assertIn(str(scan_port)+"/tcp",compact["open_ports"])
                                self.assertNotIn("stdout",compact)
                                self.assertEqual(agent.results.load()["mcp"],actual[0])
                                from redvector_ollama_setup import OllamaTimeout
                                api.async_chat.side_effect=OllamaTimeout("Injected summary timeout")
                                failed=await agent.summarize_saved()
                                self.assertIn("COMPLETED SUCCESSFULLY",failed)
                                self.assertIn("timeout",failed)
                                self.assertEqual(len(actual),1)
                                print("REAL SCOPED NMAP PASS: explicit loopback scope, bounded automatic policy, native Nmap, real MCP/backend output, open owned TCP port, recovery disabled; 328 tools.")
                        asyncio.run(run())
                finally:
                    owned.update(capture_started_backends(directory,ROOT,backend_port,started))
                    for pid,created in owned.items():
                        try:
                            process=psutil.Process(pid)
                            if process.create_time()==created and str(ROOT/"redvector_server.py") in process.cmdline():
                                process.terminate()
                                try:process.wait(timeout=10)
                                except psutil.TimeoutExpired:process.kill();process.wait(timeout=5)
                        except psutil.NoSuchProcess:pass

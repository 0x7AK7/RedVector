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
                                await agent.refresh_profiles()
                                self.assertTrue(agent.runtime_verified,agent.policy.profile_status)
                                self.assertEqual(agent.policy.profile_status.get("service-version-v1",{}).get("state"),"Ready",agent.policy.profile_status)
                                agent.version_task=True
                                data=await agent.execute("nmap_scan",{"target":host,"ports":str(scan_port),"scan_type":"-sT -sV"},{"nmap_scan"})
                                self.assertFalse(data["isError"],data)
                                payload=json.loads(data["content"][0]["text"])
                                self.assertTrue(payload["success"],payload)
                                self.assertEqual(payload["profile"],"service-version-v1")
                                self.assertEqual(len(approvals),1)
                                self.assertEqual(agent.policy.auto_count,1)
                                report=await agent.execute("create_scan_summary",{"target":"saved"},{"create_scan_summary"})
                                self.assertFalse(report["isError"],report)
                                self.assertEqual(agent.last_invocation[1]["vulnerabilities_found"],0)
                                print("REAL MCP REVIEWED PROFILE PASS: attested backend, exact approval, isolated native service probes, saved-evidence summary through actual MCP/backend; no inferred vulnerabilities.")
                                for tool_name,arguments in [
                                    ("create_vulnerability_report",{"vulnerabilities":"saved"}),
                                    ("format_tool_output_visual",{"output":"saved"}),
                                    ("server_health",{}),("get_cache_stats",{}),
                                    ("get_telemetry",{}),("error_handling_statistics",{}),
                                    ("clear_cache",{})]:
                                    data=await agent.execute(tool_name,arguments,{tool_name})
                                    self.assertFalse(data["isError"],(tool_name,data))
                                self.assertEqual(len(approvals),2)  # service probes and test-owned backend cache mutation
                                print("REAL NINE-TOOL MCP PASS: health/cache/telemetry/error statistics, approved cache clear, Nmap, three saved-evidence formatters. Only the test-owned backend was mutated.")
                                advanced=await agent.execute("nmap_advanced_scan",{"target":host,"ports":str(scan_port),"scan_type":"-sT -sV"},{"nmap_advanced_scan"})
                                self.assertFalse(advanced["isError"],advanced)
                                self.assertEqual(agent.results.load()["tool"],"nmap_advanced_scan")
                                from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
                                import threading
                                requests=[]
                                class OwnedHTTP(BaseHTTPRequestHandler):
                                    def log_message(self,*args):pass
                                    def do_GET(self):
                                        requests.append(self.path);self.send_response(200);self.end_headers();self.wfile.write(b"Owned test response")
                                web=ThreadingHTTPServer((host,0),OwnedHTTP);thread=threading.Thread(target=web.serve_forever,daemon=True);thread.start()
                                url="http://"+host+":"+str(web.server_port)+"/"
                                try:
                                    for tool_name,args in [("http_framework_test",{"url":url}),("http_repeater",{"request_spec":{"url":url}}),("nuclei_scan",{"target":url})]:
                                        outcome=await agent.execute(tool_name,args,{tool_name})
                                        self.assertFalse(outcome["isError"],(tool_name,outcome))
                                    from redvector_ollama_results import payloads
                                    actual=payloads(outcome)[0]
                                    self.assertEqual(len(actual["findings"]),2)
                                    report=await agent.execute("create_vulnerability_report",{"vulnerabilities":"saved"},{"create_vulnerability_report"})
                                    self.assertFalse(report["isError"],report)
                                    self.assertEqual(len(json.loads(agent.last_invocation[1]["vulnerabilities"])),2)
                                    self.assertEqual(requests,["/","/","/"])
                                    self.assertEqual(len(approvals),3)
                                    print("REAL THIRTEEN-TOOL MCP PASS: shared advanced Nmap, root GET/repeater, native sandboxed Nuclei; two real observations propagated into the actual report; three HTTP GETs; no extra approval for bounded reads.")
                                finally:web.shutdown();web.server_close();thread.join()



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

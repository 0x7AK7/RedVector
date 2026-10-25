"""Opt-in real Linux launcher/ownership/MCP integration. No model or targets needed."""
import asyncio
import hashlib
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
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]

def capture_started_backends(directory,root,port,started):
    """Read the actual launcher PID log even when the backend has not bound yet."""
    import psutil
    import re
    found={}
    for log in (Path(directory)/"config"/"redvector-ollama").glob("mcp-*.log"):
        for value in re.findall(r"\[RedVector\] Server PID: ([0-9]+)",log.read_text(errors="replace")):
            try:
                process=psutil.Process(int(value));args=process.cmdline();created=process.create_time()
                if (created>=started-1 and str(root/"redvector_server.py") in args
                    and "--port" in args and args[args.index("--port")+1]==str(port)):
                    found[process.pid]=created
            except (psutil.NoSuchProcess,psutil.AccessDenied,ValueError):pass
    return found

@unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("REDVECTOR_RUN_SMOKE")=="1",
                     "Requires Linux and REDVECTOR_RUN_SMOKE=1")
class RealLinuxBridgeTests(unittest.TestCase):
    def test_actual_crlf_launcher_starts_then_reuses_backend(self):
        import psutil
        import requests
        from redvector_ollama_agent import bridge,Agent
        from redvector_ollama_policy import Policy
        from redvector_backend_check import backend_state
        before=hashlib.sha256((ROOT/"start_redvector.sh").read_bytes()).hexdigest()
        with socket.socket() as available:
            available.bind(("127.0.0.1",0));port=available.getsockname()[1]
        self.assertEqual(backend_state(ROOT,"127.0.0.1",port),1)
        started=time.time();owned={}
        def listener_pid():
            matches=[connection.pid for connection in psutil.net_connections(kind="tcp")
                     if connection.laddr.port==port and connection.status=="LISTEN" and connection.pid]
            if len(set(matches))!=1:raise AssertionError("Could not identify unique test backend PID")
            return matches[0]
        with tempfile.TemporaryDirectory(prefix="rv real bridge ",dir=ROOT) as d:
            directory=Path(d);bindir=directory/"bin";bindir.mkdir()
            python=bindir/"python3"
            python.write_text('#!/bin/bash\nexec "'+sys.executable+'" "$@"\n',newline="\n");python.chmod(0o755)
            env={"REDVECTOR_HOST":"127.0.0.1","REDVECTOR_PORT":str(port),
                 "REDVECTOR_API_TOKEN":secrets.token_hex(24),"XDG_CONFIG_HOME":str(directory/"config"),
                 "PATH":str(bindir)+os.pathsep+os.environ["PATH"]}
            try:
                with patch.dict(os.environ,env):
                    async def roundtrip():
                        async with bridge() as (session,catalog):
                            self.assertEqual(len(catalog),328)
                            pid=listener_pid()
                            process=psutil.Process(pid)
                            self.assertGreaterEqual(process.create_time(),started-1)
                            self.assertTrue(any(str(ROOT/"redvector_server.py")==arg for arg in process.cmdline()))
                            owned[pid]=process.create_time()
                            self.assertEqual(backend_state(ROOT,"127.0.0.1",port),0)
                            agent=Agent(None,"unused",session,catalog,Policy(),lambda _:False,lambda _:None)
                            data=await agent.execute("server_health",{},{"server_health"})
                            self.assertFalse(data["isError"],data)
                            self.assertEqual(json.loads(data["content"][0]["text"])["status"],"healthy")
                            return pid
                    first=asyncio.run(roundtrip());second=asyncio.run(roundtrip())
                    self.assertEqual(first,second,"A duplicate backend was started")
                    http=requests.Session();http.trust_env=False
                    url=f"http://127.0.0.1:{port}/api/cache/stats"
                    self.assertIn(http.get(url,timeout=3).status_code,(401,403))
                    self.assertIn(http.get(url,headers={"Authorization":"Bearer invalid-test-token"},timeout=3).status_code,(401,403))
                    self.assertEqual(http.get(url,headers={"Authorization":"Bearer "+env["REDVECTOR_API_TOKEN"]},timeout=3).status_code,200)
                    print("REAL LINUX BRIDGE PASS: launcher startup, verified ownership, 328 MCP tools, actual health, same backend reused, authentication enforced.")
            finally:
                # Stop only the newly-created, identity-checked listener on this test's free port.
                owned.update(capture_started_backends(directory,ROOT,port,started))
                for pid,created in owned.items():
                    try:
                        process=psutil.Process(pid)
                        if process.create_time()==created and str(ROOT/"redvector_server.py") in process.cmdline():
                            process.terminate()
                            try:process.wait(timeout=10)
                            except psutil.TimeoutExpired:process.kill();process.wait(timeout=5)
                    except psutil.NoSuchProcess:pass
        self.assertEqual(hashlib.sha256((ROOT/"start_redvector.sh").read_bytes()).hexdigest(),before)
        self.assertFalse(list(ROOT.glob(".ollama-launch-*.sh")))

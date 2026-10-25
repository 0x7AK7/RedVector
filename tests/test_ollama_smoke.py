"""Opt-in REAL backend + REAL MCP SDK smoke. No target, scan, or model download.

Run: REDVECTOR_RUN_SMOKE=1 python -m pytest -q tests/test_ollama_smoke.py
The regular offline tests deliberately use model-boundary doubles and are labeled.
"""
import asyncio
from datetime import timedelta
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]

@unittest.skipUnless(os.environ.get("REDVECTOR_RUN_SMOKE")=="1","Set REDVECTOR_RUN_SMOKE=1 for the real backend/MCP smoke")
class RealMCPSmoke(unittest.TestCase):
    def test_actual_backend_and_mcp_read_only_tools(self):
        from mcp import ClientSession,StdioServerParameters
        from mcp.client.stdio import stdio_client
        import requests
        from redvector_ollama_agent import Agent,discover,result_data
        from redvector_ollama_policy import Policy
        # Bind only a fresh loopback port; never reuse or stop an existing backend.
        with socket.socket() as probe:
            probe.bind(("127.0.0.1",0));port=probe.getsockname()[1]
        env=dict(os.environ,REDVECTOR_API_TOKEN=secrets.token_hex(24),
                 REDVECTOR_HOST="127.0.0.1",REDVECTOR_PORT=str(port),
                 PYTHONIOENCODING="utf-8",PYTHONUNBUFFERED="1",NO_PROXY="*",no_proxy="*")
        with tempfile.TemporaryDirectory(prefix="redvector real smoke ") as directory:
            with open(Path(directory)/"backend.log","w",encoding="utf8") as log:
                child=subprocess.Popen([sys.executable,str(ROOT/"redvector_server.py"),
                    "--host","127.0.0.1","--port",str(port)],cwd=directory,env=env,
                    stdout=log,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL)
                try:
                    http=requests.Session();http.trust_env=False
                    url=f"http://127.0.0.1:{port}"
                    for _ in range(120):
                        if child.poll() is not None:
                            self.fail("Real backend exited: "+(Path(directory)/"backend.log").read_text(encoding="utf8")[-3000:])
                        try:
                            response=http.get(url+"/health",timeout=1)
                            if response.status_code==200 and response.json().get("status")=="healthy":break
                        except requests.RequestException:pass
                        time.sleep(.25)
                    else:self.fail("Real backend health check timed out")
                    # Confirm authentication is still active on a protected route.
                    self.assertIn(http.get(url+"/api/cache/stats",timeout=2).status_code,(401,403))
                    async def smoke():
                        params=StdioServerParameters(command=sys.executable,
                            args=[str(ROOT/"redvector_mcp.py"),"--server",url],cwd=directory,env=env)
                        with open(Path(directory)/"mcp.log","w",encoding="utf8") as errors:
                            async with stdio_client(params,errlog=errors) as streams:
                                async with ClientSession(*streams,read_timeout_seconds=timedelta(seconds=120)) as session:
                                    await session.initialize()
                                    catalog=await discover(session)
                                    self.assertEqual(len(catalog),328)
                                    for name in ("server_health","get_cache_stats"):
                                        agent=Agent(None,"unused",session,catalog,Policy(),
                                                    lambda _:False,lambda _:None)
                                        data=await agent.execute(name,{},set(catalog))
                                        self.assertFalse(data["isError"],data)
                                        payload=json.loads(data["content"][0]["text"])
                                        if name=="server_health":self.assertEqual(payload["status"],"healthy")
                                        else:self.assertIn("hit_rate",payload)
                                    print("REAL SMOKE: initialized MCP; 328 tools; actual backend health and cache output; authentication enforced.")
                                    model=os.environ.get("REDVECTOR_LIVE_MODEL")
                                    if model:
                                        from ollama_live_helpers import live_model_roundtrip
                                        await live_model_roundtrip(session,catalog,model)
                    asyncio.run(smoke())
                finally:
                    # Windows venv executables can create a Python child; terminate only
                    # descendants of the backend process this test created.
                    import psutil
                    try:owned=psutil.Process(child.pid).children(recursive=True)
                    except psutil.NoSuchProcess:owned=[]
                    for process in reversed(owned):
                        try:process.terminate()
                        except psutil.NoSuchProcess:pass
                    if child.poll() is None:
                        child.terminate()
                        try:child.wait(timeout=10)
                        except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
                    _,alive=psutil.wait_procs(owned,timeout=5)
                    for process in alive:
                        try:process.kill()
                        except psutil.NoSuchProcess:pass
                    psutil.wait_procs(alive,timeout=5)

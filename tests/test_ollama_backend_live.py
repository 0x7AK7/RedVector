"""Real cross-checkout backend -> Ollama MCP bridge, without a model/download."""
import asyncio
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]

@unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("REDVECTOR_RUN_SMOKE")=="1",
                     "Requires Linux and REDVECTOR_RUN_SMOKE=1")
class CrossCheckoutBackend(unittest.TestCase):
    def test_existing_other_checkout_backend_is_reused_for_real_mcp(self):
        import psutil
        import requests
        from redvector_ollama_agent import bridge,Agent
        from redvector_ollama_policy import Policy
        from redvector_ollama_backend import inspect_backend,BackendReuseError
        from redvector_backend_check import backend_state
        with socket.socket() as probe:
            probe.bind(("127.0.0.1",0));port=probe.getsockname()[1]
        with tempfile.TemporaryDirectory(prefix="rv cross checkout ") as directory:
            root=Path(directory);other=root/"separate installation";other.mkdir()
            for name in ("redvector_server.py","redvector_banner.py","redvector_mcp.py"):
                shutil.copyfile(ROOT/name,other/name)
            binary=root/"bin";binary.mkdir()
            python=binary/"python3"
            python.write_text('#!/bin/bash\nexec "'+sys.executable+'" "$@"\n')
            python.chmod(0o755)
            env=dict(os.environ,REDVECTOR_HOST="127.0.0.1",REDVECTOR_PORT=str(port),
                     REDVECTOR_API_TOKEN=secrets.token_hex(24),NO_PROXY="*",no_proxy="*",
                     PATH=str(binary)+os.pathsep+os.environ["PATH"],XDG_CONFIG_HOME=str(root/"config"))
            with (root/"backend.log").open("w") as log:
                child=subprocess.Popen([sys.executable,str(other/"redvector_server.py"),
                    "--host","127.0.0.1","--port",str(port)],cwd=other,env=env,
                    stdout=log,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL)
                try:
                    http=requests.Session();http.trust_env=False
                    for _ in range(120):
                        if child.poll() is not None:self.fail("Test backend exited before readiness: "+(root/"backend.log").read_text(errors="replace")[-2500:])
                        try:
                            if http.get(f"http://127.0.0.1:{port}/health",timeout=1).status_code==200:break
                        except requests.RequestException:pass
                        time.sleep(.25)
                    else:self.fail("Test backend startup timed out")
                    created=psutil.Process(child.pid).create_time()
                    # Demonstrate the exact original path-based refusal.
                    self.assertEqual(backend_state(ROOT,"127.0.0.1",port),2)
                    with patch.dict(os.environ,env):
                        proof=inspect_backend(ROOT,"127.0.0.1",port)
                        self.assertEqual(proof.pid,child.pid)
                        self.assertEqual(proof.script.parent,other)
                        with patch.dict(os.environ,{"REDVECTOR_API_TOKEN":"invalid-test-token"}):
                            with self.assertRaisesRegex(BackendReuseError,"token"):
                                inspect_backend(ROOT,"127.0.0.1",port)
                        async def real_roundtrip():
                            async with bridge() as (session,catalog):
                                self.assertEqual(len(catalog),328)
                                data=await Agent(None,"unused",session,catalog,Policy(),lambda _:False,lambda _:None).execute(
                                    "server_health",{},{"server_health"})
                                self.assertFalse(data["isError"],data)
                                actual=json.loads(data["content"][0]["text"])
                                self.assertEqual(actual["status"],"healthy")
                                self.assertEqual(actual["version"],"8.0.0")
                        asyncio.run(real_roundtrip())
                        asyncio.run(real_roundtrip())
                        self.assertIsNone(child.poll(),"Bridge must leave the reused backend running")
                        self.assertEqual(psutil.Process(child.pid).create_time(),created)
                        self.assertEqual(inspect_backend(ROOT,"127.0.0.1",port).pid,child.pid)
                    print("REAL CROSS-CHECKOUT PASS: original checker refused; independently verified reuse; two MCP sessions; 328 tools; real server_health healthy 8.0.0; authentication enforced; same PID retained.")
                finally:
                    # Only the child created above on a previously free test endpoint.
                    if child.poll() is None:
                        child.terminate()
                        try:child.wait(timeout=10)
                        except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)

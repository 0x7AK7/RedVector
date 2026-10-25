"""Legacy SDK stubbing must preserve unrelated dependency module identity."""
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]

class MCPFixtureIsolation(unittest.TestCase):
    def test_fresh_interpreter_keeps_client_and_runtime_requests_identical(self):
        code="""
import sys
sys.path.insert(0,sys.argv[1])
from test_mcp_health import load_client
client=load_client()
import requests
assert client.requests is requests, "SDK fixture replaced Requests module identity"
from mcp import ClientSession
requests.Session().prepare_request(requests.Request("GET","http://127.0.0.1/"))
"""
        result=subprocess.run([sys.executable,"-c",code,str(ROOT/"tests")],
            cwd=ROOT,capture_output=True,text=True,encoding="utf8",timeout=30)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

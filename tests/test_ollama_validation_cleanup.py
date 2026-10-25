"""A failed startup must remain cleanable before its backend has bound a socket."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from test_ollama_linux_bridge import ROOT

class ValidationCleanup(unittest.TestCase):
    def test_capture_launcher_pid_before_listening(self):
        from test_ollama_linux_bridge import capture_started_backends
        with tempfile.TemporaryDirectory(dir=ROOT) as d:
            root=Path(d);script=root/"redvector_server.py"
            script.write_text("import sys\nprint('ready',flush=True)\nsys.stdin.read()\n")
            started=time.time()
            process=subprocess.Popen([sys._base_executable,str(script),"--host","127.0.0.1","--port","42583"],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
            try:
                self.assertEqual(process.stdout.readline().strip(),"ready")
                config=root/"config"/"redvector-ollama";config.mkdir(parents=True)
                (config/"mcp-test.log").write_text(f"[RedVector] Server PID: {process.pid}\n")
                found=capture_started_backends(root,root,42583,started)
                self.assertIn(process.pid,found)
            finally:
                process.communicate(timeout=5)

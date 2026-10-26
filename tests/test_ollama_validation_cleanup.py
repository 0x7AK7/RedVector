"""A failed startup must remain cleanable before its backend has bound a socket."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock,patch
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


    def test_linux_boot_time_rounding_keeps_fresh_but_not_old_logged_processes(self):
        from test_ollama_linux_bridge import capture_started_backends
        with tempfile.TemporaryDirectory(dir=ROOT) as d:
            root=Path(d)
            config=root/"config"/"redvector-ollama";config.mkdir(parents=True)
            (config/"mcp-clock.log").write_text("[RedVector] Server PID: 123\n")
            process=Mock();process.pid=123
            process.cmdline.return_value=[str(root/"redvector_server.py"),"--port","42583"]
            process.create_time.return_value=900.0
            for kernel_start,expected in [(1000.0,{123:900.0}),(990.0,{})]:
                with self.subTest(kernel_start=kernel_start),patch("sys.platform","linux"),patch("psutil.Process",return_value=process),patch("test_ollama_linux_bridge._source_start_limit",return_value=kernel_start,create=True):
                    self.assertEqual(capture_started_backends(root,root,42583,1000.0),expected)

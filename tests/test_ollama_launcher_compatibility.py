"""Execute the real launcher adapter under Bash; OS boundaries alone are fixtures."""
from hashlib import sha256
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from test_launcher import BASH,ROOT
from redvector_ollama_agent import launcher_script

@unittest.skipUnless(sys.platform.startswith("linux"),"Requires Kali/Linux Bash and file permissions")
class LauncherCompatibilityTests(unittest.TestCase):
    def test_actual_bash_executes_windows_crlf_and_native_lf_via_adapter(self):
        for endings in ("LF","CRLF"):
            with self.subTest(endings=endings),tempfile.TemporaryDirectory(prefix="rv compatibility ",dir=ROOT) as d:
                project=Path(d)
                data=(ROOT/"start_redvector.sh").read_bytes().replace(b"\r\n",b"\n")
                original=data.replace(b"\n",b"\r\n") if endings=="CRLF" else data
                source=project/"start_redvector.sh";source.write_bytes(original)
                digest=sha256(source.read_bytes()).hexdigest()
                bindir=project/".venv"/"bin";bindir.mkdir(parents=True)
                interpreter=bindir/"python3"
                interpreter.write_text('''#!/bin/bash
case "$1" in
  */redvector_ollama_backend.py) exit 0 ;;
  */redvector_mcp.py) printf '{"transport":"stdio","project":"%s"}\\n' "$PWD" ;;
  *) exit 99 ;;
esac
''',newline="\n")
                interpreter.chmod(0o755)
                curl=bindir/"curl";curl.write_text("#!/bin/bash\nexit 0\n");curl.chmod(0o755)
                env=dict(os.environ,PATH=str(bindir)+os.pathsep+os.environ["PATH"])
                with patch("redvector_ollama_agent.ROOT",project),launcher_script() as selected:
                    result=subprocess.run([BASH,str(selected)],cwd="/tmp",env=env,capture_output=True,text=True,timeout=10)
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertIn('"transport":"stdio"',result.stdout)
                    self.assertIn(str(project),result.stdout)
                    self.assertIn("Backend already running",result.stderr)
                self.assertEqual(sha256(source.read_bytes()).hexdigest(),digest)
                self.assertFalse(list(project.glob(".ollama-launch-*.sh")))

    def test_disappeared_pinned_backend_refuses_startup_in_real_bash(self):
        import socket
        with socket.socket() as probe:
            probe.bind(("127.0.0.1",0));port=probe.getsockname()[1]
        with tempfile.TemporaryDirectory(prefix="rv pinned startup ",dir=ROOT) as d:
            project=Path(d)
            (project/"start_redvector.sh").write_bytes((ROOT/"start_redvector.sh").read_bytes())
            bindir=project/".venv"/"bin";bindir.mkdir(parents=True)
            interpreter=bindir/"python3"
            interpreter.write_text('#!/bin/bash\nshift\nexec "'+sys.executable+'" "'+str(ROOT/"redvector_ollama_backend.py")+'" "$@"\n')
            interpreter.chmod(0o755)
            env=dict(os.environ,REDVECTOR_HOST="127.0.0.1",REDVECTOR_PORT=str(port),
                     REDVECTOR_OLLAMA_BACKEND_PIN="44:1.0")
            with patch("redvector_ollama_agent.ROOT",project),launcher_script() as script:
                result=subprocess.run([BASH,str(script)],env=env,capture_output=True,text=True,timeout=10)
            self.assertNotEqual(result.returncode,0)
            self.assertIn("disappeared",result.stderr)
            self.assertNotIn("Server PID:",result.stderr)
            self.assertFalse((project/"server.log").exists())

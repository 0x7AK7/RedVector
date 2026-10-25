"""Exercise real script entry-point exception identity without a model/network call."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]

class CLIErrorRecovery(unittest.TestCase):
    def test_agent_error_returns_script_to_startup_menu_without_traceback(self):
        bootstrap="""
import builtins,sys
import psutil  # Load the real platform backend before overriding only the CLI OS guard.
# Only bypass the OS entry guard; no service or tool calls are performed.
sys.platform="linux"
from pathlib import Path
entry=Path(sys.argv[1])
answers=iter(["1","6"])
def answer():
    main=sys.modules["__main__"]
    main.Ollama.healthy=lambda self:True
    main.Ollama.show=lambda self,model:{"capabilities":["completion"]}
    import redvector_ollama_agent as agent
    async def rejected(api,model):
        raise agent.AgentError("Unsupported model: choose another model.")
    agent.verify_tools=rejected
    return next(answers)
builtins.input=answer
sys.argv=[str(entry)]
__file__=str(entry)
exec(compile(entry.read_text(encoding="utf8"),str(entry),"exec"),globals())
"""
        with tempfile.TemporaryDirectory() as d:
            config=Path(d)/"redvector-ollama";config.mkdir()
            (config/"config.json").write_text(json.dumps({"model":"local:latest"}))
            result=subprocess.run([sys.executable,"-c",bootstrap,str(ROOT/"redvector_ollama_setup.py")],
                cwd=ROOT,env=dict(os.environ,XDG_CONFIG_HOME=d,NO_COLOR="1",PYTHONIOENCODING="utf8"),
                capture_output=True,text=True,encoding="utf8",timeout=20)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn("Unsupported model: choose another model.",result.stdout)
        self.assertGreaterEqual(result.stdout.count("Choose 1-6:"),2)
        self.assertNotIn("Traceback",result.stderr)

"""Run the actual Bash entry points in isolated projects, including paths with spaces."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from test_launcher import BASH,ROOT

@unittest.skipUnless(BASH and Path(BASH).exists(),"Bash is unavailable")
class OllamaShellTests(unittest.TestCase):
    def launch(self,name,dependencies=True,answer=None):
        with tempfile.TemporaryDirectory(prefix="ollama user project ",dir=ROOT) as directory:
            project=Path(directory)
            shutil.copyfile(ROOT/name,project/name)
            venv=project/".venv"/"bin";venv.mkdir(parents=True)
            interpreter=venv/"python3"
            interpreter.write_text('''#!/bin/bash
if [[ "$1" == -c || "$1" == */redvector_ollama_dependencies.py ]]; then
    [[ "$RV_DEPS_OK" == 1 || -f "$0.installed" ]]
elif [[ "$1" == -m && "$2" == pip ]]; then
    touch "$0.installed"
    printf 'DEPENDENCIES_INSTALLED\\n'
else
    printf 'ENTRY=%s\\n' "$1"
    shift
    printf 'ARG=%s\\n' "$@"
fi
''',encoding="utf8",newline="\n")
            interpreter.chmod(0o755)
            caller=project/"unrelated caller";caller.mkdir()
            claude=project/"claude_desktop_config.json";claude.write_bytes(b'{"preserve":true}')
            result=subprocess.run([BASH,(project/name).as_posix()],cwd=caller,
                env=dict(os.environ,RV_DEPS_OK="1" if dependencies else "0"),capture_output=True,
                text=True,input=answer,encoding="utf8",timeout=10)
            self.assertEqual(claude.read_bytes(),b'{"preserve":true}')
            return result
    def test_installer_resolves_project_with_spaces_and_uses_venv(self):
        result=self.launch("install_redvector_ollama.sh")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn("redvector_ollama_setup.py",result.stdout)
        self.assertIn("ARG=--install",result.stdout)
    def test_separate_launcher_uses_same_setup_without_install_flag(self):
        result=self.launch("start_redvector_ollama.sh")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn("redvector_ollama_setup.py",result.stdout)
        self.assertNotIn("--install",result.stdout)
    def test_missing_dependencies_fail_before_wizard(self):
        for name in ("install_redvector_ollama.sh","start_redvector_ollama.sh"):
            with self.subTest(name=name):
                result=self.launch(name,dependencies=False)
                self.assertNotEqual(result.returncode,0)
                self.assertIn("dependencies",result.stderr)
                self.assertNotIn("ENTRY=",result.stdout)

    def test_installer_can_install_missing_python_dependencies_with_confirmation(self):
        result=self.launch("install_redvector_ollama.sh",dependencies=False,answer="y\n")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn("DEPENDENCIES_INSTALLED",result.stdout)
        self.assertIn("redvector_ollama_setup.py",result.stdout)

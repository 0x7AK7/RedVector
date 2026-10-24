"""Execute the real Bash launcher, substituting only OS/process boundaries."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / 'start_redvector.sh'
BASH = shutil.which('bash') if os.name != 'nt' else r'C:\Program Files\Git\bin\bash.exe'


@unittest.skipUnless(BASH and Path(BASH).exists(), 'Bash is unavailable')
class LauncherTests(unittest.TestCase):
    def launch(self, scenario, venv=False, unrelated_cwd=False, symlink=False):
        with tempfile.TemporaryDirectory(prefix='rv user project ', dir=ROOT) as directory:
            project = Path(directory)
            shutil.copyfile(LAUNCHER, project / 'start_redvector.sh')
            bin_dir = project / 'bin'
            bin_dir.mkdir()
            python = '''#!/bin/bash
case "$1" in
  */redvector_backend_check.py)
    case "$SCENARIO" in
      owned) exit 0 ;;
      foreign) exit 2 ;;
      free) [[ -f started ]] && exit 0 || exit 1 ;;
    esac ;;
  */redvector_server.py) touch started; exit 0 ;;
  */redvector_mcp.py) printf '{"mcp":"stdio","python":"%s"}\\n' "$0" ;;
  *) exit 99 ;;
esac
'''
            files = {'python3': python, 'curl': '''#!/bin/bash
[[ "$SCENARIO" != free || -f started ]]
''', 'setsid': '#!/bin/bash\nexec "$@"\n',
                     'sleep': '#!/bin/bash\nexit 0\n'}
            for name, content in files.items():
                file = bin_dir / name
                file.write_text(content, encoding='utf8', newline='\n')
                file.chmod(0o755)
            if venv:
                venv_dir = project / '.venv' / 'bin'
                venv_dir.mkdir(parents=True)
                file = venv_dir / 'python3'
                file.write_text(python, encoding='utf8', newline='\n')
                file.chmod(0o755)
            tool_path = str(bin_dir) + os.pathsep + os.environ['PATH']
            if os.name == 'nt':
                tool_path = '/' + bin_dir.drive[0].lower() + bin_dir.as_posix()[2:] + ':/usr/bin:/bin'
            bash_env = project / 'test-env.sh'
            bash_env.write_text('export PATH="$RV_TEST_PATH"\n', encoding='utf8')
            env = dict(os.environ, RV_TEST_PATH=tool_path, BASH_ENV=str(bash_env),
                       SCENARIO=scenario)
            caller = project / 'unrelated caller'
            caller.mkdir()
            entry = project / 'start_redvector.sh'
            if symlink:
                entry = caller / 'launcher-link.sh'
                entry.symlink_to(project / 'start_redvector.sh')
            result = subprocess.run([BASH, entry.as_posix()], cwd=caller if unrelated_cwd else project,
                                    env=env, capture_output=True, text=True, timeout=15)
            return result, (project / 'started').exists()

    def test_reuse_owned_backend(self):
        result, started = self.launch('owned')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(started)
        self.assertIn('Backend already running', result.stderr)
        self.assertTrue(result.stdout.startswith('{"mcp":"stdio"'))

    def test_reject_foreign_backend(self):
        result, started = self.launch('foreign')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(started)
        self.assertEqual(result.stdout, '')
        self.assertIn('ERROR', result.stderr)

    def test_start_free_port_with_project_venv(self):
        result, started = self.launch('free', venv=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(started)
        self.assertIn('.venv/bin/python3', result.stdout)
        self.assertIn('Server is healthy', result.stderr)

    def test_invocation_from_unrelated_directory(self):
        result, started = self.launch('free', venv=True, unrelated_cwd=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(started)
        self.assertIn('.venv/bin/python3', result.stdout)

    @unittest.skipIf(os.name == 'nt', 'Native Unix symlink semantics require Linux')
    def test_symlink_entry_from_unrelated_directory(self):
        result, started = self.launch('free', venv=True, unrelated_cwd=True, symlink=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(started)
        self.assertIn('.venv/bin/python3', result.stdout)


if __name__ == '__main__':
    unittest.main()

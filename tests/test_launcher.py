"""Execute the real Bash launcher, substituting only OS/process boundaries."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import sys
import threading

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / 'start_redvector.sh'
BASH = shutil.which('bash') if os.name != 'nt' else r'C:\Program Files\Git\bin\bash.exe'


@unittest.skipUnless(BASH and Path(BASH).exists(), 'Bash is unavailable')
class LauncherTests(unittest.TestCase):
    def launch(self, scenario, venv=False, unrelated_cwd=False, symlink=False, terminal=False,
               native_tty=False, pty_mode=False):
        with tempfile.TemporaryDirectory(prefix='rv user project ', dir=ROOT) as directory:
            project = Path(directory)
            # This fixture represents a native Linux checkout. Windows Git's
            # working-tree CRLF conversion is exercised separately through the
            # new bridge adapter in test_ollama_launcher_compatibility.py.
            (project / 'start_redvector.sh').write_bytes(
                LAUNCHER.read_bytes().replace(b'\r\n', b'\n'))
            for name in ('redvector_banner.py', 'redvector_mcp.py'):
                if (ROOT / name).exists():
                    shutil.copyfile(ROOT / name, project / name)
            bin_dir = project / 'bin'
            bin_dir.mkdir()
            python = '''#!/bin/bash
case "$1" in
  */redvector_banner.py) exec "$RV_REAL_PYTHON" "$@" ;;
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
            bash_env.write_text('''export PATH="$RV_TEST_PATH"
# Substitute only the OS terminal predicate; execute the actual renderer.
[() {
    if [[ "$1" == -t ]]; then
        [[ "$RV_TEST_TTY" == 1 ]]
    else
        builtin [ "$@"
    fi
}
''', encoding='utf8')
            if native_tty:
                bash_env.write_text('export PATH="$RV_TEST_PATH"\n', encoding='utf8')
            real_python = Path(sys.executable).as_posix()
            if os.name == 'nt':
                real_python = '/' + real_python[0].lower() + real_python[2:]
            env = dict(os.environ, RV_TEST_PATH=tool_path, BASH_ENV=str(bash_env),
                       SCENARIO=scenario, RV_TEST_TTY='1' if terminal else '0',
                       RV_REAL_PYTHON=real_python, PYTHONUTF8='1')
            caller = project / 'unrelated caller'
            caller.mkdir()
            entry = project / 'start_redvector.sh'
            if symlink:
                entry = caller / 'launcher-link.sh'
                entry.symlink_to(project / 'start_redvector.sh')
            kwargs = dict(cwd=caller if unrelated_cwd else project, env=env,
                          text=True, encoding='utf8', timeout=15)
            if pty_mode:
                import pty
                master, slave = pty.openpty()
                chunks = []

                def drain():
                    try:
                        while True:
                            chunk = os.read(master, 4096)
                            if not chunk:
                                break
                            chunks.append(chunk)
                    except OSError:
                        pass

                reader = threading.Thread(target=drain, daemon=True)
                reader.start()
                try:
                    result = subprocess.run([BASH, entry.as_posix()], stdin=slave, stderr=slave,
                                            stdout=subprocess.PIPE, **kwargs)
                finally:
                    os.close(slave)
                    reader.join(timeout=3)
                    os.close(master)
                result.stderr = b''.join(chunks).decode('utf8').replace('\r\n', '\n')
            else:
                result = subprocess.run([BASH, entry.as_posix()], capture_output=True, **kwargs)
            return result, (project / 'started').exists()

    def test_reuse_owned_backend(self):
        result, started = self.launch('owned')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(started)
        self.assertIn('Backend already running', result.stderr)
        self.assertTrue(result.stdout.startswith('{"mcp":"stdio"'))
        self.assertNotIn('By Adam K.', result.stderr)

    def test_manual_terminal_reuses_backend_and_renders_original_banner(self):
        result, started = self.launch('owned', terminal=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(started)
        self.assertIn('By Adam K.', result.stderr)
        self.assertIn('THREAT FRAMEWORK', result.stderr)
        self.assertIn('MCP TOOLS', result.stderr)
        self.assertTrue(result.stdout.startswith('{"mcp":"stdio"'))

    def test_manual_terminal_starts_backend_and_renders_once(self):
        result, started = self.launch('free', venv=True, terminal=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(started)
        self.assertEqual(result.stderr.count('By Adam K.'), 1)
        self.assertIn('Server is healthy', result.stderr)
        self.assertTrue(result.stdout.startswith('{"mcp":"stdio"'))

    def test_foreign_backend_is_rejected_before_banner(self):
        result, started = self.launch('foreign', terminal=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(started)
        self.assertNotIn('By Adam K.', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_claude_style_pipes_use_real_terminal_predicate_and_no_banner(self):
        result, started = self.launch('owned', native_tty=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(started)
        self.assertNotIn('By Adam K.', result.stderr)
        self.assertTrue(result.stdout.startswith('{"mcp":"stdio"'))

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Real PTY requires Linux')
    def test_real_terminal_owned_free_and_foreign(self):
        for scenario in ('owned', 'free', 'foreign'):
            with self.subTest(scenario=scenario):
                result, started = self.launch(scenario, native_tty=True, pty_mode=True)
                if scenario == 'foreign':
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn('By Adam K.', result.stderr)
                    self.assertFalse(started)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr.count('By Adam K.'), 1)
                    self.assertEqual(started, scenario == 'free')
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

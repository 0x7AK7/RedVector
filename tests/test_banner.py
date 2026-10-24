"""Golden output and import-isolation checks for the shared startup renderer."""
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BannerTests(unittest.TestCase):
    def render(self, project=ROOT, *args):
        renderer = project / 'redvector_banner.py'
        self.assertTrue(renderer.is_file(), 'Missing side-effect-free shared banner renderer')
        result = subprocess.run([sys.executable, '-B', '-X', 'utf8', str(renderer), *args],
                                cwd=project, capture_output=True, text=True, encoding='utf8',
                                env=dict(os.environ, REDVECTOR_HOST='127.0.0.1', REDVECTOR_PORT='8888',
                                         DEBUG_MODE='0'), timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        return result.stdout

    def test_original_logo_colors_spacing_and_panel(self):
        expected = (ROOT / 'tests/fixtures/startup_banner.txt').read_text(encoding='utf8')
        self.assertEqual(self.render(), expected.replace('@MCP_TOOLS@', '328'))

    def test_host_port_and_debug_match_selected_configuration(self):
        output = self.render(ROOT, '--host', 'localhost', '--port', '9999', '--debug')
        plain = re.sub(r'\x1b\[[0-9;]*m', '', output)
        self.assertIn('Waiting for targets on localhost:9999', plain)
        self.assertIn('localhost:9999', plain)
        self.assertIn('True', plain)

    def test_module_import_is_silent_and_does_not_import_server(self):
        self.assertTrue((ROOT / 'redvector_banner.py').is_file(), 'Missing shared renderer')
        code = '''import sys, socket, subprocess, threading
def forbidden(*args, **kwargs):
    raise AssertionError('Renderer attempted a runtime side effect')
socket.socket = forbidden
subprocess.Popen = forbidden
threading.Thread.start = forbidden
import redvector_banner
assert 'redvector_server' not in sys.modules
'''
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=ROOT,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, '')

    def test_tool_count_comes_from_source_without_importing_tools(self):
        self.assertTrue((ROOT / 'redvector_banner.py').is_file(), 'Missing shared renderer')
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            project = Path(directory)
            (project / 'redvector_banner.py').write_bytes((ROOT / 'redvector_banner.py').read_bytes())
            (project / 'redvector_mcp.py').write_text('''raise RuntimeError('Do not import MCP')
@mcp.tool()
def first(): pass
@mcp.tool()
def second(): pass
''')
            self.assertIn('2 tool handlers armed', self.render(project))


if __name__ == '__main__':
    unittest.main()

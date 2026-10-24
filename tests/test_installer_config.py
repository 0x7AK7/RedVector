"""Exercise the installer's actual embedded config writer in isolated paths."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WRITER = (ROOT / 'install_redvector_claude_mcp.sh').read_text(encoding='utf8').split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]


class InstallerConfigTests(unittest.TestCase):
    def run_writer(self, project, config):
        return subprocess.run([sys.executable, '-X', 'utf8', '-c', WRITER],
                              env=dict(os.environ, RV_INSTALL_PROJECT=str(project),
                                       RV_INSTALL_CONFIG=str(config)),
                              capture_output=True, text=True, encoding='utf8', timeout=10)

    def test_preserves_other_servers_settings_and_token(self):
        for username in ('alice', 'bob with spaces'):
            with self.subTest(username=username), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                home = Path(directory) / username
                project = home / 'custom path' / 'RedVector'
                project.mkdir(parents=True)
                config = home / 'claude_desktop_config.json'
                other = {'command': 'unrelated', 'args': ['keep']}
                original = {'preference': True, 'mcpServers': {'other': other,
                            'redvector-ai': {'env': {'REDVECTOR_API_TOKEN': 'test-token'}}}}
                config.write_text(json.dumps(original), encoding='utf8')
                result = self.run_writer(project, config)
                self.assertEqual(result.returncode, 0, result.stderr)
                data = json.loads(config.read_text())
                self.assertTrue(data['preference'])
                self.assertEqual(data['mcpServers']['other'], other)
                redvector = data['mcpServers']['redvector-ai']
                self.assertEqual(redvector['command'], '/bin/bash')
                self.assertEqual(redvector['args'], [str(project / 'start_redvector.sh')])
                self.assertEqual(redvector['env']['REDVECTOR_API_TOKEN'], 'test-token')
                backups = list(home.glob('*.backup-*'))
                self.assertEqual(len(backups), 1)
                self.assertEqual(json.loads(backups[0].read_text()), original)

    def test_invalid_config_is_not_overwritten(self):
        for content in ('broken JSON', '[]', '{"mcpServers": []}'):
            with self.subTest(content=content), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                config = Path(directory) / 'config.json'
                config.write_text(content)
                result = self.run_writer(Path(directory), config)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(config.read_text(), content)


if __name__ == '__main__':
    unittest.main()

"""Real Linux /proc integration: creates only its own harmless socket fixture."""
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest

from test_backend_check import backend, ROOT


@unittest.skipUnless(sys.platform.startswith('linux'), 'Requires real Linux /proc')
class LinuxBackendTests(unittest.TestCase):
    def test_live_listener_absolute_and_relative_script(self):
        for relative in (False, True):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                project = Path(directory).resolve()
                script = project / 'redvector_server.py'
                script.write_text('import socket,sys\ns=socket.socket()\ns.bind(("127.0.0.1",0))\ns.listen()\nprint(s.getsockname()[1],flush=True)\nsys.stdin.read()\n')
                process = subprocess.Popen([sys.executable, script.name if relative else str(script)],
                                           cwd=project, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True)
                try:
                    ready, _, _ = select.select([process.stdout], [], [], 5)
                    self.assertTrue(ready, 'Fixture did not start')
                    port = int(process.stdout.readline())
                    self.assertEqual(backend.backend_state(project, '127.0.0.1', port), 0)
                    self.assertEqual(backend.backend_state(ROOT, '127.0.0.1', port), 2)
                finally:
                    process.communicate(timeout=5)


if __name__ == '__main__':
    unittest.main()

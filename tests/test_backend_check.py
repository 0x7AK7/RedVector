import importlib.util
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('backend_check', ROOT / 'redvector_backend_check.py')
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)


class BackendIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rv identity user ', dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / 'project with spaces'
        self.project.mkdir()
        (self.project / 'redvector_server.py').touch()
        self.proc = self.root / 'proc'
        (self.proc / 'net').mkdir(parents=True)
        (self.proc / 'net' / 'tcp').write_text('header\n')

    def listener(self, argv, inode='123'):
        with (self.proc / 'net' / 'tcp').open('a') as table:
            table.write(f'0: 0100007F:22B8 00000000:0000 0A 0 0 0 1000 0 {inode}\n')
        process = self.proc / inode
        (process / 'fd').mkdir(parents=True)
        (process / 'cmdline').write_bytes(b'\0'.join(str(x).encode() for x in argv) + b'\0')
        (process / 'fd' / '3').write_text(f'socket:[{inode}]')

    def state(self, port=8888):
        # Only substitute Linux readlink; all parsing and file resolution is real.
        with patch.object(backend.os, 'readlink', side_effect=lambda p: Path(p).read_text()):
            return backend.backend_state(self.project, '127.0.0.1', port, self.proc)

    def test_matching_absolute_script(self):
        self.listener(['/usr/bin/python3', '-u', self.project / 'redvector_server.py'])
        self.assertEqual(self.state(), 0)

    def test_other_installation(self):
        self.listener(['/usr/bin/python3', self.root / 'other' / 'redvector_server.py'])
        self.assertEqual(self.state(), 2)

    def test_non_python_and_python_command_are_rejected(self):
        for argv in (['node', self.project / 'redvector_server.py'],
                     ['python3', '-c', str(self.project / 'redvector_server.py')]):
            with self.subTest(argv=argv):
                self.listener(argv)
                self.assertEqual(self.state(), 2)
                import shutil
                shutil.rmtree(self.proc / '123')
                (self.proc / 'net' / 'tcp').write_text('header\n')

    def test_unreadable_owner(self):
        self.listener(['python3', self.project / 'redvector_server.py'])
        (self.proc / '123' / 'cmdline').unlink()
        self.assertEqual(self.state(), 2)

    def test_multiple_owners_include_foreign(self):
        self.listener(['python3', self.project / 'redvector_server.py'])
        self.listener(['python3', self.root / 'foreign.py'], '456')
        self.assertEqual(self.state(), 2)

    def test_free_port(self):
        self.assertEqual(self.state(port=0), 1)

    def test_hidden_occupied_port(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            self.assertEqual(self.state(port=listener.getsockname()[1]), 2)

    def test_missing_proc(self):
        self.assertEqual(backend.backend_state(self.project, '127.0.0.1', 8888,
                                              self.root / 'absent'), 2)


if __name__ == '__main__':
    unittest.main()

"""Identify a local Linux backend without trusting its HTTP response.

Exit codes: 0 = this installation, 1 = free port, 2 = foreign/unverifiable.
Never sends signals or changes processes.
"""
import os
from pathlib import Path
import re
import socket
import sys


def backend_state(project, host, port, proc=Path('/proc')):
    """Fail closed when socket ownership or the executed script is unknown."""
    expected = (Path(project) / 'redvector_server.py').resolve()
    listeners = set()
    try:
        for name in ('tcp', 'tcp6'):
            table = proc / 'net' / name
            if not table.exists() and name == 'tcp6':
                continue
            for line in table.read_text().splitlines()[1:]:
                fields = line.split()
                if fields[3] == '0A' and int(fields[1].split(':')[1], 16) == port:
                    listeners.add(fields[9])
        if not listeners:
            # Also detects occupied ports not visible in this proc namespace.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind((host, port))
            return 1
        owned = set()
        for process in proc.iterdir():
            if not process.name.isdigit():
                continue
            try:
                sockets = {os.readlink(fd) for fd in (process / 'fd').iterdir()}
                inodes = {inode for inode in listeners if f'socket:[{inode}]' in sockets}
                if not inodes:
                    continue
                argv = [os.fsdecode(arg) for arg in (process / 'cmdline').read_bytes().split(b'\0') if arg]
                if not argv or not re.fullmatch(r'python(?:\d+(?:\.\d+)*)?', Path(argv[0]).name):
                    return 2
                args = argv[1:]
                while args and args[0] in ('-u', '-B', '-E', '-I', '-s', '-S', '-O', '-OO', '-b', '-bb'):
                    args.pop(0)
                if not args or args[0].startswith('-'):
                    return 2
                script = Path(args[0])
                if not script.is_absolute():
                    script = (process / 'cwd').resolve(strict=True) / script
                if script.resolve(strict=True) != expected:
                    return 2
                owned.update(inodes)
            except (OSError, ValueError):
                continue
        return 0 if owned == listeners else 2
    except (OSError, ValueError, IndexError):
        return 2


if __name__ == '__main__':
    try:
        sys.exit(backend_state(sys.argv[1], sys.argv[2], int(sys.argv[3])))
    except (ValueError, IndexError):
        sys.exit(2)

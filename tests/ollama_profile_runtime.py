"""Reusable isolated test backend lifecycle; never touches an existing listener."""
from contextlib import contextmanager
from pathlib import Path
import os,secrets,socket,sys,time
from unittest.mock import patch

@contextmanager
def owned_backend(directory):
    import psutil
    from test_ollama_linux_bridge import capture_started_backends
    root=Path(__file__).resolve().parents[1]
    with socket.socket() as probe:probe.bind(("127.0.0.1",0));port=probe.getsockname()[1]
    bindir=directory/"bin";bindir.mkdir()
    python=bindir/"python3";python.write_text('#!/bin/bash\nexec "'+sys.executable+'" "$@"\n');python.chmod(0o755)
    env={"REDVECTOR_HOST":"127.0.0.1","REDVECTOR_PORT":str(port),"REDVECTOR_API_TOKEN":secrets.token_hex(24),
         "XDG_CONFIG_HOME":str(directory/"config"),"PATH":str(bindir)+os.pathsep+os.environ["PATH"]}
    started=time.time()
    try:
        with patch.dict(os.environ,env):yield env
    finally:
        for pid,created in capture_started_backends(directory,root,port,started).items():
            try:
                process=psutil.Process(pid)
                if process.create_time()==created and str(root/"redvector_server.py") in process.cmdline():
                    process.terminate()
                    try:process.wait(timeout=10)
                    except psutil.TimeoutExpired:process.kill();process.wait(timeout=5)
            except psutil.NoSuchProcess:pass

"""Opt-in real harmless MCP/AI presentation test; no security attacks or downloads."""
import asyncio
from contextlib import contextmanager
import io
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
from unittest.mock import patch
import pytest
from redvector_ollama_agent import Agent, bridge
from redvector_ollama_policy import Policy
from redvector_ollama_results import ResultsStore
from redvector_ollama_setup import Terminal,Ollama

def _port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1",0))
        return probe.getsockname()[1]

@contextmanager
def _runtime(directory):
    """Start only test-owned processes on free loopback ports, with existing models."""
    import psutil
    from test_ollama_linux_bridge import capture_started_backends
    root=Path(__file__).resolve().parents[1]
    binary=Path(os.environ["REDVECTOR_UNIFIED_OLLAMA_BIN"]).resolve()
    models=Path(os.environ["REDVECTOR_UAT_MODELS"]).resolve()
    assert binary.is_file() and models.is_dir(),"Existing runtime/model directory required; never install or pull."
    bindir=directory/"bin";bindir.mkdir()
    python=bindir/"python3"
    python.write_text('#!/bin/bash\nexec "'+sys.executable+'" "$@"\n')
    python.chmod(0o755)
    ollama_port=_port();backend_port=_port()
    env={"OLLAMA_HOST":"127.0.0.1:"+str(ollama_port),"OLLAMA_MODELS":str(models),
         "OLLAMA_NO_CLOUD":"true","REDVECTOR_HOST":"127.0.0.1","REDVECTOR_PORT":str(backend_port),
         "REDVECTOR_API_TOKEN":secrets.token_hex(24),"XDG_CONFIG_HOME":str(directory/"config"),
         "PATH":str(bindir)+os.pathsep+str(binary.parent)+os.pathsep+os.environ["PATH"]}
    manifests={str(p.relative_to(models)):__import__("hashlib").sha256(p.read_bytes()).hexdigest()
               for p in (models/"manifests").rglob("*") if p.is_file()}
    started=time.time();process=None
    with patch.dict(os.environ,env):
        try:
            with (directory/"ollama.log").open("w") as log:
                process=subprocess.Popen([str(binary),"serve"],env=dict(os.environ),stdout=log,stderr=subprocess.STDOUT)
            deadline=time.monotonic()+60
            while not Ollama().healthy():
                assert process.poll() is None,"Test-owned Ollama exited; inspect private test diagnostics."
                if time.monotonic()>deadline:pytest.fail("Test-owned Ollama API did not become healthy.")
                time.sleep(.2)
            yield
        finally:
            # Existing services never use the test's randomly chosen port/token/PID.
            for pid,created in capture_started_backends(directory,root,backend_port,started).items():
                try:
                    owned=psutil.Process(pid)
                    if owned.create_time()==created and str(root/"redvector_server.py") in owned.cmdline():
                        owned.terminate();owned.wait(timeout=15)
                except psutil.NoSuchProcess:pass
            if process is not None and process.poll() is None:
                children=psutil.Process(process.pid).children(recursive=True)
                process.terminate();process.wait(timeout=20)
                for child in children:
                    try:child.terminate()
                    except psutil.NoSuchProcess:pass
                psutil.wait_procs(children,timeout=10)
            after={str(p.relative_to(models)):__import__("hashlib").sha256(p.read_bytes()).hexdigest()
                   for p in (models/"manifests").rglob("*") if p.is_file()}
            assert after==manifests,"Existing model manifests must remain unchanged."

def test_real_unified_health_saved_analysis(tmp_path):
    if not sys.platform.startswith("linux") or not os.environ.get("REDVECTOR_UNIFIED_LIVE_MODEL"):
        pytest.skip("Requires native Linux, existing runtime and operator-selected installed model.")
    if os.environ.get("REDVECTOR_UNIFIED_OLLAMA_BIN"):
        with _runtime(tmp_path):
            asyncio.run(_health(tmp_path))
            _terminal_smoke(tmp_path)
    else:asyncio.run(_health(tmp_path))

async def _health(tmp_path):
    api=Ollama();model=os.environ["REDVECTOR_UNIFIED_LIVE_MODEL"]
    metadata=await api.async_show(model)
    assert "tools" in metadata.get("capabilities",[])
    stream=io.StringIO();term=Terminal(stream)
    async with bridge() as (session,catalog):
        assert len(catalog)==328
        agent=Agent(api,model,session,catalog,Policy(),lambda _:False,lambda _:None,
                    terminal=term,results=ResultsStore(tmp_path/"evidence"))
        answer=await agent.turn("Call server_health exactly once with empty arguments to check the real backend. Do not scan any target.")
        record=agent.results.load()
        assert record["tool"]=="server_health"
        assert record["findings"]["status"]=="COMPLETED"
        assert "healthy" in str(record["mcp"])
        assert "8.0.0" in str(record["mcp"])
        assert "VERIFIED TOOL RESULTS" in stream.getvalue()
        assert "structuredContent" not in stream.getvalue()
        assert "AI verified" in answer,answer
        print("REAL UNIFIED HEALTH: 328 tools; server_health; healthy; version 8.0.0; saved evidence; real model verification.")


def _terminal_smoke(directory):
    from ollama_terminal_driver import TerminalSession
    from redvector_ollama_setup import save_model
    root=Path(__file__).resolve().parents[1]
    save_model(os.environ["REDVECTOR_UNIFIED_LIVE_MODEL"])
    env=dict(os.environ,TERM="xterm-256color");env.pop("NO_COLOR",None)
    session=TerminalSession(["/bin/bash",str(root/"start_redvector_ollama.sh")],env,root,directory,"unified-terminal")
    try:
        session.expect("Choose 1-6:",timeout=90);session.send("1")
        session.expect("redvector> ",timeout=600)
        session.send("/scope");session.expect("REDVECTOR AUTHORIZED TARGET SCOPE")
        session.expect("redvector> ")
        session.send("/status");session.expect("VERIFIED TOOL RESULTS",timeout=90)
        session.expect(r"result.status\s+healthy");session.expect("redvector> ")
        session.send("/results");session.expect("VERIFIED TOOL RESULTS")
        session.expect("redvector> ")
        session.send("/tools metasploit");session.expect("Blocked by client policy")
        session.expect("redvector> ");session.send("/back");session.expect("Choose 1-6:")
        session.send("6");session.finish()
        assert b"\x1b[1;91mredvector>" in session.raw
        print("REAL BASH UI: model launch; red prompt; scope; formatted real health; saved results; blocked tool discovery; back and exit.")
    finally:
        session.close()

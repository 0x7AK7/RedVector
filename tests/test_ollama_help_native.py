"""Native PTY input/help acceptance, not a simulated scan or model result."""
import os
from pathlib import Path
import sys
import pytest

SCRIPT=r"""
from types import SimpleNamespace
from redvector_ollama_setup import Terminal,Wizard
from redvector_ollama_cli import handle_command,assessment_context
from redvector_ollama_policy import Policy
import asyncio
term=Terminal()
wizard=Wizard(object(),term)
agent=SimpleNamespace(policy=Policy(),history=[])
term.write("Type /help to view all commands")
async def main():
    while True:
        text=wizard.command()
        action=await handle_command(text,agent,wizard)
        if action=="exit":return
        if action=="handled":continue
        assessment,target,message=assessment_context(text,agent.policy)
        term.write(message if message else "READY: "+str(target)+"; no tool executed by this input-only test.")
asyncio.run(main())
"""

@pytest.mark.skipif(not sys.platform.startswith("linux") or os.environ.get("REDVECTOR_RUN_SCOPE_HELP_UAT")!="1",
                    reason="Requires explicit native Linux PTY acceptance")
def test_actual_readline_help_scope_and_completion(tmp_path):
    from ollama_terminal_driver import TerminalSession
    root=Path(__file__).resolve().parents[1]
    script=tmp_path/"session.py";script.write_text(SCRIPT)
    env=dict(os.environ,TERM="xterm-256color",PYTHONPATH=str(root)+os.pathsep+os.environ.get("PYTHONPATH",""))
    env.pop("NO_COLOR",None)
    session=TerminalSession([sys.executable,str(script)],env,root,tmp_path,"scope-help-terminal")
    try:
        session.expect("Type /help to view all commands");session.expect("redvector> ")
        session.send("/he\t");session.expect("REDVECTOR OPERATOR HELP")
        session.expect("redvector> ");session.send("/help sc\t");session.expect("Usage: /scope")
        session.expect("redvector> ");session.send("/help search authorized");session.expect("COMMAND SEARCH")
        session.expect("redvector> ");session.send("/scope 192.168.5.130");session.expect("Authorized scope replaced")
        session.expect("redvector> ");session.send("Scan 192.168.5.130 for open ports and identify the services and versions running on them.")
        session.expect("Target is authorized. Execution policy restriction:")
        for _ in range(2):
            session.expect("redvector> ");session.send("Scan 192.168.5.130 for open ports and identify services running on them.")
            session.expect("READY: 192.168.5.130")
            session.expect("redvector> ");session.send("Scan 198.51.100.99 for open ports")
            session.expect("outside the operator-authorized scope")
        session.expect("redvector> ");session.send("/scope");session.expect("192.168.5.130")
        session.expect("redvector> ");session.send("/statuz");session.expect("Did you mean /status")
        session.expect("redvector> ");session.send("/back");session.finish()
        assert b"\x1b[1;91mredvector>" in session.raw
        print("REAL PTY INPUT: Tab command/detail completion; help/search; exact scope and policy distinction; consecutive allowed/denied parsing; scope retained; red prompt; exit. No security tool executed.")
    finally:session.close()

@pytest.mark.skipif(not sys.platform.startswith("linux") or os.environ.get("REDVECTOR_RUN_SCOPE_HELP_UAT")!="1",
                    reason="Requires explicit native Linux PTY acceptance")
def test_actual_no_color_help_input(tmp_path):
    from ollama_terminal_driver import TerminalSession
    root=Path(__file__).resolve().parents[1]
    script=tmp_path/"plain.py";script.write_text(SCRIPT)
    env=dict(os.environ,TERM="xterm-256color",NO_COLOR="1",PYTHONPATH=str(root)+os.pathsep+os.environ.get("PYTHONPATH",""))
    session=TerminalSession([sys.executable,str(script)],env,root,tmp_path,"scope-help-plain")
    try:
        session.expect("redvector> ");session.send("/help summary");session.expect("Usage: /summary")
        session.expect("redvector> ");session.send("/back");session.finish()
        assert b"\x1b[1;91m" not in session.raw and b"\x1b[38;5;196m" not in session.raw
    finally:session.close()

import asyncio
import io
from types import SimpleNamespace
from unittest.mock import Mock,AsyncMock,patch
import pytest
from redvector_ollama_cli import handle_command
from redvector_ollama_setup import Terminal,Wizard
from redvector_ollama_policy import Policy

IMPLEMENTED={"/artifact","/scope","/status","/tools","/results","/summary","/raw","/export","/back","/exit","/help"}

def interface():
    term=Terminal(io.StringIO())
    agent=SimpleNamespace(policy=Policy(),history=[],select=Mock(return_value=[]),
        execute=AsyncMock(),summarize_saved=AsyncMock(),results=Mock(),
        turn=AsyncMock(side_effect=AssertionError("Help must not reach the model")))
    return term,agent,Wizard(Mock(),term,lambda:"")

def test_grouped_help_lists_exact_registry_without_model_or_tools():
    from redvector_ollama_help import COMMANDS
    assert set(COMMANDS)==IMPLEMENTED
    term,agent,wizard=interface()
    asyncio.run(handle_command("/help",agent,wizard))
    text=term.stream.getvalue()
    for name in IMPLEMENTED:assert name in text
    for group in {spec.group for spec in COMMANDS.values()}:assert group in text
    agent.execute.assert_not_called();agent.turn.assert_not_called()
    assert "1,000" in text and "approval" in text.lower()

@pytest.mark.parametrize("name",sorted(IMPLEMENTED))
def test_detail_has_usage_arguments_examples_and_restrictions(name):
    term,agent,wizard=interface()
    asyncio.run(handle_command("/help "+name,agent,wizard))
    text=term.stream.getvalue()
    assert "Usage:" in text and name in text
    assert "Arguments:" in text and "Examples:" in text and "Restrictions:" in text
    agent.execute.assert_not_called()

def test_help_accepts_plain_command_name_and_search():
    term,agent,wizard=interface()
    for value in ("/help scope","/help search authorized","/help search nonexistentterm","/help search"):
        assert asyncio.run(handle_command(value,agent,wizard))=="handled"
    text=term.stream.getvalue()
    assert "/scope" in text and "No commands match" in text and "/help search TEXT" in text
    agent.execute.assert_not_called();agent.turn.assert_not_called()

def test_unknown_command_suggests_real_commands_only():
    term,agent,wizard=interface()
    asyncio.run(handle_command("/statuz",agent,wizard))
    assert "/status" in term.stream.getvalue()
    agent.execute.assert_not_called();agent.turn.assert_not_called()

def test_search_completion_no_natural_language_or_target_completion():
    from redvector_ollama_help import completion_candidates
    assert completion_candidates("/he","/he",0)==["/help"]
    assert "/scope" in completion_candidates("/help /sc","/sc",6)
    assert "scope" in completion_candidates("/help sc","sc",6)
    assert completion_candidates("please /he","/he",7)==[]
    assert completion_candidates("/scope tar","tar",7)==[]

def test_help_wraps_and_honors_no_color(monkeypatch):
    term,agent,wizard=interface()
    monkeypatch.setenv("NO_COLOR","")
    with patch("shutil.get_terminal_size",return_value=__import__("os").terminal_size((24,20))):
        asyncio.run(handle_command("/help summary",agent,wizard))
    assert all(len(line)<=24 for line in term.stream.getvalue().splitlines())
    assert "\x1b" not in term.stream.getvalue()

def test_dispatcher_recognizes_every_registry_command_without_inventing_commands():
    term,agent,wizard=interface()
    for command in IMPLEMENTED:
        argument={"artifact":"","scope":"","help":"","back":"","exit":"","status":"invalid","tools":"",
                  "results":"too many words","summary":"id invalid","raw":"too many","export":"too many"}[command[1:]]
        value=asyncio.run(handle_command(command+(" "+argument if argument else ""),agent,wizard))
        assert value==("exit" if command in ("/back","/exit") else "handled")
    assert "Unknown command" not in term.stream.getvalue()
    agent.execute.assert_not_called()

def test_actual_interactive_startup_advertises_help():
    asyncio.run(_startup())

async def _startup():
    from contextlib import asynccontextmanager
    from redvector_ollama_agent import interactive
    @asynccontextmanager
    async def connection():yield Mock(),{}
    term,agent,wizard=interface()
    wizard.command=Mock(side_effect=["/help","/back"])
    with patch("redvector_ollama_agent.verify_tools",new=AsyncMock()),patch("redvector_ollama_agent.bridge",connection):
        await interactive(Mock(),"unit-fixture",wizard)
    assert "Type /help to view all commands" in term.stream.getvalue()
    assert "REDVECTOR OPERATOR HELP" in term.stream.getvalue()

def test_artifact_command_selects_only_operator_path_without_model_dispatch():
    term,agent,wizard=interface()
    selected={"name":"owned artifact.bin","size":10,"sha256":"a"*64}
    async def choose(path):
        agent.artifact=selected
        return selected
    async def clear():agent.artifact=None
    agent.select_artifact=AsyncMock(side_effect=choose);agent.clear_artifact=AsyncMock(side_effect=clear)
    asyncio.run(handle_command('/artifact "owned artifact.bin"',agent,wizard))
    agent.select_artifact.assert_awaited_once_with("owned artifact.bin")
    assert "AUTHORIZED ARTIFACT SNAPSHOT" in term.stream.getvalue()
    asyncio.run(handle_command("/artifact --clear",agent,wizard))
    assert agent.artifact is None
    agent.turn.assert_not_called();agent.execute.assert_not_called()

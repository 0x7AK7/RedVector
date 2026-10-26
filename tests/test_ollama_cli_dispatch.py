"""Built-in CLI state is trusted application state, never a model response."""
import io
import os
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock,Mock,patch
from redvector_ollama_setup import Terminal,Wizard
from redvector_ollama_policy import Policy

class CLICommands(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.term=Terminal(io.StringIO())
        self.agent=SimpleNamespace(policy=Policy(),history=[],select=lambda q:[],
            execute=AsyncMock(return_value={"source":"mcp","isError":False}),turn=AsyncMock(side_effect=AssertionError("Built-ins must not reach a model")))
        self.wizard=Wizard(Mock(),self.term,lambda:"")

    async def dispatch(self,text):
        from redvector_ollama_cli import handle_command
        return await handle_command(text,self.agent,self.wizard)

    async def test_inline_scope_and_display_are_application_commands(self):
        await self.dispatch(" /scope 192.0.2.15 2001:db8::8 ")
        self.assertEqual(self.agent.policy.snapshot(),("192.0.2.15","2001:db8::8"))
        await self.dispatch("/scope")
        self.assertIn("REDVECTOR AUTHORIZED TARGET SCOPE",self.term.stream.getvalue())
        self.assertIn("Source: Operator command",self.term.stream.getvalue())
        self.assertNotIn("Enter explicitly",self.term.stream.getvalue())

    async def test_invalid_replacement_keeps_previous_scope(self):
        await self.dispatch("/scope 192.0.2.15")
        await self.dispatch("/scope 192.0.2.8 bad;id")
        self.assertEqual(self.agent.policy.snapshot(),("192.0.2.15",))
        self.assertIn("Invalid",self.term.stream.getvalue())

    async def test_empty_unknown_and_tools_commands_never_call_model(self):
        for text in (""," ","/unknown","/tools","/scope --clear"):
            self.assertEqual(await self.dispatch(text),"handled")
        self.assertEqual(self.agent.policy.snapshot(),())

    async def test_exit_and_argument_validation(self):
        self.assertEqual(await self.dispatch("/back"),"exit")
        self.assertEqual(await self.dispatch("/exit"),"exit")
        self.assertEqual(await self.dispatch("/back surprise"),"handled")

    async def test_status_executes_real_session_interface_without_model(self):
        await self.dispatch("/status")
        self.assertIn('"source": "mcp"',self.term.stream.getvalue())

class PromptTests(unittest.TestCase):
    def terminal(self,tty=True):
        stream=io.StringIO();stream.isatty=lambda:tty
        return Terminal(stream)
    def test_prompt_only_is_red_and_resets_before_user_input(self):
        with patch.dict(os.environ,{"TERM":"xterm"},clear=True),patch("sys.stdin.isatty",return_value=True):
            prompt=self.terminal().prompt()
            self.assertEqual(prompt,"\033[1;91mredvector>\033[0m ")
    def test_no_color_non_tty_and_noninteractive_input_stay_plain(self):
        for settings,tty,input_tty in [({"TERM":"xterm","NO_COLOR":""},True,True),
                                      ({"TERM":"xterm"},False,True),({"TERM":"dumb"},True,True),
                                      ({"TERM":"xterm"},True,False)]:
            with self.subTest(settings=settings,tty=tty,input=input_tty),patch.dict(os.environ,settings,clear=True),patch("sys.stdin.isatty",return_value=input_tty):
                self.assertEqual(self.terminal(tty).prompt(),"redvector> ")
    def test_readline_prompt_marks_nonprinting_escapes(self):
        with patch.dict(os.environ,{"TERM":"xterm"},clear=True),patch("sys.stdin.isatty",return_value=True):
            self.assertEqual(self.terminal().prompt(readline=True),"\001\033[1;91m\002redvector>\001\033[0m\002 ")

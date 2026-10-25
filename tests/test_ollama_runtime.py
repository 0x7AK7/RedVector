"""Service lifecycle and real-launcher guard regressions."""
from contextlib import nullcontext,asynccontextmanager
import io,os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch,AsyncMock
from redvector_ollama_setup import Ollama,Wizard,Terminal,SetupError
from redvector_ollama_agent import bridge,interactive,AgentError

class ServiceTests(unittest.TestCase):
    def test_healthy_service_never_starts_another_process(self):
        api=Ollama()
        with patch.object(api,"healthy",return_value=True),patch("subprocess.Popen") as start:
            api.ensure_service()
            start.assert_not_called()
    def test_free_local_port_starts_one_service_and_waits(self):
        api=Ollama()
        child=Mock();child.poll.return_value=None
        with tempfile.TemporaryDirectory() as d,patch("sys.platform","linux"),patch("redvector_ollama_setup.local_lock",return_value=nullcontext()),patch("redvector_ollama_setup.config_path",return_value=Path(d)/"config.json"),patch.object(api,"healthy",side_effect=[False,False,True]),patch("socket.create_connection",side_effect=ConnectionRefusedError),patch("shutil.which",return_value="/usr/bin/ollama"),patch("subprocess.Popen",return_value=child) as start:
            api.ensure_service()
            self.assertEqual(start.call_count,1)
            self.assertEqual(start.call_args.kwargs["env"]["OLLAMA_HOST"],"http://127.0.0.1:11434")
            child.terminate.assert_not_called()
    def test_service_cancellation_cleans_up_only_its_owned_child(self):
        api=Ollama()
        child=Mock();child.poll.return_value=None
        with tempfile.TemporaryDirectory() as d,patch("sys.platform","linux"),patch("redvector_ollama_setup.local_lock",return_value=nullcontext()),patch("redvector_ollama_setup.config_path",return_value=Path(d)/"config.json"),patch.object(api,"healthy",side_effect=[False,False,KeyboardInterrupt]),patch("socket.create_connection",side_effect=ConnectionRefusedError),patch("shutil.which",return_value="/usr/bin/ollama"),patch("subprocess.Popen",return_value=child):
            with self.assertRaises(KeyboardInterrupt):api.ensure_service()
            child.terminate.assert_called_once()
            child.wait.assert_called_once()
    def test_existing_unhealthy_service_does_not_spawn(self):
        api=Ollama()
        with patch.object(api,"healthy",return_value=False),patch("socket.create_connection"),patch("subprocess.Popen") as start:
            with self.assertRaises(SetupError):api.ensure_service()
            start.assert_not_called()

class RuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_crlf_existing_launcher_is_adapted_without_modification(self):
        from redvector_ollama_agent import launcher_script
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"start_redvector.sh";original=b"#!/bin/bash\r\nexit 0\r\n";path.write_bytes(original)
            with patch("redvector_ollama_agent.ROOT",Path(d)):
                with launcher_script() as selected:
                    self.assertEqual(selected.parent,Path(d))
                    self.assertNotEqual(selected,path)
                    self.assertEqual(selected.read_bytes(),b"#!/bin/bash\nexit 0\n")
                    self.assertEqual(path.read_bytes(),original)
                self.assertFalse(selected.exists())
                self.assertEqual(path.read_bytes(),original)
    async def test_lf_existing_launcher_is_used_directly(self):
        from redvector_ollama_agent import launcher_script
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"start_redvector.sh";path.write_bytes(b"#!/bin/bash\nexit 0\n")
            with patch("redvector_ollama_agent.ROOT",Path(d)),launcher_script() as selected:
                self.assertEqual(selected,path)
            self.assertTrue(path.exists())
    async def test_invalid_scope_can_be_corrected_without_losing_session(self):
        api=Mock()
        session=Mock()
        @asynccontextmanager
        async def connection():yield session,{}
        answers=iter(["/scope","bad;id","/back"])
        wizard=Wizard(api,Terminal(io.StringIO()),answers.__next__)
        with patch("redvector_ollama_agent.verify_tools",new=AsyncMock()),patch("redvector_ollama_agent.bridge",connection):
            await interactive(api,"local",wizard)
        self.assertIn("Invalid",wizard.term.stream.getvalue())

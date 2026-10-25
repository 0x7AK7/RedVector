"""Regressions for independent review findings."""
import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from redvector_ollama_policy import Policy,PolicyError
from redvector_ollama_setup import Ollama

class DependencyTests(unittest.TestCase):
    def test_missing_backend_dependency_is_reported(self):
        from redvector_ollama_dependencies import dependency_issues
        from importlib.metadata import PackageNotFoundError
        def installed(name):
            if name=="flask":raise PackageNotFoundError(name)
            return "1.0"
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"requirements.txt";path.write_text("flask>=2.3,<4\nrequests>=2.31,<3\n")
            with patch("importlib.metadata.version",side_effect=installed):
                problems=dependency_issues([path])
            self.assertTrue(any("flask" in problem for problem in problems))
            self.assertTrue(any("requests" in problem for problem in problems))
    def test_satisfied_versions_pass_without_importing_backend(self):
        from redvector_ollama_dependencies import dependency_issues
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"requirements.txt";path.write_text("\ufeff# UTF-8 BOM from existing requirements\nflask>=2.3,<4 # comment\n\n# ignored\n",encoding="utf8")
            with patch("importlib.metadata.version",return_value="3.1.0"):
                self.assertEqual(dependency_issues([path]),[])

class ScopeTests(unittest.TestCase):
    def test_ipv6_nmap_rejected_before_operator_approval(self):
        approvals=[]
        with self.assertRaisesRegex(PolicyError,"IPv6"):
            Policy(["::1"]).authorize("nmap_scan",{"target":"::1"},lambda op:approvals.append(op) or True)
        self.assertEqual(approvals,[])

class CancellationTests(unittest.IsolatedAsyncioTestCase):
    async def test_live_http_inference_can_be_cancelled_without_worker_threads(self):
        connected=asyncio.Event();release=asyncio.Event()
        async def handle(reader,writer):
            try:
                await reader.readuntil(b"\r\n\r\n")
                connected.set()
                await release.wait()
            except (asyncio.IncompleteReadError,ConnectionError):pass
            finally:
                writer.close()
                await writer.wait_closed()
        server=await asyncio.start_server(handle,"127.0.0.1",0)
        api=Ollama(f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}")
        try:
            task=asyncio.create_task(api.async_chat("local",[],[]))
            await asyncio.wait_for(connected.wait(),timeout=3)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task,timeout=1)
        finally:
            release.set();server.close();await server.wait_closed()

"""Replay synthetic 31-port success; inject transport failure, never scan a host."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch,Mock,AsyncMock
import httpx
from redvector_ollama_setup import Ollama,OllamaTimeout,Terminal
from redvector_ollama_agent import Agent
from redvector_ollama_policy import Policy
from redvector_ollama_results import ResultsStore
from test_ollama_agent_responses import tool
from test_ollama_results import response

class DiagnosticReplay(unittest.IsolatedAsyncioTestCase):
    async def test_actual_transport_cause_stage_and_duration_are_logged_without_secrets(self):
        with tempfile.TemporaryDirectory() as d:
            async def handler(request):raise httpx.ReadTimeout("Authorization: Bearer PRIVATE_SENTINEL")
            real=httpx.AsyncClient
            with patch.dict(os.environ,{"XDG_CONFIG_HOME":d}),patch("httpx.AsyncClient",side_effect=lambda **kw:real(transport=httpx.MockTransport(handler),**kw)):
                with self.assertRaises(OllamaTimeout):await Ollama().async_chat("fixture-model",[{"role":"user","content":"PRIVATE_FINDINGS"}],[])
            entries=[json.loads(line) for line in (Path(d)/"redvector-ollama"/"agent-errors.log").read_text().splitlines()]
            entry=entries[-1]
            self.assertEqual(entry["details"]["timeout_stage"],"read")
            self.assertGreaterEqual(entry["details"]["elapsed_seconds"],0)
            self.assertIn("ReadTimeout",[item["type"] for item in entry["causes"]])
            self.assertNotIn("PRIVATE_SENTINEL",json.dumps(entries))
            self.assertNotIn("PRIVATE_FINDINGS",json.dumps(entries))

    async def test_31_port_success_with_post_tool_timeout_preserves_all_facts_and_one_action(self):
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{"XDG_CONFIG_HOME":str(Path(d)/"config")}):
            rows=[{"port":p,"protocol":"tcp","state":"open","service":"fixture-service"} for p in range(10000,10031)]
            stdout="PORT STATE SERVICE\n"+"\n".join(str(row["port"])+"/tcp open fixture-service" for row in rows)
            data=response(rows,stdout=stdout,partial_results=False,timed_out=False)
            self.assertGreater(len(json.dumps(data)),3000)
            wire={"isError":False,"content":data["content"],"structuredContent":data["structuredContent"],"vendor_extension":{"retained":True}}
            session=Mock();session.call_tool=AsyncMock(return_value=Mock(
                isError=False,content=[Mock(type="text",text=data["content"][0]["text"])],
                structuredContent=data["structuredContent"],model_dump=lambda **kw:wire))
            call={"role":"assistant","tool_calls":[{"function":{"name":"nmap_scan","arguments":{"target":"192.0.2.8","ports":"10000-10030"}}}]}
            api=Mock();api.async_chat=AsyncMock(side_effect=[call,OllamaTimeout("Injected post-tool response timeout")])
            term=Terminal(io.StringIO())
            agent=Agent(api,"fixture-model",session,{"nmap_scan":tool("nmap_scan")},Policy(["192.0.2.8"]),
                        lambda operation:False,lambda text:None,results=ResultsStore(Path(d)/"results"),terminal=term)
            answer=await agent.turn("Scan 192.0.2.8 TCP ports 10000-10030")
            self.assertIn("COMPLETED SUCCESSFULLY",answer)
            self.assertIn("no AI analysis run",answer)  # area 5: no automatic post-scan AI pass
            record=agent.results.load()
            self.assertEqual(record["findings"]["open_count"],31)
            self.assertEqual(record["findings"]["duration"],20.16)
            self.assertEqual(record["wire"],wire)
            for port in range(10000,10031):self.assertIn(str(port)+"/tcp",term.stream.getvalue())
            # Area 5: no automatic post-scan AI pass, so the turn makes only the tool-selection
            # chat and returns a concise deterministic summary; evidence is preserved above.
            self.assertEqual(api.async_chat.await_count,1)
            session.call_tool.assert_awaited_once()

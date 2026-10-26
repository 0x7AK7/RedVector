"""Native verifier boundary tests."""
import copy
import json
import unittest
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import patch
from redvector_ollama_agent import AgentError

DIGEST = "a" * 64
CALL = {"role":"assistant","content":"","thinking":"Check health","tool_calls":[{"id":"h1","function":{"name":"server_health","arguments":{}}}]}

class API:
    def __init__(self):
        self.tags = [{"name":"local:latest","digest":DIGEST}]
        self.metadata = {"capabilities":["completion","tools"]}
        self.replies = [copy.deepcopy(CALL),{"role":"assistant","content":json.dumps({"status":"healthy","version":"6.7.8"})}]
        self.messages = []
        self.requests = []
        self.after_chat = None
    async def async_request(self,path):
        assert path == "/api/tags"
        self.requests.append(path)
        return {"models":copy.deepcopy(self.tags)}
    async def async_show(self,model):
        assert model == "local:latest"
        return copy.deepcopy(self.metadata)
    async def async_chat(self,model,messages,tools):
        assert model == "local:latest"
        assert [t["function"]["name"] for t in tools] == ["server_health"]
        self.messages.append(copy.deepcopy(messages))
        if len(self.messages)==2 and self.after_chat:self.after_chat()
        return self.replies.pop(0)

class Session:
    def __init__(self):
        self.calls=[]
        self.payload={"status":"healthy","version":"6.7.8"}
        self.error=False
    async def call_tool(self,name,arguments):
        self.calls.append((name,arguments))
        assert name=="server_health" and arguments=={}
        return SimpleNamespace(isError=self.error,content=[SimpleNamespace(type="text",text=json.dumps(self.payload))],structuredContent={"result":self.payload} if getattr(self,"envelope",False) else self.payload)

class ModelCheckTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import redvector_ollama_model_check as check
        self.check=check
        self.api=API()
        self.session=Session()
        @asynccontextmanager
        async def bridge():
            tool=SimpleNamespace(name="server_health",description="Health",inputSchema={"type":"object","properties":{}})
            yield self.session,{"server_health":tool,"execute_command":tool}
        self.patch=patch.object(check,"bridge",bridge)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    async def test_health_result_returns_to_model_and_evidence(self):
        evidence=await self.check.verify_selected_model(self.api,"local")
        self.assertEqual((evidence["model"],evidence["digest"]),("local:latest",DIGEST))
        self.assertEqual((evidence["status"],evidence["version"]),("healthy","6.7.8"))
        self.assertEqual(self.session.calls,[("server_health",{})])
        result=json.loads(self.api.messages[1][-1]["content"])
        self.assertEqual(result["structuredContent"],{"status":"healthy","version":"6.7.8"})
        self.assertEqual(self.api.messages[1][-1]["tool_call_id"],"h1")
        self.assertEqual(self.api.messages[1][-2]["thinking"],"Check health")
        self.assertEqual(self.api.requests,["/api/tags","/api/tags"])

    async def test_unsupported_missing_or_malformed_capabilities_never_execute(self):
        for metadata in ({},{"capabilities":[]},{"capabilities":"tools"},{"capabilities":["tools",3]}):
            self.api.metadata=metadata
            with self.assertRaises(AgentError):await self.check.verify_selected_model(self.api,"local")
        self.assertEqual(self.session.calls,[])

    async def test_missing_exact_tag_or_invalid_digest_never_execute(self):
        for tags in ([],[{"name":"local:other","digest":DIGEST}],[{"name":"local:latest"}],[{"name":"local:latest","digest":"bad"}]):
            self.api.tags=tags
            with self.assertRaises(AgentError):await self.check.verify_selected_model(self.api,"local")
        self.assertEqual(self.session.calls,[])

    async def test_wrong_malformed_or_multiple_calls_never_execute(self):
        for calls in ([{"function":{"name":"execute_command","arguments":{}}}],
                      [{"function":{"name":"server_health","arguments":{"extra":True}}}],
                      CALL["tool_calls"]*2,[],"bad",[{}]):
            self.api.replies=[{"role":"assistant","tool_calls":calls}]
            with self.assertRaises(AgentError):await self.check.verify_selected_model(self.api,"local")
        self.assertEqual(self.session.calls,[])

    async def test_failed_unhealthy_or_incomplete_backend_result_rejected(self):
        for payload,error in (({"status":"healthy","version":"6.7.8"},True),
                              ({"status":"unhealthy","version":"6.7.8"},False),
                              ({"status":"healthy"},False)):
            self.api.replies=[copy.deepcopy(CALL)]
            self.session.payload,self.session.error=payload,error
            with self.assertRaises(AgentError):await self.check.verify_selected_model(self.api,"local")

    async def test_summary_requires_actual_status_version_and_no_extra_calls(self):
        for summary in ({"content":"healthy version 99"},{"content":"6.7.8"},CALL,
                        {"content":"The backend is not healthy and version is not 6.7.8"},
                        {"content":"\x1b]52;c;encoded\x07 healthy 6.7.8"},
                        {"content":json.dumps({"status":"healthy","version":"6.7.8","summary":"not healthy"})},
                        {"content":json.dumps({"status":"unhealthy","version":"6.7.8"})},
                        {"content":json.dumps({"status":"healthy","version":"99"})}):
            self.api.replies=[copy.deepcopy(CALL),summary]
            with self.assertRaises(AgentError):await self.check.verify_selected_model(self.api,"local")
        self.assertEqual(len(self.session.calls),8)

    async def test_changed_digest_or_capabilities_rejected(self):
        for change in (lambda:self.api.tags[0].update(digest="b"*64),
                       lambda:self.api.metadata.update(capabilities=["completion"])):
            self.api=API()
            self.api.after_chat=change
            with self.assertRaises(AgentError):await self.check.verify_selected_model(self.api,"local")



    async def test_actual_fastmcp_result_envelope_is_preserved_and_verified(self):
        self.session.envelope=True
        evidence=await self.check.verify_selected_model(self.api,"local")
        self.assertEqual(evidence["status"],"healthy")
        returned=json.loads(self.api.messages[1][-1]["content"])
        self.assertEqual(returned["structuredContent"],{"result":self.session.payload})

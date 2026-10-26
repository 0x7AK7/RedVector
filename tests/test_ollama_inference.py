import asyncio
import json
import os
import unittest
from unittest.mock import patch,Mock
import httpx
from redvector_ollama_setup import Ollama,SetupError

class Inference(unittest.IsolatedAsyncioTestCase):
    async def test_error_categories_are_not_collapsed(self):
        for status,payload,category in [(400,{"error":"input exceeds context length"},"context-overflow"),
                                        (503,{"error":"model unavailable secret-token"},"http-error"),
                                        (200,{"error":"model unavailable"},"model-error")]:
            async def handler(request):return httpx.Response(status,json=payload)
            transport=httpx.MockTransport(handler)
            real=httpx.AsyncClient
            with patch("httpx.AsyncClient",side_effect=lambda **kw:real(transport=transport,**kw)):
                try:await Ollama().async_request("/api/chat",{})
                except SetupError as exc:
                    self.assertEqual(getattr(exc,"category",None),category)
                    self.assertNotIn("secret-token",str(exc))
                else:self.fail("API error was hidden")
    async def test_timeout_has_separate_category_and_cancel_propagates(self):
        async def handler(request):raise httpx.ReadTimeout("private-request")
        real=httpx.AsyncClient
        with patch("httpx.AsyncClient",side_effect=lambda **kw:real(transport=httpx.MockTransport(handler),**kw)):
            with self.assertRaises(SetupError) as caught:await Ollama().async_request("/api/chat",{})
            self.assertEqual(getattr(caught.exception,"category",None),"timeout")
        async def cancelled(request):raise asyncio.CancelledError()
        with patch("httpx.AsyncClient",side_effect=lambda **kw:real(transport=httpx.MockTransport(cancelled),**kw)):
            with self.assertRaises(asyncio.CancelledError):await Ollama().async_request("/api/chat",{})
    def test_cpu_limits_are_configurable_and_bounded(self):
        api=Ollama()
        with patch.dict(os.environ,{"REDVECTOR_OLLAMA_TIMEOUT":"900","REDVECTOR_OLLAMA_CONTEXT":"4096","REDVECTOR_OLLAMA_PREDICT":"512"}):
            self.assertEqual(api.chat_timeout(),900)
            payload=api.chat_payload("custom",[],[])
            self.assertEqual(payload["options"]["num_ctx"],4096)
            self.assertEqual(payload["options"]["num_predict"],512)
        for key,value in [("REDVECTOR_OLLAMA_TIMEOUT","infinite"),("REDVECTOR_OLLAMA_CONTEXT","0"),("REDVECTOR_OLLAMA_PREDICT","999999")]:
            with patch.dict(os.environ,{key:value}),self.assertRaises(SetupError):
                if "TIMEOUT" in key:api.chat_timeout()
                else:api.chat_payload("custom",[],[])

    async def test_slow_response_and_total_deadline_are_bounded(self):
        async def handler(request):
            await asyncio.sleep(0.05)
            return httpx.Response(200,json={"version":"fixture"})
        real=httpx.AsyncClient
        with patch("httpx.AsyncClient",side_effect=lambda **kw:real(transport=httpx.MockTransport(handler),**kw)):
            self.assertEqual((await Ollama().async_request("/api/version",timeout=1))["version"],"fixture")
            with self.assertRaises(SetupError) as caught:await Ollama().async_request("/api/version",timeout=0.01)
            self.assertEqual(caught.exception.category,"timeout")

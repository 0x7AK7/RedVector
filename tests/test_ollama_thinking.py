"""Use only thinking controls explicitly advertised by the selected model."""
import unittest
from unittest.mock import AsyncMock,patch
from redvector_ollama_setup import Ollama

class ThinkingControls(unittest.IsolatedAsyncioTestCase):
    async def test_supported_fast_tool_calling_disables_optional_thinking(self):
        api=Ollama()
        with patch.object(api,"async_request",new=AsyncMock(side_effect=[
            {"thinking":{"values":[False,True],"default":True}},
            {"message":{"role":"assistant","content":"ok"}}])) as request:
            await api.async_show("qwen3:8b")
            await api.async_chat("qwen3:8b",[],[])
        self.assertIs(request.call_args_list[1].args[1].get("think"),False)
    async def test_required_thinking_model_does_not_receive_unsupported_false(self):
        api=Ollama()
        with patch.object(api,"async_request",new=AsyncMock(side_effect=[
            {"thinking":{"values":["low","medium","high"],"default":"medium"}},
            {"message":{"role":"assistant","content":"ok"}}])) as request:
            await api.async_show("gpt-oss:20b")
            await api.async_chat("gpt-oss:20b",[],[])
        self.assertNotIn("think",request.call_args_list[1].args[1])

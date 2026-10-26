import asyncio
from unittest.mock import AsyncMock
import pytest
from redvector_ollama_setup import Ollama,SetupError

def test_evidence_schema_reaches_official_chat_api_without_tools():
    asyncio.run(_format())

async def _format():
    api=Ollama()
    api.async_request=AsyncMock(return_value={"message":{"role":"assistant","content":"{}"}})
    schema={"type":"object","properties":{"status":{"enum":["COMPLETED"]}}}
    await api.async_chat("installed",[{"role":"user","content":"saved facts"}],[],response_schema=schema)
    payload=api.async_request.call_args.args[1]
    assert payload["format"]==schema
    assert not payload.get("tools")
    with pytest.raises(SetupError):
        await api.async_chat("installed",[],[{"type":"function"}],response_schema=schema)

"""Explicit offline Ollama boundary double; never used by live MCP smoke."""
from unittest.mock import AsyncMock,Mock

def model_api():
    api=Mock()
    api.async_chat=AsyncMock(side_effect=api.chat)
    api.async_show=AsyncMock(side_effect=api.show)
    return api

# AI Integration

RedVector separates two distinct systems. Keeping them separate is the key mental model.

## MCP clients connect TO RedVector

External AI applications speak MCP to RedVector (RedVector is the **server**):

- **Claude Desktop** — one-click setup
- **Cursor** — one-click setup
- **ChatGPT** — guided setup (configured in the ChatGPT app, not a local file)
- other MCP-compatible clients

```
Claude Desktop / Cursor / ChatGPT  ──MCP──▶  RedVector MCP ──▶ RedVector backend
```

### One-click setup (Claude Desktop, Cursor)

RedVector detects the client's per-OS MCP config file, backs it up, merges in a `redvector-ai` server entry (preserving all your other settings), writes it atomically, and verifies the result. If anything fails, the previous config is restored. A client restart is required to load RedVector.

The generated entry uses your current Python executable and the absolute path to `redvector_mcp.py` — no manual path editing.

### ChatGPT (guided)

ChatGPT connects to MCP servers through the ChatGPT app with account-level authorization, not a local JSON file. RedVector cannot silently configure it. The manager reports `setup_required` and provides guided steps: run the backend, start MCP over SSE (`python redvector_mcp.py --transport sse --mcp-port 8889`), expose it over a secure URL if remote access is needed, then add and authorize the connector in ChatGPT.

## AI providers are used BY RedVector

RedVector can call AI model services (RedVector is the **client**):

| Provider | Type | API key |
|---|---|---|
| Ollama | local | not required |
| Claude (Anthropic) | cloud | required |
| Gemini (Google) | cloud | required |
| DeepSeek | cloud | required |

```
RedVector ──▶ AI Provider Manager ──▶ Claude | Gemini | DeepSeek | Ollama
```

### Provider switching is transactional

Switching the active provider runs: configuration check → credential check → health check → model check → activate. If **any** step fails, the previous provider stays active and a clear error is returned. Switching never silently routes your data to a different cloud provider; any fallback is explicit and off by default.

### Credentials

API keys are stored via your OS keyring when available (Windows Credential Manager / macOS Keychain / Linux Secret Service). Without a keyring, RedVector falls back to read-only environment variables and never writes plaintext secrets. Secrets are never logged or returned in API responses.

## Management API

| Method | Route |
|---|---|
| GET | `/api/ai/integrations` |
| GET | `/api/ai/providers`, `/api/ai/providers/<id>`, `/api/ai/providers/<id>/models` |
| POST | `/api/ai/providers/<id>/test`, `/api/ai/providers/<id>/activate` |
| GET | `/api/ai/active` |
| GET | `/api/ai/clients`, `/api/ai/clients/<id>` |
| POST | `/api/ai/clients/<id>/connect`, `/verify`, `/restore` |

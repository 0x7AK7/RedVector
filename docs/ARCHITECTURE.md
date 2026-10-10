# RedVector Architecture

A high-level, public overview of how RedVector is structured. Facts here (tool counts, routes) reflect the shipped code.

## Flow

```
AI client (Claude Desktop / Cursor / ChatGPT)
        │  MCP (stdio / SSE / streamable-http)
        ▼
RedVector MCP  (redvector/mcp/server.py)
        │  REST (safe_get / safe_post / safe_delete)
        ▼
RedVector backend  (redvector/server.py)
        ├── security-tool routes  /api/tools/*   → execute_command → external binaries
        ├── autonomous routes     /api/autonomous/*
        ├── LLM routes            /api/llm/*
        └── AI Integration mgmt   /api/ai/*
        │
        ▼
AI providers  (Claude / Gemini / DeepSeek / Ollama)   ← used BY RedVector
```

## Components

| Module | Responsibility |
|---|---|
| `redvector/server.py` | Flask backend, routes, command execution, caching |
| `redvector/mcp/server.py` | MCP server; forwards tool calls to the REST backend |
| `redvector/mcp/core.py` | Typed MCP registry + transport adapter |
| `redvector/mcp/declarative.py` | Spec-driven MCP tool generation |
| `redvector/security_tools.py` | Typed security-tool registry + command builder |
| `redvector/config.py` | Typed configuration & startup resolution |
| `redvector/ai_integration.py` | AI Integration Manager (providers + MCP clients) |
| `redvector/core.py` / `redvector/workflows.py` / `redvector/payloads.py` | Core services, workflows, payload templates |
| `redvector/cve_intelligence.py` / `redvector/error_handling.py` / `redvector/cache_process.py` | CVE correlation, recovery, cache/process |

## MCP layer

RedVector registers **328** MCP tools through a central, inspectable registry: **171** are generated from typed specs and **157** are explicit custom handlers. Tool names, signatures, routes, and result/error shapes are stable.

## Security-tool layer

**134** integrations under `/api/tools/*`; **55** have declarative command builders driven by typed specs and **79** are custom handlers. Execution flows through a shared command executor. See [SECURITY_TOOLS.md](SECURITY_TOOLS.md).

## Configuration

Typed configuration resolves from environment, CLI, and defaults with clear precedence. See [CONFIGURATION.md](CONFIGURATION.md).

## AI Integration Manager

A typed provider abstraction + registry (Claude, Gemini, DeepSeek, Ollama), transactional provider switching (the previous provider is kept on any failed switch), secure credential handling, and one-click MCP client configuration with backup/rollback. See [AI_INTEGRATION.md](AI_INTEGRATION.md).

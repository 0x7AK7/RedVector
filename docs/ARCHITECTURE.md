# RedVector Architecture

A high-level, public overview of how RedVector is structured. Facts here (tool counts, routes) reflect the shipped code.

## Flow

```
AI client (Claude Desktop / Cursor / ChatGPT)
        │  MCP (stdio / SSE / streamable-http)
        ▼
RedVector MCP  (redvector_mcp.py)
        │  REST (safe_get / safe_post / safe_delete)
        ▼
RedVector backend  (redvector_server.py)
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
| `redvector_server.py` | Flask backend, routes, command execution, caching |
| `redvector_mcp.py` | MCP server; forwards tool calls to the REST backend |
| `redvector_mcp_core.py` | Typed MCP registry + transport adapter |
| `redvector_mcp_declarative.py` | Spec-driven MCP tool generation |
| `redvector_security_tools.py` | Typed security-tool registry + command builder |
| `redvector_config.py` | Typed configuration & startup resolution |
| `redvector_ai_integration.py` | AI Integration Manager (providers + MCP clients) |
| `redvector_core.py` / `redvector_workflows.py` / `redvector_payloads.py` | Core services, workflows, payload templates |
| `redvector_cve_intelligence.py` / `redvector_error_handling.py` / `redvector_cache_process.py` | CVE correlation, recovery, cache/process |

## MCP layer

RedVector registers **328** MCP tools through a central, inspectable registry: **171** are generated from typed specs and **157** are explicit custom handlers. Tool names, signatures, routes, and result/error shapes are stable.

## Security-tool layer

**134** integrations under `/api/tools/*`; **55** have declarative command builders driven by typed specs and **79** are custom handlers. Execution flows through a shared command executor. See [SECURITY_TOOLS.md](SECURITY_TOOLS.md).

## Configuration

Typed configuration resolves from environment, CLI, and defaults with clear precedence. See [CONFIGURATION.md](CONFIGURATION.md).

## AI Integration Manager

A typed provider abstraction + registry (Claude, Gemini, DeepSeek, Ollama), transactional provider switching (the previous provider is kept on any failed switch), secure credential handling, and one-click MCP client configuration with backup/rollback. See [AI_INTEGRATION.md](AI_INTEGRATION.md).

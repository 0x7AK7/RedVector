<div align="center">
  <img src="assets/Redvector-logo4.png" alt="RedVector" width="320"/>

  # RedVector

  **AI-assisted cybersecurity automation & security-testing platform**

  ![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
  ![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)
  ![REST API](https://img.shields.io/badge/API-Flask-black.svg)
  ![MCP Tools](https://img.shields.io/badge/MCP%20Tools-328-brightgreen.svg)
  ![Security Tools](https://img.shields.io/badge/Security%20Integrations-134-orange.svg)
  ![Use](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-red.svg)
</div>

---

## 1. Overview

RedVector is an AI-assisted platform that orchestrates established security tools behind a single, typed, auditable interface. It exposes a Flask REST backend and a Model Context Protocol (MCP) server so AI assistants can drive reconnaissance, vulnerability analysis, and reporting workflows against **systems you are authorized to test**.

## 2. Why RedVector

- **One interface, many tools** — 134 security-tool integrations behind consistent REST routes.
- **AI-native** — connect AI clients over MCP and let RedVector handle orchestration.
- **Typed & declarative** — tool and configuration surfaces are defined by typed specs, not scattered globals.
- **No manual config editing** — the AI Integration Manager connects clients/providers from one place.
- **Authorized-use first** — RedVector is a professional tool for legal engagements.

## 3. Key Features

- 328 MCP tools (171 spec-driven / 157 custom handlers) over a central, inspectable registry.
- 134 `/api/tools/*` security-tool integrations (55 declarative command builders / 79 custom).
- Typed configuration & startup with environment/CLI resolution.
- **AI Integration Manager**: connect/test/switch AI providers and configure MCP clients.

## 4. Architecture Overview

```
AI client (Claude Desktop / Cursor / ChatGPT)
        │  MCP
        ▼
RedVector MCP (redvector_mcp.py)
        │  REST
        ▼
RedVector backend (redvector_server.py) ── security-tool registry ── external tools
        │
        ▼
AI providers (Claude / Gemini / DeepSeek / Ollama)   ← used BY RedVector
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## 5. AI Integration

RedVector separates two systems (see [docs/AI_INTEGRATION.md](docs/AI_INTEGRATION.md)):

- **MCP clients connect TO RedVector** — Claude Desktop, Cursor, ChatGPT (guided), and other MCP clients.
- **AI providers are used BY RedVector** — Claude API, Gemini API, DeepSeek API, and local Ollama.

## 6. MCP Client Integration

One-click setup is available for Claude Desktop and Cursor (safe config merge + backup + rollback). ChatGPT uses a guided flow because it is configured in-app, not via a local file.

## 7. Supported AI Providers

| Provider | Type | API key | Model discovery |
|---|---|---|---|
| Ollama | local | no | yes |
| Claude (Anthropic) | cloud | yes | yes |
| Gemini (Google) | cloud | yes | yes |
| DeepSeek | cloud | yes | yes |

## 8. Installation

```bash
git clone <your-fork-url> redvector
cd redvector
python -m venv .venv
# Linux/macOS: source .venv/bin/activate   |   Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Full guide: [docs/INSTALLATION.md](docs/INSTALLATION.md).

## 9. Quick Start

```bash
python redvector_server.py            # starts the backend on 127.0.0.1:8888
curl http://127.0.0.1:8888/health     # verify
```

Connect an MCP client with `redvector_mcp.py` (see [docs/AI_INTEGRATION.md](docs/AI_INTEGRATION.md)).

## 10. Configuration

Environment variables, defaults, and precedence are documented in [docs/CONFIGURATION.md](docs/CONFIGURATION.md). Defaults: host `127.0.0.1`, port `8888`.

## 11. Security Tool Integration

RedVector **delegates** execution to external security binaries installed on the host (e.g. nmap, nuclei, trivy). It does not bundle or install them; if a binary is missing, the tool returns a failure result. Command construction is a stable contract.

## 12. Usage / Workflow

1. Start the backend. 2. Connect an AI client over MCP (or call the REST API). 3. Request an authorized task. 4. RedVector routes it to the right integration and returns structured output.

## 13. Platform Support

Windows, macOS, and Linux. External tool availability depends on your OS and installation.

## 14. Project Structure

```
redvector/
├── README.md, LICENSE, requirements.txt, .gitignore
├── redvector_server.py        # Flask backend + routes
├── redvector_mcp.py           # MCP server
├── redvector_mcp_core.py      # MCP registry + transport
├── redvector_mcp_declarative.py
├── redvector_security_tools.py
├── redvector_config.py        # typed configuration
├── redvector_ai_integration.py# AI Integration Manager
├── redvector_core.py, redvector_workflows.py, redvector_payloads.py
├── redvector_cve_intelligence.py, redvector_error_handling.py, redvector_cache_process.py
├── assets/  └── docs/  └── tests/
```

## 15. Documentation

- [Installation](docs/INSTALLATION.md)
- [Architecture](docs/ARCHITECTURE.md)
- [AI Integration](docs/AI_INTEGRATION.md)
- [Configuration](docs/CONFIGURATION.md)
- [Security / Authorized Use](docs/SECURITY.md)

## 16. Security / Authorized Use

RedVector is intended **only** for security testing you are explicitly authorized to perform. You are responsible for complying with all applicable laws and obtaining written authorization. See [docs/SECURITY.md](docs/SECURITY.md).

## 17. License

Released under the MIT License — see [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## 18. Author

Adam Karim.

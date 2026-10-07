# RedVector Configuration & Startup

> Generated from `tests/fixtures/config_startup_manifest.json` (the Phase-4 compatibility contract). Values are resolved by the typed model in `redvector_config.py`.

## Precedence

`cli > environment > config_file(none) > hard-coded default`

No host/port/LLM config file is read at runtime; FileConfigSource is a future no-op.

## Settings

| Setting | Env var | Default | Sources | Normalization | Secret |
|---|---|---|---|---|---|
| `server.port` | `REDVECTOR_PORT` | `8888` | cli:--port, env:REDVECTOR_PORT, default | int(env or 8888); empty/malformed -> ValueError at import | no |
| `server.host` | `REDVECTOR_HOST` | `127.0.0.1` | cli:--host, env:REDVECTOR_HOST, default | str | no |
| `server.token` | `REDVECTOR_API_TOKEN` | *** | env:REDVECTOR_API_TOKEN, default | str | yes |
| `runtime.debug_mode` | `DEBUG_MODE` | `False` | cli:--debug, env:DEBUG_MODE, default | env.lower() in {1,true,yes,y}; --debug forces True | no |
| `runtime.command_timeout` | - | `300` | constant | none | no |
| `runtime.cache_size` | - | `1000` | constant | none | no |
| `runtime.cache_ttl` | - | `3600` | constant | none | no |
| `runtime.max_cached_result_bytes` | - | `10485760` | constant | none | no |
| `llm.base_url` | `LLM_BASE_URL` | `http://127.0.0.1:11434` | env:LLM_BASE_URL, default | str | no |
| `llm.api_key` | `LLM_API_KEY` | *** | env:LLM_API_KEY, default | str | yes |
| `llm.default_model` | `LLM_MODEL` | `` | env:LLM_MODEL, default | str | no |
| `llm.timeout` | `LLM_TIMEOUT` | `120` | env:LLM_TIMEOUT, default | int(env or '120') | no |
| `platform.comspec` | `COMSPEC` | `cmd.exe` | env:COMSPEC, default | str | no |
| `mcp.default_server` | - | `http://127.0.0.1:8888` | cli:--server, constant | str | no |
| `mcp.default_timeout` | - | `300` | cli:--timeout, constant | int | no |
| `mcp.max_retries` | - | `3` | constant | none | no |
| `mcp.api_token` | `REDVECTOR_API_TOKEN` | *** | env:REDVECTOR_API_TOKEN, default | str | yes |
| `mcp.allow_insecure` | `REDVECTOR_ALLOW_INSECURE` | `False` | env:REDVECTOR_ALLOW_INSECURE, default | == '1' | no |
| `mcp.cli_transport` | - | `stdio` | cli:--transport, default | choice {stdio,sse,streamable-http} | no |
| `mcp.cli_mcp_port` | - | `8889` | cli:--mcp-port, default | int | no |
| `mcp.cli_mcp_host` | - | `127.0.0.1` | cli:--mcp-host, default | str | no |

## Entry points

### `server` — `redvector_server.py`
- Invocation: `python redvector_server.py`
- CLI: `--debug`, `--port`, `--host`
- Process: Flask app.run
- Logging: basicConfig INFO + redvector.log (import-time)

### `mcp` — `redvector_mcp.py`
- Invocation: `python redvector_mcp.py`
- CLI: `--server`, `--timeout`, `--transport`, `--mcp-port`, `--mcp-host`, `--debug`
- Process: FastMCP mcp.run(transport)
- Logging: basicConfig INFO stderr (import-time)

### `launcher_sh` — `start_redvector.sh`
- Invocation: `bash start_redvector.sh [args]`
- Behavior: cd script dir; activate .venv; start server if /health down (setsid, 30s wait); exec mcp --server

### `launcher_ps1` — `start_redvector.ps1`
- Invocation: `powershell start_redvector.ps1 [args]`
- Behavior: cd script dir; activate .venv; start server if /health down (Start-Process, 30s wait); run mcp --server

## Notes

- An empty or malformed `REDVECTOR_PORT` raises `ValueError` at import (preserved legacy behavior).
- Logging is configured at import time (`logging.basicConfig`); the server also writes `redvector.log`.
- Secrets (`REDVECTOR_API_TOKEN`, `LLM_API_KEY`) are tracked by source in provenance and never logged.

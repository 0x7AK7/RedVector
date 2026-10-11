# RedVector AI Setup

RedVector 8.0.0 makes it simple to connect AI clients, configure AI providers, and set up optional AI harnesses. The launcher delegates all of this to one shared Python setup layer, so you never have to hand-edit MCP JSON files or guess configuration paths.

Keep these categories separate:

- **AI clients** connect *to* RedVector over MCP: Claude Desktop, Cursor, ChatGPT, and other MCP-compatible clients.
- **AI providers** are used *by* RedVector: Ollama, Claude API, Gemini API, DeepSeek API.
- **AI harnesses** bring their own agent runtime: DeepSeek Harness (DSH).

## Commands

Linux / Kali:

RedVector is menu-first. Run the launcher with no arguments:

```bash
./start_redvector.sh
```

```
RedVector 8.0.0

1. AI Providers      Choose the AI RedVector uses
2. AI Clients        Connect external AI applications to RedVector
3. Start RedVector
4. AI Harnesses      Advanced: optional execution backends for specific workflows
5. Diagnostics       Full installation / configuration / connection details
6. Status            Quick system summary
0. Exit
```

RedVector starts straight into the classic interface when an AI provider is configured, validated, and reachable; otherwise it shows this menu. Use `./start_redvector.sh --menu` to always show the menu.

The menu runs in-process and loops: every submenu offers `0. Main menu`, actions return to the relevant menu, and you never restart the launcher to move between areas. Option 1 ensures the backend is running, loads the active AI provider/model, and opens the provider-agnostic chat (type `exit`, `quit`, or `0` to return to the menu). If no provider is configured, RedVector shows a short message and offers to configure one.

Power users may still use flags directly (Windows PowerShell uses the same flags with `.\start_redvector.ps1`):

```bash
./start_redvector.sh --chat
./start_redvector.sh --connect-claude
./start_redvector.sh --connect-cursor
./start_redvector.sh --setup-ai
./start_redvector.sh --setup-harness
./start_redvector.sh --diagnostics
./start_redvector.sh --status
./start_redvector.sh --provider ollama
./start_redvector.sh --disconnect-claude
./start_redvector.sh --disconnect-cursor
```

Non-interactive launches (for example when an MCP client starts RedVector through `start_redvector.sh`) start the backend and MCP directly and never show a menu.

## AI clients

Every client config change is backup-first, atomic, preserves unrelated MCP servers, prevents duplicate RedVector entries, and repairs a stale RedVector entry (for example one left behind by an upgrade). A valid config is reported `CONFIGURED`; RedVector never reports `CONNECTED` for a desktop client unless a live connection is actually observable, so after configuring you may see "waiting for the client to connect."

### Claude Desktop

On Linux, Claude Desktop is an official beta for Debian 12+/Ubuntu 22.04+ (x86_64/arm64), installed from Anthropic's apt repository with a signing key. Kali Linux is Debian-based; Claude Desktop may work, but Kali is not currently an officially validated Claude Desktop distribution. RedVector does not auto-add third-party apt repositories; it shows the official steps and marks installation `MANUAL REQUIRED`. Once Claude Desktop is installed, `--connect-claude` adds the RedVector MCP entry.

### Cursor

Cursor provides an official apt repository and direct `.deb`/RPM/AppImage downloads (x86_64/arm64). RedVector configures the per-user MCP file (`~/.cursor/mcp.json`) with `--connect-cursor`. It does not install arbitrary `.deb` files or add repositories automatically.

### ChatGPT

ChatGPT connects to RedVector as an MCP connector configured inside the ChatGPT app, not by editing a local JSON file. There is no local stdio MCP mechanism, so RedVector reports this as platform-dependent and provides guided steps (expose RedVector's MCP server over SSE and add it as a connector in the app).

### Other MCP clients

RedVector prints a copy-pasteable config (command, args, env, transport) using the current package entrypoint `python -m redvector.mcp.server`. It never auto-edits unknown third-party configuration files. Ready-made examples live under [docs/examples/](examples/).

## AI providers

Use `--setup-ai` (or `--provider <id>`). Provider setup reuses RedVector's existing provider manager; there is no second provider registry. API keys are entered securely, stored through RedVector's credential store, and never echoed, logged, or placed in documentation or release examples. Provider status shows `CONFIGURED` without displaying any secret.

### Ollama

RedVector detects the Ollama executable/service, checks the endpoint, lists installed models, and lets you select one. The recommended default is **dolphin-llama3:8b** (Dolphin 2.9, Llama-3 8B, ~4.7GB). This is a recommendation only and is never a RedVector runtime dependency; any installed model works. You can pick an installed model or enter a custom model name. Custom names are validated (no shell metacharacters), every pull requires explicit confirmation (nothing downloads silently), and a model is only activated after a minimal inference test passes. Model states: `INSTALLED`, `AVAILABLE_TO_PULL`, `DOWNLOADING`, `READY`, `FAILED`. RedVector does not auto-install Ollama; it links the official installer.

### Claude API, Gemini API, DeepSeek API

Each reuses RedVector's existing provider implementation with secure key entry, a connectivity health check, and activation through the provider manager. The Claude Desktop account login is a different thing from a Claude API key.

## DeepSeek Harness (DSH)

DSH is an optional developer-preview harness, official package `@deepseek-ai/dsh` (repository `deepseek-ai/deepseek-harness`). RedVector checks Node.js against the current engine requirement (`^22.19.0 || >=24.0.0`) plus `npx`, and runs it with `npx @deepseek-ai/dsh web` (no global npm install) after explicit confirmation. It never installs a similarly named unofficial package. DSH's current MCP client capability is not verified here, so RedVector does not invent DSH configuration syntax; it reports `MANUAL_GUIDANCE_REQUIRED` and points to the official documentation. First-run validation uses a safe temporary workspace, never your home directory, private keys, or RedVector's development workspace.

## Diagnostics and status

`--diagnostics` is read-only: it never modifies config, installs software, pulls models, runs security tools, or creates provider traffic beyond minimal health checks. It reports Python/venv/dependencies/backend/MCP, the live capability counts (read from the running registries), and client/provider/harness status.

`--status` prints a concise startup summary and performs bounded recovery for connections RedVector owns.

## Status model (Installation / Configuration / Connection)

`--diagnostics` and `--status` report every AI client, provider, and harness using three independent dimensions, so they are never conflated:

- Installation: is the app or runtime actually present? A config file existing does not mean the app is installed.
- Configuration: is RedVector's integration set up? An app being installed does not mean the config is complete.
- Connection: is a live connection actually observed? A complete config does not mean it is connected.

Claude Desktop and Claude Code are reported separately: the `claude` CLI (Claude Code) being installed is never treated as proof that the Claude Desktop app is installed. ChatGPT reports Installation as not applicable (it integrates via an in-app connector). Node.js is reported as its own prerequisite entity and never implies that DeepSeek Harness is ready. RedVector never fabricates `CONNECTED`; a desktop client that is configured but whose session RedVector cannot observe shows Connection `NOT OBSERVABLE`.

## Connection states and reconnect

Client states: `NOT_INSTALLED`, `INSTALLED`, `NOT_CONFIGURED`, `CONFIGURED`, `CONFIGURED_BUT_STALE`, `CONFIG_INVALID`, and `CONNECTED` only when actually observable. For connections RedVector controls directly (its backend, Ollama endpoint, API providers), recovery is bounded: it probes, then waits 1s, 2s, 4s between retries, then stops with a final `READY`/`CONNECTED` or `FAILED`/`DEGRADED`. RedVector never retries forever, never busy-loops, and never repeatedly triggers paid API calls to maintain an artificial connection. Desktop clients own their own session, so RedVector verifies configuration and MCP viability but never fabricates a client connection.

## Supported vs unvalidated systems

RedVector is honest about platforms. Where a vendor officially supports your OS, it says so; where your distribution is merely compatible (for example Kali as a Debian-based system) it says the vendor has not validated it; where no safe automated path exists it reports `MANUAL REQUIRED` and links the official source. It never invents package URLs or claims connectivity it cannot establish.

## Security and secrets

Secrets are handled by RedVector's existing credential store (environment variables are authoritative; optional OS keyring when available). RedVector never displays API keys, bearer tokens, Authorization headers, passwords, or private keys. It performs no account actions: it does not sign you in, create accounts, purchase credits, change subscriptions, or accept terms on your behalf.

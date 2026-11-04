# RedVector Diagnostic Plugin v0.1 (private, local-only)

A minimal, **read-only** MCP plugin for **ChatGPT Desktop** that reports basic
health/status/version of a **locally running** RedVector backend. It is
deliberately isolated from RedVector's main (offensive) MCP server: it never
imports or exposes those tools.

> Status: **prepared for review only.** Not installed, not executed, not
> connected to ChatGPT. Runtime behaviour (MCP handshake, ChatGPT recognition,
> real tool invocation) is **unverified** — see `SECURITY-REVIEW.md`.

## Contents

| File | Purpose |
|------|---------|
| `plugin.json` | Plugin identity/metadata (see schema caveat below). |
| `mcp.json` | Local **stdio** MCP server entry (documented format). |
| `adapter/redvector_diag_adapter.py` | Isolated read-only MCP adapter (stdlib only). |
| `SECURITY-REVIEW.md` | Static review notes + unverified properties. |

## Tools (exactly three, all read-only)

- `backend_health` — GET `http://<loopback>:<port>/health`; reports reachable/healthy.
- `service_status` — loopback TCP reachability + host/port (no secrets).
- `backend_version` — the **running** backend's self-reported `version` from
  `/health`, or `unknown`.

## Configuration (nothing hardcoded)

The adapter discovers the backend from the documented RedVector environment
variables, matching `start_redvector.sh`:

- `REDVECTOR_HOST` (default `127.0.0.1`, loopback only)
- `REDVECTOR_PORT` (**required**; if unset, tools report "not configured" rather
  than guessing a port)
- `REDVECTOR_DIAG_TIMEOUT` (optional, seconds; default 3, clamped 0.5–10)

Set these in the plugin's `mcp.json` `env` (when supported) or the launching
environment. The adapter refuses any non-loopback destination.

## Requirements

- Python 3 on `PATH` as `python3`.
- **No third-party Python packages** (standard library only).

## Install (future phase — requires separate authorization)

Local MCP plugins are created/installed via the officially supported ChatGPT
**Plugin Creator** flow on **ChatGPT Desktop**; local plugins install
automatically for the creator. Public Plugin Directory submission of a local-MCP
plugin additionally requires OpenAI partner allowlisting and is **out of scope**
here. Exact steps and the account/Linux prerequisites are in `SECURITY-REVIEW.md`.

## `plugin.json` schema caveat

OpenAI's `build/package` manifest reference was not retrievable during
preparation (HTTP 404). `plugin.json` here is intentionally minimal
(`name`/`version`/`description`). Before installation, reconcile it with the
schema the installed ChatGPT Desktop / Plugin Creator actually expects (e.g. let
Plugin Creator scaffold the manifest and drop in this vetted `mcp.json` +
adapter). No manifest fields were invented beyond these three.

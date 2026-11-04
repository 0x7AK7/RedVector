# RedVector Diagnostic Plugin v0.1 — Static Security Review

Prepared on Windows against a dev copy of the repo. **No execution, no backend
contact, no install, no Git operations.** Runtime properties remain unverified
until a separately authorized execution/ChatGPT test.

## Security controls (enforced in code)

1. **Exact-name allowlist** — `ALLOWED_TOOLS = ("backend_health","service_status","backend_version")`. `tools/call` rejects any other name with a JSON-RPC error **before** dispatch (fail-closed); the handler map holds only these three.
2. **No offensive registry** — the adapter imports no RedVector project module and never enumerates RedVector's MCP tools. It cannot reach the 328-tool registry.
3. **No shells / no subprocess** — `subprocess`, `os.system`, `os.popen`, `eval`, `exec`, `pty`, `shlex` are **not imported or used**. Imports are stdlib only: `ipaddress, json, os, socket, sys, urllib.*`.
4. **Loopback-only egress** — every HTTP GET resolves host from `REDVECTOR_HOST` (default `127.0.0.1`) and is refused unless the host is a loopback address / `localhost`; the assembled URL is re-validated (`http` + loopback) before connecting.
5. **No redirects** — a custom `HTTPRedirectHandler` returns `None`, so a redirect to a non-loopback host cannot be followed.
6. **No credentials** — no `Authorization` header is ever set (the backend's `/health` is auth-exempt). No token/secret is read into requests or logs.
7. **No listener / no state change** — the adapter only makes client connections; it never binds a port and never starts/stops/restarts the backend.
8. **Minimal output** — tool results contain only small, non-sensitive fields; exceptions are caught and returned as a generic "diagnostic error" (no stack traces, no paths, no secrets).
9. **Bounded resource use** — short clamped timeout (0.5–10s) and a 64 KiB read cap.
10. **No hardcoding** — no username, home dir, project path, OS/app/backend version, or port is baked in; the backend port must come from `REDVECTOR_PORT` or the tools report "not configured".

## Tool inventory (confirmed)

Exactly three tools are defined and handled: `backend_health`, `service_status`,
`backend_version`. Grep confirms no fourth handler and no dynamic tool
registration.

## Backend configuration discovery

`/health` and `/health/details` are **auth-exempt** in `redvector_server.py`
(`AUTH_EXEMPT_PATHS`), and `/health` returns `{"status","message","version","uptime"}`.
`backend_version` reads the **running** server's `version` from that response —
it does not assume the source-tree version matches, and returns `unknown` when
unavailable. Host/port come from `REDVECTOR_HOST`/`REDVECTOR_PORT` (same
convention as `start_redvector.sh`).

## Properties NOT verified at this phase (require authorized execution)

- MCP initialization handshake actually succeeds with a real client.
- Protocol-version / message-framing compatibility with **ChatGPT Desktop**
  (the adapter implements a minimal newline-delimited JSON-RPC MCP transport by
  hand; it has not been run against MCP Inspector or ChatGPT).
- `tools/list` is accepted and the three tools appear in ChatGPT.
- A real read-only tool call returns a verified backend result.
- `plugin.json` matches the exact schema the installed app expects (manifest
  reference doc was 404 during preparation).
- Whether the installed **Kali Linux** ChatGPT Desktop preview enables local
  stdio MCP plugins at all, and whether the account may create them.

## Next approval boundary (each needs your explicit go-ahead)

Executing the adapter / MCP Inspector handshake · contacting the backend ·
installing or registering the plugin in ChatGPT · activating it · publishing ·
any Git commit or push.

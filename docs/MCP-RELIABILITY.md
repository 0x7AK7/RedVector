# MCP Reliability & Claude Desktop Limitations

This page documents the Model Context Protocol (MCP) transport limitations that
affect RedVector when it runs as a local **stdio** MCP server under **Claude
Desktop**, and the mitigations shipped in the upcoming **v8.1.0 — MCP
Reliability & Stability Update**.

It separates **confirmed, measured behaviour** from **inferences that have not
been independently verified**, so operators can rely on the first set and treat
the second as working hypotheses.

> Scope note: the root limitation is **host-side** (Claude Desktop), not in
> RedVector. RedVector cannot lengthen or override the host's deadline; it can
> only report clearly, avoid making things worse, and keep read-only
> diagnostics usable.

---

## Confirmed limitations (Claude Desktop 4.4212.0, Linux)

Measured with a harmless synthetic stdio MCP probe (sleep/progress/in-memory
job only — no network, no tools):

1. **~55–60 s per-tool-call timeout.** Any single MCP tool call that runs longer
   than ~55–60 seconds is cancelled by the host with
   `MCP error -32001: Request timed out`. Calls of 30/45/55 s succeed; 60 s
   fails. The boundary sits between 55 s and 60 s.
2. **The per-server `timeout` in `claude_desktop_config.json` is not honored.**
   Setting a large value (e.g. `300000`) does not change the ~60 s cancellation.
3. **Progress notifications do not reset the deadline.** A call that emits
   `notifications/progress` every second is still cancelled at ~60 s.
4. **The server survives the cancellation.** A read-only call issued immediately
   after a timeout still returns — the failure is on the host/transport side,
   not a RedVector crash.

### Operational consequence
A long single operation (deep Nmap, large Nuclei run, big wordlist) can exceed
~60 s and be cancelled by Claude Desktop. In some runs the transport is then
dropped and the tools disappear from the session until Claude Desktop is fully
quit and relaunched (see the unverified note below on intermittency).

---

## Not independently verified (treat as hypotheses)

- **Suspected cause.** The fixed ~60 s bound is *consistent with* the MCP
  TypeScript SDK's default request timeout and the absence of
  `resetTimeoutOnProgress`, but this has **not** been confirmed from Claude
  Desktop internals.
- **Disconnect-until-restart is intermittent.** The hard transport drop happens
  in *some* runs, not reproducibly every time; the exact trigger was not
  isolated.
- **Other versions/OSes.** Only 4.4212.0 on Linux was measured.

---

## Recommended usage while the host limit stands

- **Keep single tool calls short.** Prefer scoped targets, tighter port ranges,
  smaller wordlists, and tool-level time budgets so an individual call returns
  well under ~55 s.
- **Split long work** into several shorter calls rather than one long one.
- **If tools vanish mid-session**, fully quit and relaunch Claude Desktop; the
  backend keeps running and reconnects on relaunch.
- **Read-only diagnostics stay usable** right after a timeout (health, telemetry,
  process/cache status), which helps confirm the backend is still alive before
  you restart the host.

---

## What v8.1.0 changes (and deliberately does not)

Shipped mitigations are **additive and safety-oriented**. They do **not** change
offensive execution semantics, add autonomous capability, or bypass any
authentication, authorization, ownership or permission control. All 328 MCP
tools and their exact input schemas are unchanged.

- **C1 — Typed error reporting.** Client request failures now carry an
  `error_type` (`connection_error`, `client_timeout`, `backend_http_error`
  [+`status_code`], `request_error`, `unexpected_error`) so a slow-but-alive
  backend is distinguishable from one that is actually down. Existing
  `success`/`error` fields are retained.
- **C2 — No auto-retry after timeout.** A command that times out is returned
  as-is and is **not** automatically re-run. Re-running a long operation that
  already hit its deadline would duplicate work/side effects and push further
  past the host deadline. Non-timeout failures still use the existing recovery
  path. The operator remains free to re-issue a call deliberately.
- **C4 — Backend health reachability.** The health check returns an additive
  read-only `reachable` flag (no new tool, no schema change, no extra backend
  call).
- **C5 — Credential-safe errors.** Error strings returned to the host and
  written to logs are scrubbed of credential shapes (bearer/authorization
  headers, `token=`/`api_key=` pairs, URL userinfo) plus the live API token.
- **R4 — Safe connection recovery for read-only diagnostics.** When a read-only
  diagnostic (health, telemetry, cache, process/error-handling status) hits a
  connection error or client timeout, it performs **at most one** read-only
  `/health` re-probe and returns an additive `reachable` flag plus an actionable
  `recovery_hint`. Offensive operations get **no** new retry or reconnect.
- **R5 — Safe process cleanup on timeout.** A timed-out command's direct child is
  terminated and reaped; on POSIX its process group is cleaned up so helper
  processes it spawned are not orphaned, while unrelated processes are never
  signalled. No new execution capability is added. (Does not change the host
  timeout itself — see below.)

### Still out of scope (host-side; cannot be fixed in RedVector)
The ~55–60 s cancellation, the ignored `timeout` config, the lack of
progress-based reset, and the absence of auto-reconnect are Claude Desktop
behaviours. They are reported upstream (see the synthetic-probe bug report) and
can only be resolved by the host.

---

## References
- Upstream bug report (local, not yet submitted):
  `claude-desktop-mcp-timeout-bugreport.md` + the harmless synthetic probe.
- MCP lifecycle (request timeouts):
  https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle
- MCP cancellation & progress-based reset:
  https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/cancellation

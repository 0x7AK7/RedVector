# CLI, target scope and MCP agent implementation plan

> Execute using test-driven development; independent policy and CLI domains may
> be implemented in parallel under the dispatching-parallel-agents workflow.
> Do not commit, push, download models, change branches or touch existing services.

Goal: deterministic English CLI commands, atomic explicit target authorization,
safe real assessment execution and clear model/result handling.

User spec: attached production CLI/target scope/MCP agent request dated 2026-10-26.
Branch: 0x7AK7/ollama-mcp-integration; initial HEAD a9af807c3eed677534444d02bc4542019aa4fac4.
Keep original checkout, banner, backend, Claude configuration, storage and
verified backend reuse unchanged.

Architecture and decisions:
- Session-local Policy with atomic replace_scope(), canonical scope snapshot(),
  revision and DNS pins. Explicit names authorize only their displayed pinned
  initial destinations; changes are rejected, never automatically added.
- Scope IPv4/IPv6 hosts/networks, exact hostnames and whitespace-separated sets.
  CIDR host bits normalize visibly. Active invocations remain a single numeric
  unicast host per approval; network scope grants membership, not automatic fanout.
- Validate every assessment argument. The only active operation is the reviewed
  TCP-connect Nmap invocation, no active version detection or NSE,
  no free command text, no DNS resolution by Nmap, no automatic recovery.
- Add optional use_recovery=True to the existing MCP Nmap wrapper; existing
  clients retain their default behavior, Ollama explicitly passes False.
  WHOIS referrals cannot be constrained by the existing backend: keep registration
  but disable agent execution with that explicit reason. No arbitrary fallback.
- Deterministic command dispatcher handles outer whitespace, /scope [TARGET...],
  /scope (display), /scope --clear, /tools [QUERY], /status, /back, /exit, /help.
  Unknown slash commands never reach the model. Red prompt resets before input;
  NO_COLOR/non-TTY stays plain and readline uses nonprinting markers.
- Natural-language scans use a single explicitly authorized host where clear;
  missing/ambiguous/incomplete scope/task asks for clarification without a model
  call. Send a fresh trusted scope snapshot and relevant schemas each turn.
- No blank/thinking-only final answers; discovery/disabled/failed operations have
  explicit attribution. History retains raw model content, never UI wrappers.
  Technical failures go to a private sanitized diagnostic log; no secret echoes.
- Real acceptance: native Kali, real backend/MCP, all 328 tools, harmless health
  and Nmap against only a test-owned loopback listener; no public scanning.
  Existing qwen3:8b may be reused, never downloaded or changed.

Known limits before implementation: unmodified backend cannot enforce network
egress for WHOIS referrals or arbitrary tools. OS-level routing/DNS resolver
traffic is not an application egress sandbox. Network scopes do not trigger
automatic large scans; operators choose a host. Only demonstrably confined
invocations can execute.

- [x] Add red tests and implement atomic scope/DNS/argument/approval policy.
- [x] Add red tests and implement command dispatch, prompt and scope display.
- [x] Fix relevance, scan context and empty/error/result handling with regressions.
- [x] Extend MCP Nmap wrapper with default-preserving recovery control.
- [x] Independent security review and real controlled Nmap/MCP acceptance.
- [x] Run full Windows/Kali suites and report exact evidence and limits.

Reviewed amendment: official Nmap documentation confirms -sV automatically runs
version-category scripts. The new light-version option was removed before
delivery; only -sT (derived -6 for IPv6) is allowed. Port-name service mappings
are not presented as verified product versions. Native model-to-scan acceptance
is recorded separately from mock-model regression fixtures.

Actual counts, separate native UI/model/PTY evidence and operational limits
are recorded in [the validation report](../../ollama-cli-scope-validation.md).

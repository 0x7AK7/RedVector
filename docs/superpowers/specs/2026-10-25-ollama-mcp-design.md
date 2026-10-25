# Automatic Ollama Integration — Design

Date: 2026-10-25
Repository: https://github.com/0x7AK7/RedVector.git
Checkout: the dedicated RedVector Ollama development checkout.
Branch: 0x7AK7/ollama-mcp-integration
Verified base: 5c7a62928f301430c4f9616449ce6f8e5865a167

## Intent and constraints

Implement the user's English-only interactive Linux Ollama installer and local MCP agent. Kali is primary; Debian and Ubuntu are supported where practical. The original RedVector-main directory is untouched. No pushes, merges, PRs, history rewriting, global Git changes, website changes, or protected-branch changes.

Existing backend, authentication, terminal banner, Claude Desktop integration, launchers, MCP configurations, and all 328 MCP registrations remain unchanged. Only new Ollama files, regression tests, and a concise README section are introduced.

## Approach

The supplied specification determines the architecture: Ollama chat API → new local Python agent → MCP ClientSession over stdio → existing start_redvector.sh → existing redvector_mcp.py → existing Flask backend.

A direct Flask adapter would bypass required MCP initialization and schema discovery. A second MCP server or backend would duplicate existing functionality. Neither meets the supplied requirements. The implementation uses the existing Python MCP SDK and its stdio client, not a separate graphical application.

The following implementation details are proposed builder choices rather than additional user requirements.

## Files and responsibilities

- install_redvector_ollama.sh: Bash entry point that resolves its own real project path, selects the project Python interpreter, checks prerequisites, and starts the installation wizard.
- start_redvector_ollama.sh: equivalent separate startup entry point, using saved model selection.
- redvector_ollama_setup.py: English menus, terminal formatting, Ollama installation/service/model management, resource checks, and local configuration persistence.
- redvector_ollama_agent.py: asynchronous MCP lifecycle, Ollama tool-calling conversation, schema validation, task-specific discovery, bounded execution, and terminal interaction.
- redvector_ollama_policy.py: explicit tool classification, scope and argument validation, and operator approval policy.
- tests/test_ollama_setup.py, tests/test_ollama_agent.py, tests/test_ollama_policy.py: new regression tests and harmless integration smoke coverage.
- README.md: Automatic Ollama Integration prerequisites, installation, model selection, startup, diagnostics, and troubleshooting.

No existing source code or Claude configuration needs modification. Reuse redvector_banner.render_banner() for the artwork, stripping ANSI in the new interface when NO_COLOR is set or no capable terminal is available.

## Installation and model workflow

1. Check Linux, Bash, Python, curl, project environment dependencies, Ollama executable, and local API health. Present explicit retry, skip, back, and exit choices. EOF and Ctrl-C cancel cleanly.
2. If Ollama is missing, offer install/skip/exit. Download only https://ollama.com/install.sh into a private temporary file using HTTPS. Identify the source and destination, explain privileges, allow inspection, and obtain explicit confirmation before invoking the saved script. Never pipe network content to a shell. Report failures without continuing as if installation succeeded.
3. Accept only a local Ollama endpoint; bypass HTTP proxies and redirects. Reuse a healthy service. Start only when required, bind a new service to 127.0.0.1:11434, coordinate competing starts with a lock, poll readiness, and report occupied/unhealthy ports without killing processes.
4. Show exactly the seven requested model choices and official identifiers. List installed models using /api/tags. Validate custom identifiers as data; subprocess commands use argument arrays without a shell.
5. Show known approximate model download sizes. For custom models obtain available official manifest size metadata without starting a pull; if reliable size metadata is unavailable, disclose uncertainty and require an operator-supplied conservative download budget before enforcing free-space checks. Measure space in the effective model storage location; report when service-user storage cannot be established and require its path before downloading.
6. Report RAM and GPU resources, including unavailable detection. Explain model requirements as estimates, and warn before proceeding on constrained memory. Block a pull when storage is insufficient. Existing models are reused unless the operator explicitly requests an update.
7. Execute ollama pull with its native progress attached to the terminal. Preserve partial downloads on cancellation so Ollama can resume. Verify the selected model through /api/show and persist only a successful selection atomically in an Ollama-specific user configuration file with restrictive permissions. Do not persist API tokens.
8. Present the six requested startup options. Starting validates service, selected model, and tool-calling support before connecting MCP. MCP diagnostics can run independently of model support. No target is requested during installation.

## MCP and model interaction

Use the existing launcher as the stdio subprocess with the same environment token behavior and project working directory. Let that launcher retain responsibility for backend ownership and health checks. Initialize the MCP session, follow paginated tools/list results, validate discovered tool names and JSON input schemas, and show the actual discovery count. Record any mismatch from the expected 328 as a diagnostic.

Use Ollama /api/show capabilities plus a harmless synthetic tool-call probe to verify tool calling before enabling agent mode; a probe never invokes a real assessment tool. Unsupported or inconclusive models receive a clear English diagnostic and can be changed.

Expose a small local discovery function that returns matching tool names and concise descriptions. Load a bounded selection of actual MCP schemas relevant to the operator task; never send all verbose schemas by default. Reject unknown tool names and invalid arguments before MCP dispatch. Bound model rounds, tool calls per turn, timeouts, response sizes, and history size. Preserve structured tool call IDs, arguments, errors, and real results across multiple steps.

Treat tool results as untrusted data. Render a concise real result for the operator before continuing the conversation. Clearly distinguish failures, blocked calls, empty output, and verified results. Never infer that a scan succeeded from a model assertion.

## Assessment safety and operator control

First-run verification exposes only a reviewed read-only diagnostic allowlist such as server_health and get_cache_stats, after inspecting their implementations. It does not require a target or invoke a security executable.

The operator explicitly supplies authorized target scope in the interactive session before any assessment call. Scope is session-local and comes from terminal input, never from model text. Normalize IPs, networks, hostnames, and URLs and compare target-bearing arguments against that scope. Reject ambiguous, out-of-scope, or unclassifiable calls.

Arbitrary command, script, payload, persistence, credential access, and autonomous compound-operation tools are not enabled through model text. Preserve their existing MCP registrations for other clients. Tools lacking a reviewed argument and target validation policy remain discoverable but cannot be executed by this agent.

Reviewed assessment tools require validated structured arguments, explicit scope, and display of the exact proposed operation. High-impact or state-changing operations require separate per-call operator approval and cannot be approved by the model, a saved blanket setting, or tool output. Cancelled approval becomes a structured denial; nothing is executed.

For an initial implementation, support a small explicit assessment allowlist with dedicated validators; do not automatically authorize all 328 tools based on names or descriptive heuristics. Documentation explains this agent policy and its coverage.

## Verification

Add automated coverage for every requested case: Ollama present/missing, declined installation, insufficient disk, selected/existing/invalid model, unavailable service, unsupported tool calling, MCP initialization/discovery, reused backend, failed backend health, cancellation, and unchanged Claude configuration.

Also cover scope bypass attempts, shell metacharacters and free-form command arguments, invalid schemas, pagination, model-call errors, tool-call errors, approval rejection, bounded loops, config atomicity, endpoint restrictions, paths containing spaces, and duplicate startup.

Run the existing regression suite and new tests. Compare protected source/config/banner files and registration counts against the verified base. Use real MCP initialization and read-only tool output for the integration smoke test; use deterministic mock Ollama responses for offline protocol tests, clearly labeled. A real Ollama/model smoke test is reported separately and only claimed if available.

This Windows host may not provide a Linux service environment, Linux /proc process verification, or an installed Ollama model. Inspect available Bash/WSL/Python dependencies before selecting runnable checks; report unavailable Linux or live-model validation explicitly, without claiming it passed.

## Completion report

Report every changed file, automated results, live smoke results and limitations, current branch, unchanged main hash, and no push/merge/PR. Leave changes available for user review.

## Implementation clarifications

A separate redvector_ollama_dependencies.py validates both existing/new requirement constraints and the MCP client APIs without importing the backend. Inference uses cancellable httpx async streams. Windows Git converts the existing LF Bash launcher to CRLF in this checkout; the new bridge runs a private temporary LF copy beside it, removes that copy on exit, and leaves the original untouched. Active Nmap calls require IPv4 until a reviewed IPv6 policy exists. Existing Nmap recovery may retry with fixed timing/timeout changes inside the approved target scope.

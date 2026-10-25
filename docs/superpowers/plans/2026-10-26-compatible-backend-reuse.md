# Compatible backend reuse implementation plan

> Execute inline using systematic debugging and test-driven development.
> Do not commit, push, modify Claude configuration or stop pre-existing processes.

Goal: allow the Ollama MCP launcher to reuse a verified compatible backend from
another directory without trusting health JSON alone.

Architecture: add an Ollama-only verifier; adapt only the already transient
Ollama launcher copy to use it. Legacy launchers and their checker stay intact.
Trust evidence: kernel listener ownership; readable process start time,
executable, argv, cwd and same root/mount/network context; verified Python
executable; backend and local banner content matching this checkout (CRLF/LF
normalization only), unchanged since process startup; compatible healthy API
and enforced authentication with the operator-supplied token. No remote calls,
namespace entry, token discovery, process changes or port switching.
Recheck identity after HTTP and MCP initialization to detect startup races.

Exact matching is conservative: independently modified/older backend source
requires review, even if health claims version 8.0.0. Source matching does not
attest a compromised OS, malicious Python dependencies or runtime memory.
Alternative HTTP-only reuse is explicitly forbidden; changing shared Claude
launcher behavior is unnecessary and would broaden this task.

- [x] Add failing portable verifier tests for equivalent copies, foreign code,
  inaccessible metadata, endpoint binding, restart and authentication.
- [x] Implement verifier and Ollama-only transient launcher adaptation.
- [x] Add live Linux cross-checkout backend/MCP test on an isolated free port.
  Stop only processes created by that test, never an existing operator backend.
- [x] Run Windows and Kali regressions and real MCP tool execution.
- [x] Document trust boundaries, actual counts and any live-environment limits.

Validation results and conservative source-layout/timestamp limits are in
[the delivery report](../../ollama-backend-reuse-validation.md).

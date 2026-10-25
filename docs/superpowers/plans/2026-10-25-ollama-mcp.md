# Ollama MCP Implementation Plan
> Implement inline using superpowers:executing-plans and test-driven-development.

Goal: deliver the approved automatic installer and real MCP agent.
Spec: ../specs/2026-10-25-ollama-mcp-design.md
Architecture: Bash entry points, Python setup and policy modules, SDK stdio client, existing launcher and backend.
Constraints: branch 0x7AK7/ollama-mcp-integration only; existing architecture, website, banner, Claude configuration and original directory unchanged. No push, merge or publish; repository-local identity 0x7AK7.

## Tasks
- [x] 1. Add failing policy, setup and agent tests. Interfaces: Policy.authorize(name,args,approve), Ollama.request(path,payload), Wizard.select_model(), Bridge.connect(), Agent.turn(text).
- [x] 2. Implement reviewed diagnostic/assessment policy. Validate JSON schemas, explicit exact target scope, strict argument formats, and separate approval for each state change. Test malformed inputs, injection, scope escapes, denied approvals.
- [x] 3. Implement local Ollama HTTP, installation, service locking/readiness, download budgeting, model verification, atomic configuration, menus and Bash entry points. Test present/missing/declined Ollama, storage, reuse, invalid models, cancellation, paths with spaces.
- [x] 4. Implement real MCP SDK initialization, pagination and schema discovery, capability probe, tool selection and bounded multi-step calls. Test errors, malformed schemas, unknown calls, round limits and results.
- [x] 5. Add harmless real-backend MCP smoke test; install isolated test dependencies if needed. Run existing plus new regression suite; distinguish real smoke from offline model doubles. Document operation, prerequisites, policy coverage and troubleshooting.
- [x] 6. Fresh branch review, fix material findings, final tests and preservation checks. Report changed files and verification limits.

Review focus: endpoint redirects/proxies; service ownership and races; custom download sizes/storage path; scope cannot be supplied by model; tool-output errors cannot become success.
Verification: python -m pytest -q; isolated MCP smoke; Bash syntax where available; git diff against base for all protected paths.

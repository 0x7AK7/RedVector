# Unified evidence presentation plan
User brief: professional unified terminal UI across existing workflow categories.
Continue existing uncommitted scan/timeout implementation; no backend, policy,
banner, README, Claude configuration, model download or Git publication changes.

Design choice: extend the existing Python presentation layer, not a new terminal
dependency or per-tool terminal implementations. A normalized, source-labelled
view feeds shared panels/tables and existing private evidence exports. Category
names are display metadata, never an execution authorization decision.
Unknown schemas use lossless flattened source-field display. Candidate, observed,
and source-confirmed findings remain distinct; tool completion is not compromise.
All result fields remain available through /results and exact /raw /export.
AI operates on bounded saved pages with no tool capability; rejects invented
fields. Existing strict Nmap analysis and automatic-discovery limits stay intact.

1. Add regression fixtures for vulnerability/candidate/execution/session/web/API/
cloud/wireless/forensics/OSINT/unknown schemas, states, severity and safety.
2. Add normalization and reusable width-aware panels/tables. Preserve scan adapter.
3. Generalize private record creation and saved-result rendering without changing
the schema of existing scan records or exact raw exports.
4. Integrate all permitted MCP results, progress, blocked/errors, discovery, approval,
scope, diagnostics and AI sections. Keep menus and banner unchanged.
5. Extend saved-only analysis and timeout recovery to non-scan operations.
6. Run full Windows and native Kali regressions plus real read-only MCP health.
Document actual tests separately from presentation fixtures.

Review focus: malicious terminal controls; uncertain outcomes; malformed nested
data; large evidence; no repeated actions on AI failure; no policy expansion;
narrow/redirected output; unsupported vs blocked; old saved record compatibility.

Completed: shared adapters/panels, generic private evidence and scope context, constrained saved-only analysis, native real model/Bash acceptance, review fixes, Windows354/24skip and native376/1skip regression verification. Detailed report: docs/ollama-unified-presentation-validation.md. No publication or README changes.

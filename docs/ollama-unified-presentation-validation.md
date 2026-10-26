# Unified terminal presentation validation — 2026-10-26

Branch: 0x7AK7/ollama-mcp-integration. This extends the existing uncommitted
scan workflow, evidence and timeout work; it does not replace that work.
No commit, staging, push, merge, PR, publication or model download is authorized
or performed. README.md remains unchanged.

## Root cause and design

The previous presentation adapter and saved-only recovery were hardwired to
nmap_scan. Other tool responses used the generic raw JSON conversation path.
Terminal.box also used a fixed border width. Those paths could not consistently
present source findings or retain an independently usable result after AI failure.

Shared Panel primitives now provide runtime width detection, wrapped/aligned
source fields, headings, tables, status coloring, neutral body text, ASCII-safe
terminal sanitization, NO_COLOR and redirected output. Existing menus retain their
commands and content; the existing banner is untouched.

The generic source adapter preserves complementary JSON dictionaries and
text/array evidence, deduplicates exact repeats, and exposes conflicting alternatives.
Supplied status/return-code aliases must agree before completion is reported.
Malformed/missing content stays Unknown with warnings. Primary severity totals
are explicitly qualified if alternative evidence conflicts.

The existing Nmap adapter retains numeric TCP/UDP sorting and adds source-reported
host state, invocation scan type and filtered counts. Absence is never interpreted
as zero or as a verified product version.

## Components and integration

- redvector_ollama_panels.py: shared Panel.section/fields/table/line and status colors.
- redvector_ollama_views.py: ordered workflow families, lossless source-leaf display,
  conservative execution states, source severity/validation and byte-bounded pages.
- redvector_ollama_presentation.py: shared factual-result, tool-discovery and approval
  panels, plus the existing scan renderer.
- redvector_ollama_results.py: existing private storage/export generalized to all
  executed tools. Original MCP wire/normalized evidence remains intact. New records
  include the actual operator scope, pinned DNS, revision and approval context.
  Old schema-1 records remain readable; backend report/export formats are untouched.
- redvector_ollama_generic_analysis.py: optional saved-only model interpretation.
  Only known evidence-grounded observation IDs are accepted. Status/fields must
  exactly match the source page; unknown/duplicate explanation IDs are rejected.
  Baseline priority/validation/limitations are visible even if the model selects none.
- redvector_ollama_analysis.py: dispatches generic records while preserving the
  existing scan-specific verifier.
- agent/CLI/setup: all permitted tool outputs and saved-result commands use the
  shared design. /status and /tools no longer dump raw MCP JSON. /raw remains the
  explicit original-evidence view. The legacy programmatic evidence callback remains
  compatible. Normal tool calling does not use the optional analysis response schema.

Official structured-output API reference:
[Ollama structured outputs](https://github.com/ollama/ollama/blob/main/docs/capabilities/structured-outputs.mdx).
The format schema is supplied only to tool-free optional analysis; local validation
still checks the returned fields. Models/APIs that cannot provide valid output
leave analysis Unavailable and retain the actual operation result.

## Workflow coverage and limits

The shared source adapter renders actual fields from every discovered registration,
including unfamiliar schemas, without enabling their execution. Display families
cover reconnaissance, network/protocol scanning, vulnerability/advisory/configuration,
web/API/cloud/wireless/authentication, OSINT/forensics, exploit candidates/execution,
privilege escalation, pivoting/lateral movement, post-exploitation/sessions,
diagnostics, AI models and reporting. Scope, approval, progress, evidence and result
commands share the same terminal components.

This is not a claim that all families can execute through this client. Its reviewed
allowlist is still exactly server_health, get_cache_stats, clear_cache and nmap_scan.
Other registered operations remain Blocked by client policy; absent registrations
remain Unavailable. Selection never grants execution eligibility. No new exploit,
escalation, credential attack, pivot or lateral movement capability was added.

Source findings retain CVE/CWE/CVSS/version, references, evidence, remediation,
timestamps, session/route/hash/privilege values whenever actually returned.
A scanner's confirmation remains source-reported rather than independently verified.
Open ports never become confirmed vulnerabilities. Unfamiliar fields are shown by
source path rather than guessed semantics. Large/nested evidence remains accessible
through /results, /raw and private JSON export. Beyond display-depth limits, raw
evidence remains authoritative. AI pages can be retried separately without executing
the original tool. General free-form model claims are intentionally not accepted
as factual findings.

## Verification ledger

Final Windows and native Kali counts are recorded below after the final runs.
The previously completed installer/capacity/model-selection acceptance is not
unnecessarily repeated. The native regression command excludes the older long
test_ollama_kali_uat.py acceptance scenario; its assertions were adapted to the new
panel contract. A focused real Bash acceptance covers changed presentation paths.

Commands:
- rtk proxy .\\.ollama-test-env\\Scripts\\python.exe .ollama-test-env/unified_windows.py
  runs python -m pytest -q -s, with the existing explicit smoke-test environment.
- rtk proxy .\\.ollama-test-env\\Scripts\\python.exe .ollama-test-env/unified_kali.py
  runs native Kali Python 3.13 pytest -q -s --ignore=tests/test_ollama_kali_uat.py.
  It uses the already installed runtime/model store via opt-in test variables.
- The native real test uses an existing official Ollama binary on a random loopback
  port and the existing selected model. Test-owned backend instances use a separate
  random port and token. Cleanup verifies process creation time/executable and never
  stops a pre-existing service. Model manifest hashes must remain unchanged.

Actual command arrays, timings and stdout are stored only in ignored docs/kali-uat
*-command.json / *-tests.txt artifacts; no logs or machine-specific runtime config
are added as delivery files.

Historical validation issues:
1. Initial native run: 371 passed, 1 failed, 1 skipped (123 subtests).
   The new real AI test had no running Ollama service. Backend/MCP and owned-loopback
   Nmap tests passed. The fixture now starts only its own existing official runtime;
   it does not install or pull.
2. First test-owned real health run: MCP completed and evidence persisted; generic
   AI output failed exact validation (invalid-summary). The operation correctly stayed
   Completed and provided an evidence-only retry. No successful result was fabricated.
3. Saved-evidence-only replay: actual model generation reached the response limit.
   It did not invoke MCP again. Schema-constrained optional output was added and
   validated without removing evidence or ID checks.
4. Red/green regressions reproduced complementary evidence loss, malformed content,
   Unicode byte overflow, contradictory status aliases, fixed-width boxes, missing
   scan metadata, missing report authorization context and diagnostic explanation
   values before their respective fixes.

Exploit/escalation/pivot/session/web/cloud examples are presentation fixtures only.
They do not establish real offensive execution. Real testing is limited to local
diagnostics and the existing test-owned loopback Nmap regression.

## Preservation audit

Fresh task snapshot matches README.md, redvector_server.py, redvector_mcp.py,
redvector_banner.py, start_redvector.sh, the execution-policy module and the Windows
Claude Desktop configuration. Existing scope/approval/rate/session controls remain
authoritative. No production usernames, target addresses, machine-specific model
paths or process IDs were introduced. Fixture targets and opt-in runtime configuration
are test-only. Git author and committer remain
0x7AK7 <339140058+0x7AK7@users.noreply.github.com>.

The original lab post-scan failure remains unproven; these presentation tests do not
retroactively establish its cause. Claude Desktop itself was not launched or tested.


## Final results

| Verification | Passed | Failed | Skipped | Subtests |
|---|---:|---:|---:|---:|
| Full Windows regressions | 354 | 0 | 24 | 116 |
| Native Kali core regressions | 375 | 0 | 1 | 123 |
| Real Kali model/MCP and Bash UI acceptance | 1 | 0 | 0 | 0 |
| Final native shared-renderer/report/recovery recheck (overlapping tests) | 11 | 0 | 0 | 0 |

Native core plus real acceptance are disjoint: **376 passed, 0 failed, 1 skipped**.
The final 11-test recheck is not added to that unique count. It covers the final
one-line scan dispatch through the shared result renderer after the core run started.
Windows skips are platform/opt-in tests, including the dedicated native acceptance.
Kali's one skipped test is Windows-specific ACL verification. The older long native
installer/capacity/model-selection UAT is excluded explicitly, not counted as passed.
It was already completed before this task; the new real Bash acceptance exercises
the modified result/UI path and existing navigation.

Actual final outputs:

    Windows: 354 passed, 24 skipped, 116 subtests passed in 69.53s
    Kali core: 375 passed, 1 skipped, 123 subtests passed in 300.73s
    Kali real model + Bash UI: 1 passed in 266.04s
    Kali final rendering/recovery recheck: 11 passed in 4.23s

Real output markers:

    REAL UNIFIED HEALTH: 328 tools; server_health; healthy; version 8.0.0;
    saved evidence; real model verification.
    REAL BASH UI: model launch; red prompt; scope; formatted real health;
    saved results; blocked tool discovery; back and exit.
    REAL SCOPED NMAP PASS: explicit loopback scope, bounded automatic policy,
    native Nmap, real MCP/backend output, open owned TCP port, recovery disabled;
    328 tools.

Model used: the already installed qwen3:8b selected through the opt-in native test
environment. No pull command or new model installation was performed. The real
model generated the structured server_health call and processed actual saved
health evidence. The Bash launcher reused that model and exercised real diagnostics,
scope, stored results, disabled-tool discovery, return navigation and exit.
Existing model manifest hashes were asserted unchanged.

Final native commands are split to avoid executing the model/UI acceptance twice:
unified_kali_core.py excludes test_ollama_kali_uat.py and test_ollama_unified_live.py;
unified_kali_focused.py runs the latter alone; unified_kali_render_final.py runs
scan recovery/components/report tests only. All wrappers and actual argv records
remain ignored local validation artifacts.

Fresh protected hashes and Git branch/HEAD were checked again after tests.
No staging or Git mutation was performed. The original checkout was not modified.

## Complete working-tree delivery file list

This includes the preserved earlier scan/timeout work, not just this extension.

- redvector_ollama_agent.py
- redvector_ollama_cli.py
- redvector_ollama_errors.py
- redvector_ollama_policy.py
- redvector_ollama_setup.py
- tests/test_ollama_agent_responses.py
- tests/test_ollama_cli_dispatch.py
- tests/test_ollama_kali_uat.py
- tests/test_ollama_linux_bridge.py
- tests/test_ollama_nmap_live.py
- tests/test_ollama_policy.py
- tests/test_ollama_review.py
- tests/test_ollama_scope_extended.py
- docs/ollama-scan-workflow-validation.md
- docs/ollama-unified-presentation-validation.md
- docs/superpowers/plans/2026-10-26-scan-workflow.md
- docs/superpowers/plans/2026-10-26-unified-presentation.md
- redvector_ollama_analysis.py
- redvector_ollama_generic_analysis.py
- redvector_ollama_panels.py
- redvector_ollama_presentation.py
- redvector_ollama_private.py
- redvector_ollama_results.py
- redvector_ollama_views.py
- tests/conftest.py
- tests/test_ollama_automation.py
- tests/test_ollama_diagnostics.py
- tests/test_ollama_inference.py
- tests/test_ollama_result_commands.py
- tests/test_ollama_results.py
- tests/test_ollama_saved_offline.py
- tests/test_ollama_scan_recovery.py
- tests/test_ollama_unified_analysis.py
- tests/test_ollama_unified_components.py
- tests/test_ollama_unified_evidence.py
- tests/test_ollama_unified_format.py
- tests/test_ollama_unified_live.py
- tests/test_ollama_unified_pages.py
- tests/test_ollama_unified_presentation.py
- tests/test_ollama_unified_report.py

## Subsequent checkpoint authorization — 2026-10-26

The operator subsequently authorized a checkpoint commit and a normal push of only the existing development branch, without a PR or merge. The restrictions earlier in this report describe the implementation/validation phase. Fresh pre-commit checks: Windows 354 passed, 0 failed, 24 skipped (116 subtests); native presentation/recovery/security checks 93 passed, 0 failed (61 subtests). Earlier native full and real-model/Bash acceptance evidence is preserved. No models were downloaded. Protected-file hashes match the validated snapshot.

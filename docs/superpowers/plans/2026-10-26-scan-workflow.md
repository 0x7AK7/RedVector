# Secure scan workflow and summary recovery implementation plan

> Execute inline with test-driven development. The supplied detailed user spec
> authorizes implementation; operator chose <=1,000 ports for default automation.
> No commits, pushes, README changes, model downloads or backend changes.

Goal: preserve actual scan evidence independently of optional model availability,
automate only reviewed bounded discovery, and render professional terminal facts.

Architecture: keep the existing MCP/backend/authentication and central Policy.
Add evidence/parsing, presentation and optional-analysis modules; integrate them
in Agent and deterministic CLI commands. Avoid a general workflow rewrite.

Constraints: branch 0x7AK7/ollama-mcp-integration; keep all 328 registrations,
dynamic scope/DNS pinning and exact-argument approval for intensive operations.
Exploit/unreviewed/unconfined tools remain disabled, never enabled by scope.
The existing terminal banner and unrelated menus remain byte-identical.

Confirmed diagnosis from source: model errors currently escape after completed
MCP actions; results exist only in local turn variables/raw terminal JSON.
Tool replies duplicate structured and text data and trim raw JSON by character
count, not a model-token budget. Exceptions collapse timeout, HTTP/context and
protocol errors. The particular user's CPU timeout is not yet reproducible;
record API outcome/latency/context diagnostics without claiming Nmap failed.

Design decisions:
- Automatic profile: one explicitly scoped host, TCP connect only, <=1,000 unique
  ports (empty selection means Nmap's default 1,000), 60-second host limit,
  fixed scan delay/max rate/parallelism/retries, one in-flight scan, bounded
  unattended operations per session and cooldown. Larger/intensive reviewed
  connect scans require exact existing approval. No scripts/version probes.
- Scope and pinned destinations revalidate regardless of approval mode.
- Store original wire response and unknown fields in private application-managed
  JSON under a dynamically resolved result directory. Reject path traversal,
  symlink evidence files and unsafe existing directory ownership/permissions.
  If final persistence fails after execution, retain in-session data and report
  lack of durability; never rerun the scan automatically.
- Parse validated structured port rows first, validated stdout fallback second.
  Backend open_ports includes other states: count only state=open. No inferred
  closed totals or product versions. Unknown/partial/failed states remain visible.
- Sort and display every reported port with narrow-width wrapping, NO_COLOR,
  green OPEN, amber unknowns and red errors. Raw JSON is dedicated diagnostics.
- Expose /results [ID], /raw [ID], /export [ID] and /summary [ID] [PAGE].
  Analysis commands never go through the network-tool execution loop.
- Separate one completed assessment from summary generation; preserve results on
  timeout/error/cancellation, provide category-specific messages, no automatic
  retry. Evidence-only compact pages stay within conservative UTF-8 byte budget.
  Model returns factual status/port extraction checked against actual evidence;
  application renders English facts, never invented CVEs/versions/vulnerabilities.
- Configurable bounded CPU inference deadline/context/output settings, typed
  timeout/context/HTTP/protocol errors, safe request metrics, no infinite retry.
- Preserve legacy non-assessment tool flow and original MCP evidence contracts.

Tasks:
- [x] TDD evidence normalization/status, private retention/export and all-port parsing.
- [x] TDD structured renderer and bounded duplicate-free analysis pages.
- [x] TDD central automatic policy, limits, scope rechecks and manual high-risk gate.
- [x] TDD typed Ollama failures and configurable bounded inference settings.
- [x] TDD Agent save/render/optional-summary and cancellation/error transitions.
- [x] TDD operator commands; retry invokes only analysis, no network tools.
- [x] Update legacy manual-policy fixtures explicitly; full Windows/Kali suites.
- [x] Independent security/correctness review; actual test-owned loopback Nmap/MCP,
  installed-model analysis when available, injected summary timeout with no rescan.
- [x] Final report: source changes, actual causes/evidence, exact counts and limits.

Review focus:
- Successful MCP action followed by any AI failure must remain completed/saved.
- Conflicting structured/text evidence or partial stdout cannot become success.
- Filesystem failure must not misrepresent evidence as durable.
- Large/Unicode/untrusted service names must not corrupt terminal or context.
- Summary retry after scope/model changes must remain incapable of tool dispatch.


Implementation ledger:
- All main modules implemented. Policy, results, renderer, evidence-only analysis,
  typed API errors, offline saved-result flags and deterministic commands tested.
- Windows privacy review issues fixed with current-SID/owner/DACL verification;
  only new result directories receive private DACLs, existing unsafe ones reject.
- Saved-summary configuration/page exceptions now remain recoverable.
- Added conservative trusted automatic-intent flag; ambiguous/negative intent
  cannot enable unattended scanning, and polite analysis requests route to saved
  evidence before scan intent. Central policy remains authoritative.
- Managed JSON limit is 32 MiB; oversized/save-failed results remain in memory,
  are explicitly marked non-durable and can be exported without dropping fields.
- Original operator timeout cause cannot be proved from the supplied successful
  Nmap facts alone; no original API transaction/diagnostic was available. Confirmed
  source defects (generic failures, duplicate context, no retained results) fixed;
  typed numeric inference diagnostics now support future exact investigations.
- Full native acceptance will run actual installed qwen3:8b and owned loopback
  discovery only. API-timeout injection is explicitly a boundary fixture, not a
  claim that the real model timed out. No model downloads or external scans.
- Protected source snapshot: .ollama-test-env/scan-workflow-before.json.
- Final regression and acceptance evidence will use scan-workflow-final-* files
  under ignored docs/kali-uat; do not confuse early Windows failure logs with final.


Validation progress:
- Full native Bash/model/MCP/Nmap acceptance and regressions: 318 passed, 1
  Windows-only skip, 123 subtests, 855.55 seconds. Actual one-port scan returned
  OPEN, preserved evidence, successful model facts, then injected AI timeout
  without a second network action. Existing model store remained unchanged.
- Final Windows: 299 passed, 23 skipped, 116 subtests, 68.77 seconds.
- Added user-requested 31-port/20.16-second synthetic replay plus actual
  httpx.ReadTimeout cause/stage/timing redaction test. Both pass.
- One intermediate final non-UI Kali batch had 319 passed, 1 failed, 1 skipped:
  second MCP session initialization in legacy Linux bridge test closed.
  Original temporary log had been cleaned. No cause was assumed and no
  verification was bypassed. Added redacted, test-owned log retention.
- Isolated bridge + diagnostic replay: 3 passed in 68.30 seconds, same verified
  backend reused by both sessions, authentication enforced.
- Stable final non-UI batch now uses scan-workflow-accepted-kali evidence prefix
  and REDVECTOR_TEST_DIAGNOSTICS=1. Do not claim its result until summary arrives.


Final evidence:
- scan-workflow-accepted-windows: 299 passed, 23 skipped, zero failures;
  116 subtests, 68.77 seconds.
- scan-workflow-accepted-kali: 320 passed, one Windows-only skip, zero failures;
  123 subtests, 271.79 seconds (already passed interactive/model case omitted).
- Real UAT and original 318-test native batch remain successful, with no model
  download, no external target scan and one actual automatic Nmap request.
- Protected source/README snapshot matches. Claude file was only read; its hash
  differs from an older pre-task checkpoint, so historical byte equality is not
  asserted. No restoration/overwrite was performed.
- Report docs/ollama-scan-workflow-validation.md includes limits, exact changed
  files, confirmed/suspected causes and the intermediate initialization failure.

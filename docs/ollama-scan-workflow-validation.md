# Automatic discovery, saved results and Ollama recovery

This is an incremental client-only change on
0x7AK7/ollama-mcp-integration, based on checkpoint
96712368da8cd6cde6f218b717ef5c7b1e1a4d89.
No commit, push, merge, PR, README update, model download or external target scan
was performed. Existing backend/MCP implementations and banner remain unchanged.

## Confirmed causes and remaining uncertainty

The operator supplied a successful Nmap MCP result: 31 open TCP ports,
approximately 20.16 seconds, success true, return_code 0, isError false,
partial_results false and timed_out false, with local qwen3:8b. This confirms a
completed tool request followed by a failure in the optional model stage. It
does not establish which Ollama transport/model exception occurred.

The previous client confirms these defects:
- Every non-diagnostic operation reached the same approval callback regardless
  of reviewed low-impact eligibility.
- Agent.turn kept outcomes in a local variable and raised a generic error on
  any later model exception. There was no durable scan archive/retry boundary.
- Normal output printed the complete MCP JSON, including duplicate text and
  structured content, raw stdout and parsed findings.
- Model context was capped using character counts/JSON preview text, rather
  than a conservative context budget. Response allowance was 2,048 tokens and
  the chat deadline was a fixed 300 seconds.
- HTTP, context, protocol and timeout failures collapsed into generic SetupError;
  original exception messages were intentionally excluded from logs, but safe
  cause types, timeout stage and request timing were not retained.

Duplicate input can increase context pressure and CPU inference time.
The synthetic 31-port replay has 8,058 bytes of duplicated tool JSON versus
444 bytes of compact findings. These are measured byte sizes, not token counts.
This demonstrates the avoidable input expansion; it does not prove that the
original failure was context overflow or CPU timeout. No original API traceback
or verified diagnostic path was available, and the operator explicitly asked us
to proceed without assuming a cause.

Synthetic transport tests inject a real httpx.ReadTimeout at the HTTP boundary
and verify typed handling, safe chained cause logging and total deadline behavior.
They are fixtures, not a claim that the original lab error was reproduced on the
real model. A separate 31-port successful MCP fixture followed by a summary
timeout preserves all 31 rows, the original fields and exactly one tool action.

## Reviewed automatic profile

The operator chose up to 1,000 ports, with larger scans requiring approval.

Automatic execution requires a trusted explicit positive discovery request,
an active operator-authorized scope, one validated/pinned host, reviewed TCP
connect arguments and available session limits. Ambiguous/negative wording does
not confer unattended eligibility. Saved-analysis language is intercepted before
scan-intent handling, including polite requests to summarize previous findings.

The automatic profile uses:
- <=1,000 unique TCP ports; an empty selection means Nmap's default 1,000.
- -sT, derived -6 for IPv6, DNS disabled, host discovery skipped and unprivileged.
- --max-retries 1 --host-timeout 60s.
- --max-rate 50 --scan-delay 20ms --max-parallelism 8.
- One in-flight scan per agent session, at most five automatic dispatches per
  session and at least 30 seconds between automatic dispatch starts.
- Automatic recovery disabled. Scope, DNS pins and normalized parameters checked
  independently of the model and approval mode.

These are Nmap/application controls, not an OS-wide egress or packet-rate sandbox.
They do not govern other applications or separately launched operator sessions.
The [official Nmap timing controls](https://nmap.org/book/man-performance.html)
describe probe delay, parallelism and host timeouts.

Full-range/intensive reviewed connect scans, exhausted unattended limits and
state changes retain explicit exact-argument approval. Unreviewed exploitation,
privilege escalation, lateral movement, password guessing, scripts, free-form
commands and unconfined secondary destinations remain disabled; this change
does not enable them merely by adding an approval prompt.

An unknown/disconnected MCP execution is saved as UNKNOWN and blocks another
scan in that session for a conservative 90-second window. Cancelling a client
wait does not claim the backend action was stopped. AI failures never enter a
network retry loop.

## Evidence and terminal results

Original MCP wire fields available from the SDK, unknown extensions, normalized
MCP data, invocation and parsed facts are preserved in JSON. Dynamic default:
the existing application config directory's results child. REDVECTOR_RESULTS_DIR
can select an absolute operator-controlled location.

New POSIX directories/files use 0700/0600; unsafe existing ownership/permissions
or symlink evidence files are rejected. Windows checks the current dynamic SID,
owner and DACL; only new application result directories receive a protected DACL.
Existing unsafe directories are rejected without permission/ownership repair.
SYSTEM/Administrators are trusted privileged principals, analogous to root.
Files are created privately; exports use fresh exclusive filenames.

Managed documents are bounded to 32 MiB. If saving fails or a document exceeds
that bound, the complete result remains available in the current session, is
explicitly marked non-durable and can be exported before exit. It is never
silently truncated or represented as safely archived. No automatic deletion or
external-service export was introduced.

Validated structured port rows are primary; a strict Nmap stdout fallback is
available. Backend open_ports includes non-open rows, so only exact state=open
counts as confirmed OPEN. Numeric ports sort ascending; TCP/UDP remain explicit.
Closed totals use actual reported rows/aggregates and otherwise display Unknown.
Versions display Not verified unless explicitly identified by the source.

Every actual row remains visible with scrolling/wrapping. Wide tables align
columns; narrow terminals use wrapped per-port details. OPEN is green, unknowns
and warnings amber, actual errors red. NO_COLOR and redirected output stay plain.
Untrusted terminal controls are removed; non-ASCII display escapes remain in full
original evidence. Open ports are not classified as confirmed vulnerabilities,
CVEs, severity or exploitability.

Completed, partial, failed and unknown execution remain distinct. Backend
timed_out or host-timeout evidence cannot be reported as a completed scan.
Cancellation of analysis leaves the completed scan unchanged.

## Inspect and retry without scanning

Interactive commands:
- /results [ID] shows all parsed facts; /results list lists saved IDs.
- /raw [ID] shows the dedicated original MCP diagnostic response.
- /export [ID] creates a private complete JSON copy.
- /summary [ID|latest] [PAGE] analyzes saved findings only.

The same evidence is available without starting MCP or the backend:

    ./start_redvector_ollama.sh --results
    ./start_redvector_ollama.sh --raw RESULT_ID
    ./start_redvector_ollama.sh --export RESULT_ID
    ./start_redvector_ollama.sh --summary RESULT_ID --page 1

Viewing/exporting requires neither a running Ollama API nor a backend. Summary
requires only the selected existing local model/API. These entry points do not
run an installer, pull models, call network tools or change target scope.

Analysis receives bounded ASCII JSON pages with one canonical port list and no
raw stdout, duplicate parsed/structured content or tool schemas. All findings
remain in the rendered/archive views; analysis explicitly reports page coverage.
The model must return actual status/ports that match the page. Arbitrary prose,
extra fields, invented ports and attempted tool calls are rejected. The client
renders factual English from the verified extraction rather than presenting
unverified vulnerability claims.

## CPU inference and diagnostics

Runtime environment settings:
- REDVECTOR_OLLAMA_TIMEOUT: default 600 seconds, bounded 1..3600.
- REDVECTOR_OLLAMA_CONTEXT: default 4096, bounded 1024..32768.
- REDVECTOR_OLLAMA_PREDICT: default 512, bounded 64..min(2048, context/2).

No global Ollama service, model files or GPU architecture were changed.
Optional thinking is disabled only when the installed model explicitly supports
that API setting. Context and response allowances follow the
[official Ollama context configuration](https://docs.ollama.com/faq).

Errors distinguish connection, read/write/pool/total deadline, HTTP status,
model error, context overflow, invalid response and output-token exhaustion.
There is no infinite or automatic summary retry. Ctrl-C can cancel analysis;
the actual completed findings remain preserved.

Private agent-errors.log records operation stage, exception class, bounded
chained cause types/frame metadata, safe numeric request duration/size/limits
and known timeout stage. Exception messages/arguments, request bodies, model
findings, headers, credentials, source lines and locals are excluded. Tests
confirm that credential-like and private-finding sentinels never enter logs.

## Real native Kali acceptance

Installed qwen3:8b, without downloads, selected nmap_scan against a listener owned
by the test on loopback. The actual MCP/backend/Nmap response reported one OPEN
TCP port, unknown service, version Not verified, no reported errors and
approximately 0.13 seconds of backend execution. Closed count remained Unknown.

The normal terminal displayed the structured result, and the real model verified
1 of 1 reported open ports. Observed inference metrics: 440 serialized message
bytes, 103 prompt-evaluation tokens, 17 output tokens and 5.759 seconds; configured
context 4096 and output allowance 512. These measurements describe this actual
one-port test, not the original 31-port lab incident.

A subsequent explicitly injected AI timeout kept status COMPLETED, retained the
original evidence and left the actual MCP call count at one. No second scan was
executed. Actual and injected boundaries are recorded separately in ignored
docs/kali-uat/scan-workflow-native.json.

The full native batch passed real Bash installer/model selection, incompatible
rejection, unverified-download cancellation, restart, native health, automatic
loopback discovery, NO_COLOR, cancellation and unavailable-service behavior:
318 passed, 1 skipped, 123 subtests in 855.55 seconds. That batch preceded only
the final extra chained-diagnostic and color/timeout-row regression refinements.
The one skip is Windows-native DACL behavior.

Final post-refinement results:
- Windows: 299 passed, 0 failed, 23 skipped; 116 subtests; 68.77 seconds.
- Kali final regressions: 320 passed, 0 failed, 1 Windows-only skip; 123 subtests;
  271.79 seconds. This excludes only the already passed interactive/model UAT.
- Earlier full native UI/model batch: 318 passed, 0 failed, 1 Windows-only skip;
  123 subtests; 855.55 seconds. The later additional tests were diagnostic/format
  refinements, not another model download or external scan.
Counts describe separate runs and must not be added together. Windows skips are
native Linux/opt-in model tests plus Unix-only permission semantics; its native
Windows DACL test passed.

An intermediate final Kali batch had 319 passed, 1 failed, 1 skipped: the second
session in the existing Linux bridge-reuse test closed during initialization.
Its temporary child log had already been removed, so no cause was invented.
Redacted test-owned log retention was added, without changing identity checks.
Isolated reuse plus diagnostic tests then passed (3 tests, 68.30 seconds), and
the final full non-UI batch above passed. The one earlier initialization closure
did not reproduce; its underlying cause remains unverified.

Prepared-environment commands:

    rtk proxy .\.ollama-test-env\Scripts\python.exe .ollama-test-env/scan_workflow_final_kali.py
    rtk proxy .\.ollama-test-env\Scripts\python.exe .ollama-test-env/scan_workflow_accepted_windows.py
    rtk proxy .\.ollama-test-env\Scripts\python.exe .ollama-test-env/scan_workflow_accepted_kali.py

The last command omits only the already passed interactive/model acceptance case.
Raw command argv, exit statuses, stdout, actual API exchanges and transcripts
remain ignored under docs/kali-uat. Runtimes, models, logs and local configuration
are not delivery files.

## Review, preservation and limitations

Independent review found and resolved Windows DACL/owner checks and saved-analysis
configuration exceptions. Legacy approval tests now explicitly select manual
mode so their approval-race/DNS protections remain tested. New default-mode tests
exercise unattended eligibility and denial separately. No safety assertion was
dropped to accept the new behavior.

Protected source snapshots verify unchanged backend, all 328 MCP registrations,
MCP/backend reuse implementation, storage detection, model compatibility
modules, legacy launchers, terminal banner and README. Claude configuration is
only read/hash-checked; a live Claude Desktop session is not claimed.

Limitations:
- Original lab transport cause remains unverified; context/CPU pressure are
  possible contributors, not proven diagnoses.
- Real network validation is only against test-owned loopback. The operator's
  Metasploitable host was not rescanned, and no external/public scan or
  exploitation was run.
- The backend's caching semantics remain unchanged. A cached result is not
  proof of a fresh scan; original cache metadata is retained.
- Service versions, vulnerabilities and exploitability are not inferred from
  port-name mappings. AI analysis is intentionally limited to verifiable facts.
- Automatic limits are per agent session, not a replacement for an OS/network
  sandbox. Conservative language classification may still require manual
  approval for ambiguous or mixed instructions.
- Managed-save failures require an explicit export before exiting the session.
- Model loading/API operation, missing assessment binaries and administrative
  host controls remain subject to the existing installation environment.


## Final audit and exact files

All protected source/README hashes match the task-start snapshot. HEAD and Git
author/committer remain unchanged and configured as 0x7AK7. No files are staged.

Claude audit qualification: its current SHA256 differs from an older pre-task
checkpoint. This task did not capture a fresh starting Claude checksum and
contains no writes to that configuration; current content was left untouched.
Therefore byte equality to the historical snapshot is not claimed. No
configuration was restored, rewritten or reconfigured, and no live Desktop test
is claimed. The differing historical/current hashes are retained only in an
ignored audit artifact.

Exact uncommitted source, test and documentation files:
- docs/ollama-scan-workflow-validation.md
- docs/superpowers/plans/2026-10-26-scan-workflow.md
- redvector_ollama_analysis.py
- redvector_ollama_presentation.py
- redvector_ollama_private.py
- redvector_ollama_results.py
- tests/conftest.py
- tests/test_ollama_automation.py
- tests/test_ollama_diagnostics.py
- tests/test_ollama_inference.py
- tests/test_ollama_result_commands.py
- tests/test_ollama_results.py
- tests/test_ollama_saved_offline.py
- tests/test_ollama_scan_recovery.py
- redvector_ollama_agent.py
- redvector_ollama_cli.py
- redvector_ollama_errors.py
- redvector_ollama_policy.py
- redvector_ollama_setup.py
- tests/test_ollama_agent_responses.py
- tests/test_ollama_kali_uat.py
- tests/test_ollama_linux_bridge.py
- tests/test_ollama_nmap_live.py
- tests/test_ollama_policy.py
- tests/test_ollama_review.py
- tests/test_ollama_scope_extended.py

# Incremental CLI and model compatibility validation

This task resumes the interrupted implementation on the existing
0x7AK7/ollama-mcp-integration branch. No reset, stash, branch replacement,
commit, push or publication was performed. README.md was not edited:
its pre-task SHA256 remains
9eed2c6c8727730763e4f84919fea360442cd607f215bc1ea4ce545a978fd355.
It already contained changes from the preceding CLI task; those were preserved.

## Work already completed before resuming

The earlier report, docs/ollama-cli-scope-validation.md, records the red prompt,
deterministic built-ins, atomic operator-only scope, IP/CIDR parsing and hostname
pinning, approval enforcement, relevant discovery, actual result attribution and
incomplete-input handling. Previous final counts were Windows 231 passed,
22 skipped and Kali 252 passed with no skips (separate earlier native UI run
also passed). These are historical results, not added to the current totals.

The prior agent, policy, error handling and MCP source bytes match their
saved model-compatibility checkpoint. CLI dispatch, scope and rendering were
preserved; the later native test required the narrow scan-negation correction
described below. The prior optional Nmap recovery flag
retains its existing-client default; Ollama still disables recovery. No
previously disabled operation was enabled.

At interruption the model compatibility plan and tests existed, but the metadata
test ended midway through a statement and the two production model modules
were absent. Work resumed there; the completed CLI was not reimplemented.

## Implementation after resuming

redvector_ollama_models.py normalizes validated exact model identifiers and
classifies actual computed /api/show capabilities. A valid list containing
tools is Supported. A valid list without tools is Unsupported. Missing,
malformed, failed or incomplete evidence is Unverified. Names, coding labels,
presets and marketing badges never determine support.

For an uninstalled model the installer also reads official exact-tag registry
metadata. It requests only a bounded manifest and a known small JSON config
descriptor, with a 64 KiB limit per response, HTTPS to the fixed official host,
no proxy environment or redirects, descriptor size/digest checks and fixed
timeouts. It never fetches model or template layers. The manifest supplies an
estimated download size when valid. Registry failure does not invent size or
capabilities.

Important registry limitation: config capabilities are not exhaustive. Ollama
also computes capabilities from GGUF metadata, templates, parsers and model
families. Config omissions are not proof of incompatibility, and config
declarations alone do not override that computation. Registry-only evidence
therefore remains Unverified in this implementation.
See the [official capability implementation](https://github.com/ollama/ollama/blob/v0.40.11/server/images.go)
and [official show route](https://github.com/ollama/ollama/blob/v0.40.11/server/routes.go).
There is no model-name allowlist or mandatory model.

The existing selection menu and three recommended presets remain. Selection
shows model, Supported/Unsupported/Unverified, whether download is required,
known size and evidence source before any pull. Confirmed Unsupported choices
offer another model, Back or Exit without a download. Unverified downloads
require the exact phrase DOWNLOAD UNVERIFIED, followed by all existing storage
capacity and download confirmations. Cancellation preserves the prior selection.
Installed models are reused and are never deleted.

redvector_ollama_model_check.py performs post-selection verification before the
selection is saved. It verifies exact installed tag/digest and computed tools,
uses the existing authenticated/process-verified MCP bridge and existing policy,
exposes only server_health, accepts exactly one empty-argument native call,
executes the actual registered tool, and sends the unchanged actual MCP result
back to the model. FastMCP's single-result structured envelope is unwrapped only
for local comparison with the text response.

The final model response must extract exactly the actual status/version as JSON.
Extra fields, incorrect values, prose, empty output and extra tool calls fail.
A fixed English summary is rendered from the verified extracted fields through
the existing terminal sanitizer. This avoids accepting contradictory prose or
printing model-supplied terminal controls. Tag/digest and capabilities are checked
again after the round trip. The existing runtime native-tool gate remains active.
Failure offers recovery without accepting a new model, deleting files, switching
silently, retrying an operation or running a scan.

## Test boundaries and current evidence

Unit tests replace external registry/API/MCP boundaries explicitly. They exercise
custom identifiers and variants, installed S/U/unknown, computed metadata for
uninstalled choices, registry omissions, offline/redirect/oversized/invalid
metadata, integrity failures, exact consent, cancellation, insufficient-storage
handoff, recovery and no unintended pulls/deletes. Mocked compatible/uninstalled
cases do not claim a publicly available computed registry capability endpoint.

The full suites retain scope/DNS/approval/argument checks, relevance, ANSI and
NO_COLOR, backend authentication/reuse, all registrations and actual harmless
MCP diagnostics. Public target parsing uses fixtures; no external public target
is scanned. The native connect-scan fixture uses a test-owned loopback listener.

Independent read-only review found two issues in the initial new verifier:
raw terminal text and keyword-based prose acceptance. Both were fixed with
regressions and reviewed again. Native testing also exposed the actual FastMCP
structured result envelope; its regression now uses that wire shape. An existing
failure-verification test was updated to exercise the newly required Back menu
rather than expecting an exception to escape.

Windows final full-suite command:

    rtk proxy .\.ollama-test-env\Scripts\python.exe .ollama-test-env/model_compatibility_windows.py

Actual output:

    REAL SMOKE: initialized MCP; 328 tools; actual backend health and cache output; authentication enforced.
    260 passed, 22 skipped, 116 subtests passed in 52.93s

The 22 Windows skips are platform-specific native Linux tests and opt-in
model-driven tests. They are not counted as passes.

Native Kali final command:

    rtk proxy .\.ollama-test-env\Scripts\python.exe .ollama-test-env/model_compatibility_accepted_kali.py

The runner invokes the prepared native Python with REDVECTOR_RUN_SMOKE=1,
REDVECTOR_RUN_KALI_UAT=1 and the already installed model store supplied externally.
Actual final output:

    LIVE E2E PASS: Ollama -> structured call -> MCP -> actual backend -> model summary.
    KALI UAT PASS: real Bash installer/launcher, existing model store unchanged, 328 tools.
    REAL LINUX BRIDGE PASS: verified ownership, actual health, same backend reused, authentication enforced.
    REAL SCOPED NMAP PASS: owned loopback port, explicit scope/approval, native output, recovery disabled.
    REAL SMOKE: initialized MCP; 328 tools; actual health/cache output; authentication enforced.
    282 passed, 123 subtests passed in 700.85s (0:11:40)

Final failures: zero on both platforms. Final skips: 22 Windows, zero Kali.
Counts are separate runs and must not be added together. The authoritative native
files are model-compatibility-accepted-kali-command.json and
model-compatibility-accepted-kali-tests.txt. Earlier similarly named native files
retain intermediate failed runs and are not final acceptance results.

Complete commands, raw stdout, model exchanges and terminal transcripts remain
in the ignored docs/kali-uat directory. Test runtimes, service/model paths,
process IDs, logs and local environments are not delivery files.

## Preserved components and limits

Checksum verification confirms the backend, original launchers, banner, Claude
installation/configuration files and protected branch refs unchanged.
All 328 MCP registration names and their order match HEAD. The prior optional
MCP Nmap parameter is unchanged in this resumed task. A configured live Claude
Desktop session is not claimed; its existing configuration was only read and
hash-checked.

Real official registry metadata lookup from the Windows environment was
unavailable and correctly returned Unverified with unknown size. No weights
were downloaded to resolve that uncertainty. Actual uninstalled-model native
tool capability cannot universally be proven from the public config metadata.
The operator may cancel or explicitly approve an unverified download later;
post-install verification still must pass. No such download is approved or
performed during this validation.

Scope checks do not provide an OS egress sandbox. Unreviewed execution, active
version detection/NSE, arbitrary shell execution and WHOIS referral execution
remain disabled. Existing backend caching behavior is preserved.

## Exact working-tree files

Resumed implementation files: redvector_ollama_setup.py; the narrow
redvector_ollama_cli.py negation fix; tests/test_ollama_agent_responses.py; new
redvector_ollama_models.py and redvector_ollama_model_check.py;
tests/test_ollama_model_metadata.py, tests/test_ollama_model_check.py,
tests/test_ollama_model_selection.py; existing tests/test_ollama_setup.py,
tests/test_ollama_storage.py, tests/test_ollama_edges.py and
tests/test_ollama_kali_uat.py; the model compatibility plan and this report.

The complete uncommitted file list (including preserved earlier CLI work) is:

- docs/ollama-cli-scope-validation.md
- docs/ollama-model-compatibility-validation.md
- docs/superpowers/plans/2026-10-26-cli-scope-agent.md
- docs/superpowers/plans/2026-10-26-model-compatibility.md
- redvector_ollama_cli.py
- redvector_ollama_errors.py
- redvector_ollama_model_check.py
- redvector_ollama_models.py
- tests/test_ollama_agent_responses.py
- tests/test_ollama_cli_dispatch.py
- tests/test_ollama_model_check.py
- tests/test_ollama_model_metadata.py
- tests/test_ollama_model_selection.py
- tests/test_ollama_nmap_live.py
- tests/test_ollama_nmap_recovery.py
- tests/test_ollama_scope_extended.py
- README.md
- redvector_mcp.py
- redvector_ollama_agent.py
- redvector_ollama_policy.py
- redvector_ollama_setup.py
- tests/test_ollama_edges.py
- tests/test_ollama_kali_uat.py
- tests/test_ollama_linux_bridge.py
- tests/test_ollama_policy.py
- tests/test_ollama_review.py
- tests/test_ollama_runtime.py
- tests/test_ollama_schema_view.py
- tests/test_ollama_setup.py
- tests/test_ollama_storage.py
- tests/test_ollama_validation_cleanup.py


The native backend diagnostic reports that gobuster, dirb, hydra, john and
hashcat are absent from this test environment. Their MCP registrations are
preserved, but successful execution of all registered assessment tools is not
claimed and no missing tools were installed automatically.

The first native run ended with 274 passed and three failures in 843.21 seconds:
the old failure-recovery expectation, the installer acceptance at the actual
FastMCP envelope, and an old collected prose fixture against the newly tightened
JSON verifier. These intermediate failures prompted the corrections described
above. They are retained in model-compatibility-kali-tests.txt; final stable
validation uses a separate model-compatibility-final-kali-tests.txt.

During the final native run, the real Bash installer has already confirmed
Supported / no download for the installed qwen3:8b, completed the actual
server_health({}) round trip and displayed:
"Model response: Server status: healthy; version: 8.0.0."
The overall native suite subsequently passed: 282 tests, no failures or skips.


The first stable native batch after the envelope correction had 278 passed,
one failed, no skips, and 123 passing subtests in 682.68 seconds. Its remaining
failure was the real diagnostic prompt containing "Do not scan a target":
the earlier CLI intent heuristic treated that prohibition as a positive scan
request and returned a missing-scope clarification before contacting the model.

The narrow correction removes directly negated scan/nmap verbs (do not,
don't, never, with optional run/use/execute/perform) only when deciding whether
assessment intent exists. If positive intent remains, original text and all
existing scope/destination checks still apply. Negative-only input leaves the
assessment target unset; model attempts to invoke Nmap remain blocked by the
unchanged execution guard. No scope is granted or expanded by this processing.
Three regressions proved diagnostic routing, preserved positive-scan scope
gating, and absence of scan execution context for a negative-only request.
The failing tests were observed before the correction, then all 42 targeted
CLI/agent/scope tests passed. A read-only follow-up review found no authorization
regression. Mixed/ambiguous prose may still require clarification.

The subsequent native Bash user acceptance now passes, including compatibility
selection, explicit unknown-download cancellation, incompatible-model rejection,
reselection, restart, color/NO_COLOR, EOF, unavailable-service handling and a
real free-form Qwen diagnostic despite the explicit "Do not scan" instruction.
That model generated server_health({}), received the actual MCP/backend result
and answered: "The RedVector AI Tools API Server is operational and healthy,
running version 8.0.0."

A separate actual invocation of the new post-selection verifier used installed
qwen3:8b, advertised capabilities completion/tools/thinking, and discovered 328
tools. The exact unmodified MCP response was confirmed in the second model
request; the actual model response was:
{"status": "healthy", "version": "8.0.0"}
The native evidence and both exchanges are in ignored
docs/kali-uat/model-compatibility-native.json. The model store was unchanged.


## Final preservation checks

HEAD and branch remain unchanged; author and committer resolve to the required
0x7AK7 identity. Protected branch refs, backend source, legacy launchers, banner,
backend verification source, Claude installer/configuration bytes and README
match their saved checkpoints. The existing agent, policy, error handling and
MCP source also match the pre-model-compatibility checkpoint. Only the narrowly
documented CLI negation fix alters prior CLI source. The original checkout was
not written. No credentials, model weights, logs, environments or local machine
configuration appear in the delivery file list. No models were downloaded.
No commit, push, merge, PR, history rewrite or publication was performed.

No approval is needed for completed validation. A future download of an
unverified model would still require explicit operator consent. A live Claude
Desktop session and successful execution of unavailable assessment binaries
remain unverified as stated above.

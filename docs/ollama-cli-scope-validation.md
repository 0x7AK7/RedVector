# CLI, scope and MCP agent validation

Date: 2026-10-26. Branch: `0x7AK7/ollama-mcp-integration`.
Initial HEAD: `a9af807c3eed677534444d02bc4542019aa4fac4`.
No commit, push, merge, model download or operator-service changes in this task.
Final regression failures: **0**. No failed test was hidden or removed.

## Root causes

The old dispatcher matched only the exact /scope string and prompted for a
second line. /scope TARGET instead reached the model, which had no command
authority or trusted active-scope context. The new dispatcher handles commands
before model calls. /scope displays state; inline target arguments replace it.

The old response path prefixed even empty model content with a UI label and
saved that prefixed response in history. This could yield blank content and
repeat the label on later turns. Thinking-only and missing final text now
receive actionable application messages. UI wrappers are not model history.
Assessment success is based on actual MCP outcomes, not final model prose.

Discovery admitted description-only hits alongside direct tool-family matches.
Direct names now exclude loose description-only hits; shorter direct names
rank ahead of broader variants where match strength is equal. Specific Nmap
requests therefore expose the reviewed tool rather than unrelated CCTV tools.

## Commands and prompt

- /scope: show actual current policy state, canonical entries, DNS pins and source.
- /scope TARGET [TARGET...]: atomically replace the session-local scope.
- /scope --clear: clear authorization; diagnostics remain available.
- /tools QUERY: show registered matches and their execution-policy status.
- /status: actual read-only MCP server_health call.
- /help, /back and /exit: deterministic application commands.

Only insignificant outer whitespace is removed. Invalid scope leaves the old
scope, DNS pins and revision unchanged. Unknown slash commands never reach the
model. Scope updates clear conversation history; model text cannot update policy.

Only the prompt text redvector> is bright red, with reset before input. Plain
terminals, non-interactive input/output and NO_COLOR receive plain text. GNU
readline is given nonprinting escape markers for editing and wrapping. The
shared ASCII banner and response colors are unchanged.

## Authorization and destinations

Scope is an immutable policy snapshot with an atomic revision. It accepts
explicit private/public IPv4, IPv6, CIDR networks and exact plain DNS names.
No address family, interface or local subnet is automatically authorized.

CIDR host bits use strict=False normalization and the canonical result is
displayed with a warning when changed. Network scope grants membership; active
operations require a single host rather than automatic subnet fanout.

An explicitly authorized hostname pins every initial resolved unicast address.
DNS alone never creates scope: the operator must name the hostname first.
All fresh answers must match those pins before and after approval. The chosen
backend target is numeric; -n prevents backend re-resolution. Numeric targets
authorized only by hostname pins also revalidate the originating DNS set.
Explicit numeric IP/CIDR authorization needs no DNS lookup.

Default DNS lookup has a five-second wait and at most four outstanding daemon
workers. Timed-out workers retain their slot until completion. Late lookup
results cannot change policy state. URLs, wildcards, alternate numeric forms,
zone identifiers and non-unicast destinations are rejected.

Natural-language scans with one clear authorized host receive a trusted task
context. No scope, multiple ambiguous entries, network-only choices and incomplete
instructions produce clarification without a model call. A model cannot replace
the selected task host with a different globally scoped host.

## Nmap and other tools

All 328 MCP registrations remain. The existing nmap_scan handler gained only
an optional use_recovery=True parameter. Existing clients retain that default.
The Ollama policy always sends False, using the backend's already supported
non-recovery path. No backend implementation was duplicated or rewritten.

Reviewed assessment arguments allow one canonical numeric destination, strict
port numbers/ranges, -sT (derived -6 for IPv6), and the fixed flags:

```text
-n -Pn --unprivileged --max-retries 1 --host-timeout 60s
```

All arguments are checked against the real schema and the client policy.
Unexpected secondary destinations, proxies, files, free arguments, scripts and
recovery overrides are rejected. Exact normalized arguments require fresh
operator approval. Policy/DNS changes during approval block dispatch.

Active service-version detection is disabled because
[Nmap -sV automatically runs version-category NSE scripts](https://nmap.org/book/nse-vscan.html).
Scripts are not a destination-confinement mechanism. TCP scan service labels
are port-name mappings, not verified product versions.

WHOIS remains registered but agent execution is disabled with a registry/referral
confinement explanation. Other tools without reviewed policies remain disabled;
there is no arbitrary shell or alternate-tool fallback. Diagnostics remain
read-only; clear_cache retains separate operator approval.

## Responses and technical failures

Tool output is attributed to the real MCP response and returned to Ollama.
A diagnostic or discovery response cannot prove a scan happened. Assessment
final text is derived from actual Nmap outcomes, preventing invented ports or
versions from final model prose. Original tool output remains visible.

Policy denial and failed tool responses stay failures. A timed-out/disconnected
RPC reports unknown execution state because the backend might already have
started; it never claims nothing happened or retries automatically. Empty,
thinking-only or missing final text gets a concise actionable message.

Technical diagnostics use a private agent-errors.log with bounded traceback
frame metadata. Exception messages/arguments, source lines, locals, headers
and credentials are omitted. User-facing errors do not echo arbitrary exception
text. Existing API authentication, localhost restrictions and backend identity
checks remain active.

## Actual validation

Windows result: **231 passed, 0 failed, 22 skipped; 103 subtests passed in
58.20 seconds**. Linux/native and optional model-driven tests account for skips.

Full native Kali regression/UI result before the final language-edge additions:
**247 passed, 0 failed, 0 skipped; 108 subtests passed in 628.61 seconds**.
This includes the real Bash installer/launcher, installed qwen3:8b, red prompt,
scope display/replacement/invalid-state preservation, incomplete-command
clarification, restart, error handling and actual server_health output.

Final isolated Kali regressions after all parser/attribution and validation-helper fixes:
**252 passed, 0 failed, 0 skipped; 110 subtests passed in 269.66 seconds**.
That run excludes the already passed model-driven UI case. These are separate
runs; their counts must not be added together.
Separate installed-model Nmap acceptance: **PASS**. The actual qwen3:8b accepted
a polite natural-language scan request, generated nmap_scan, received approval
for only one owned loopback host/port, and received the actual native Nmap 7.99
open-port output through MCP. All 328 tools were discovered. Only one operation
was approved; no model download occurred and model manifests stayed unchanged.
The assessment summary shown by the application attributes actual MCP evidence
instead of printing unverified model findings.

Separate native PTY validation: **PASS** for 24-column wrapping, left-arrow and
backspace editing, exact resulting input, red-only prompt/reset and NO_COLOR.

The real native Nmap/MCP test has passed against an owned loopback listener,
confirming an actual open TCP port, per-operation approval, recovery disabled,
328 discovered tools and actual stdout decoded from the response sent back to
the model. That regression labels its model boundary double explicitly;
the separate model acceptance below uses actual qwen3:8b.

Prepared-environment verification commands:

```powershell
rtk proxy .\.ollama-test-env\Scripts\python.exe .ollama-test-env/cli_scope_delivery_windows.py
rtk proxy .\.ollama-test-env\Scripts\python.exe .ollama-test-env/cli_scope_kali.py
rtk proxy .\.ollama-test-env\Scripts\python.exe .ollama-test-env/cli_scope_delivery_kali.py
rtk proxy .\.ollama-test-env\Scripts\python.exe .ollama-test-env/real_cli_scan_runner.py
rtk proxy .\.ollama-test-env\Scripts\python.exe .ollama-test-env/cli_prompt_pty_runner.py
```

The Kali runner invokes the prepared Python with REDVECTOR_RUN_SMOKE=1,
REDVECTOR_RUN_KALI_UAT=1 and the existing model store supplied externally.
It runs python -m pytest -q -s, including the real Bash/native model acceptance.
Only installed models are reused; download confirmations are declined.

Exact argv, complete stdout and exit statuses are retained in ignored
docs/kali-uat/cli-scope-delivery-windows-{command.json,tests.txt},
cli-scope-kali-{command.json,tests.txt} (full UI run),
cli-scope-delivery-kali-{command.json,tests.txt} (authoritative final regression),
cli-scope-real-model-scan-{command.json,tests.txt} and
cli-scope-prompt-pty-{command.json,tests.txt}. Terminal
transcripts and real model exchanges also stay ignored; machine-specific
paths, model data, environments and logs are not delivery files.

Validation also exposed and fixed a false-positive hostname parse in the phrase
"Call nmap_scan exactly once", plus language variants and mixed blocked/real
results. Their regressions preserve the selected-task guard on every Nmap path.
An intermediate overlapping Kali batch failed a cleanup assertion because
another test owned a transient launcher and both batches shared a log.
No safety check was weakened. An independent later failure in the test-owned
cleanup helper exposed its use of cached/rounded psutil boot time. That test
helper now uses the existing kernel startup-time window while retaining the
script, port, fresh-process check and original identity token. A regression
proves fresh logged processes are captured and genuinely old ones excluded.
The final isolated run uses fresh log names; older overlapping/failed logs are
historical and not authoritative evidence.

## Changed files

Production: redvector_ollama_cli.py and redvector_ollama_errors.py (new);
redvector_ollama_agent.py; redvector_ollama_policy.py;
redvector_ollama_setup.py (prompt/input only); redvector_mcp.py (optional
Nmap recovery control, unchanged default).

New regressions: tests/test_ollama_cli_dispatch.py;
tests/test_ollama_agent_responses.py; tests/test_ollama_scope_extended.py;
tests/test_ollama_nmap_recovery.py; tests/test_ollama_nmap_live.py.

Existing regressions updated to test the new intended behavior while retaining
safety checks: tests/test_ollama_policy.py, tests/test_ollama_review.py,
tests/test_ollama_schema_view.py, tests/test_ollama_edges.py,
tests/test_ollama_runtime.py and tests/test_ollama_kali_uat.py.
Test-owned cleanup only: tests/test_ollama_linux_bridge.py and
tests/test_ollama_validation_cleanup.py (kernel-clock regression).

Documentation: README.md; this report;
docs/superpowers/plans/2026-10-26-cli-scope-agent.md.

## Limits and preserved behavior

Live scanning is restricted to test-owned loopback endpoints. Public/private
IPv4, IPv6, DNS changes, CIDRs and secondary-argument attacks use isolated
fixtures; real public scanning is not performed. The application does not
provide an OS/network egress sandbox: resolver traffic, kernel routing and a
compromised host require external controls.

Hostname scans choose one pinned address per operation. Internationalized names
must be supplied in their ASCII DNS form. Networks do not automatically launch
large scans. Active version detection, NSE, WHOIS referral execution and all
unreviewed tools remain unavailable. Backend caching is preserved; an actual
tool response is not automatically proof of a fresh uncached scan.

The backend, original launchers, banner, storage detection, verified backend
reuse, selected-model behavior and Claude configuration are preserved.
The default MCP Nmap call behavior is regression-tested; a live Claude Desktop
session is not claimed. No GPU architecture changes or model downloads occurred.

# Authorization scope and interactive help — validation, 2026-10-26

Branch: 0x7AK7/ollama-mcp-integration.
Base/checkpoint remains 0f79ac8baa73a631b9a0d9313f6a9cf28a03762d.
No commit, staging, push, merge, PR, README update, additional model download or
high-impact capability enablement was performed.

## Confirmed root cause and trace

The exact reported request was reproduced before editing. The secondary operand
regex treated the phrase "on them." as an explicit target operand, captured
"them.", removed punctuation, then rejected the unscoped hostname "them".
This happened in assessment_context before tool selection, Ollama or MCP execution.

At the same time, the Policy snapshot still contained the explicitly authorized
address, contains(address) returned True, and direct authorize(nmap_scan, ...)
accepted the exact target with the existing bounded profile. The failure was not
lost session state, backend authentication or an MCP scope mismatch.

The fix recognizes referential pronouns, canonicalizes explicit addresses through
the policy's existing target function and membership authority, preserves leading
IPv6 colons, and checks every explicit scan operand. Different spellings of a valid
IPv6 address converge on the same canonical target. CIDR scopes permit member-host
selection; an authorized network/subnet request still requires one explicit host
before execution. No network-wide operation is newly enabled.

The same trusted Policy instance remains session-local. Only /scope replaces its
atomic state. Agent target binding, schema validation, DNS pin rechecks, current
authorization checks and actual MCP dispatch remain authoritative. Tests cover
consecutive allowed requests separated by denied requests and help commands.

Requests for active service-version detection now distinguish authorization from
execution policy. After validating scope, the original request reports:
"Target is authorized. Execution policy restriction: active service-version
detection (-sV) and scripts are disabled in this MCP client."
No scan is silently substituted. A request for open TCP ports and service labels
continues through the unchanged bounded discovery policy. Labels are not verified
versions. Explicit exclusions such as "without -sV" do not request the disabled
action; a later positive -sV request still remains restricted.

Review-driven regressions cover ordinary prose labels ("ports:"), "scan only ports",
negated flags, multiple explicit destinations and authorized subnets. No unapproved
destination was used to reproduce the issue. The reported lab address appears only
in explicitly labelled test fixtures/input tests, never production defaults.

## Built-in help

One shared Command registry drives dispatcher routing, grouped help, detailed help,
search, typo suggestions and command-name completion. It contains only the ten
implemented commands:
 /scope, /status, /tools, /results, /summary, /raw, /export, /back, /exit, /help.

- /help: grouped commands plus authorization and execution restrictions.
- /help COMMAND or /help /COMMAND: usage, description, arguments, examples and limits.
- /help search TEXT: local command-help search; never tool discovery or inference.
- Unknown commands suggest nearby real command names and explain how to find help.
- Interactive startup includes "Type /help to view all commands".
- /exit retains its actual existing alias behavior: return to the startup menu.
- Natural-language assessment instructions remain separate from command dispatch.
- Help uses existing Panel/Terminal wrapping, headings, color and NO_COLOR behavior.

Optional Tab completion operates only for built-in command names and /help command
arguments in a real TTY. It does not complete target names or filesystem paths.
GNU readline's public symbols are obtained from the installed extension at runtime;
the existing Tab binding, completer and delimiters are restored after each prompt,
including input exceptions. Existing custom completers/bindings, macros, libedit,
unsupported platforms and redirected input are preserved rather than overridden.
Without supported completion, /help search remains available. No library dependency
or installation path was added.

API reference: [upstream GNU Readline manual in Debian source](https://sources.debian.org/src/readline/8.1-1/doc/readline.pdf/).
Native tests verify the actual binding is restored and actual PTY Tab input works.

## Final results

| Configured verification | Passed | Failed | Skipped | Subtests |
|---|---:|---:|---:|---:|
| Complete Windows suite | 398 | 0 | 27 | 116 |
| Native Kali regression suite | 422 | 0 | 1 | 123 |
| Earlier focused native PTY/completion check (overlaps final suite) | 7 | 0 | 0 | 0 |

Actual final output:

    Windows: 398 passed, 27 skipped, 116 subtests passed in 63.02s
    Kali: 422 passed, 1 skipped, 123 subtests passed in 284.87s

Windows skips are platform/opt-in cases, including real GNU-readline and native PTY
tests. Kali's single skipped test is Windows-specific ACL verification.

The native command explicitly excludes the older long installer/model acceptance
test_ollama_kali_uat.py and test_ollama_unified_live.py. These two optional scenarios
are not counted as passed or skipped here. The prior checkpoint's actual Qwen3 MCP
health/AI loop remains preserved; it was not repeated for this input/parser change.
The Ollama API class AST is identical to HEAD. New PTY tests exercise actual input,
commands and parsing, without simulating a scan result or claiming model execution.

Real native output additionally confirmed:
- Independent cross-checkout backend verification and reuse; authentication enforced.
- Actual launcher/MCP initialization and discovery of 328 registered tools.
- Real server_health output: healthy, version 8.0.0.
- Real Nmap only against a test-owned loopback listener, under existing fixed limits;
  no active version detection or recovery.
- Actual red prompt, Tab command/detail completion, /help/search, scope persistence,
  allowed/denied parsing, policy distinction, unknown-command suggestions, exit,
  and NO_COLOR under a Linux PTY. The input-only PTY scenario executes no tool.

Fresh full-suite commands:

    rtk proxy .\.ollama-test-env\Scripts\python.exe .ollama-test-env/scope_help_final_windows.py
    rtk proxy .\.ollama-test-env\Scripts\python.exe .ollama-test-env/scope_help_final_kali.py

The first wrapper runs python -m pytest -q -s with the established smoke-test opt-in.
The second runs native Kali Python 3.13 with the same suite and the two explicit
exclusions, enabling REDVECTOR_RUN_SCOPE_HELP_UAT=1 and REDVECTOR_RUN_SMOKE=1.
Exact command arrays and stdout remain in ignored docs/kali-uat/scope-help-final-*
artifacts, preserving earlier validation evidence. No logs or machine configuration
are included among the changed delivery files.

Failure history:
- Red/green tests reproduced the reported bug and additional extraction/help gaps
  before their fixes. No failure remains in the configured final suites.
- A reviewer ran a focused case under the unprovisioned PATH Python. The
  test_session_scope_persists_across_denial_help_and_multiple_requests integration
  case failed because that interpreter lacks jsonschema and mcp. The case passes
  in the configured environment (fresh isolated rerun: 1 passed in 0.62s).
  This diagnostic environment failure is separate from the final suite counts.
- A test collection error used pytest's reserved parameter name request initially;
  the fixture name was corrected before implementation.

## Preservation and qualifications

Verified unchanged from the task snapshot:
README.md, redvector_server.py, redvector_mcp.py, redvector_banner.py,
redvector_ollama_policy.py, start_redvector.sh and redvector_ollama_results.py.
Tool selection and the entire Ollama API class are unchanged. Existing serialized
evidence formats and saved results code remain unchanged.

The reviewed allowlist, authorized-host checks, DNS pin validation, 1,000-port
automatic ceiling, fixed rate/parallelism/delay/retry limits, per-session limits,
and approval requirements remain unchanged. Help cannot grant permissions.
No exploitation, credential attack, escalation, pivot or lateral movement was run.

Claude Desktop configuration qualification: a fresh initial hash was captured
read-only. Its hash changed during verification; the file's observed modification
time was 2026-10-26 18:25:17 UTC, after the initial snapshot. No task code writes that
configuration, and existing configuration-writer tests explicitly target temporary
files. The responsible process was not established. The actual configuration was
left untouched; no restore or overwrite was attempted. Byte-for-byte preservation
of that external file therefore cannot be claimed. Claude Desktop itself was not
launched or validated in this task.

Natural-language parsing is deliberately conservative rather than a general-purpose
language parser. Ambiguous or unsupported requests may need clarification. Active
version detection and subnet execution remain restricted. Completion is available
only when the existing GNU editing state can be safely restored.

## Exact changed files

Production:
- redvector_ollama_agent.py — startup help hint only.
- redvector_ollama_cli.py — registry routing, canonical target extraction and policy clarification.
- redvector_ollama_setup.py — optional reversible completion around interactive input only.
- redvector_ollama_help.py — shared command registry, help/search/suggestions/completion candidates.
- redvector_ollama_completion.py — guarded reversible GNU readline integration.

Tests:
- tests/test_ollama_scope_regression.py
- tests/test_ollama_interactive_help.py
- tests/test_ollama_completion.py
- tests/test_ollama_help_native.py

Documentation:
- docs/superpowers/plans/2026-10-26-scope-help.md
- docs/ollama-scope-help-validation.md

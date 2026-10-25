# Verified Ollama integration checkpoint

The integration adds English Bash installer and launcher entry points,
separate Ollama setup, model selection, a real MCP client, execution policy,
dependency checks and regression tests. It reuses the existing backend and all
328 MCP registrations. The original launcher, banner, backend, Claude Desktop
integration and website source are preserved.

The real native Kali acceptance workflow uses an existing qwen3:8b model.
It covers installer menus, model selection, invalid input, unsupported-model
recovery, restart, reconnecting to the same backend/service, plain terminal
output, cancellation, service failure, declined installation and clean exit.
Qwen3 generates server_health({}); the actual MCP/backend result is
healthy / 8.0.0; that result returns to the model for its correct summary.
No model download is performed by acceptance testing.

## Verification

Final complete-suite results on the checkpoint implementation:

| Environment | Actual result |
| --- | --- |
| Kali, real native terminal/model/MCP acceptance and real backend enabled | 106 passed, 58 subtests passed, no skips, in 500.58s |
| Windows, real backend/MCP smoke enabled | 100 passed, 6 Linux-only skips, 51 subtests passed, in 48.42s |

Both complete runs exited successfully with no failed tests. Native model
execution used the existing qwen3:8b weights and discovered 328 MCP tools.
Actual server_health({}) returned healthy / 8.0.0 and the model correctly
summarized that real result. No Windows live-model rerun is claimed here.

The default suite includes unit/boundary tests; an opt-in smoke test starts
an actual loopback backend and real MCP SDK session, checks authentication,
discovers all 328 schemas and executes harmless diagnostics.

    python -m pytest -q
    REDVECTOR_RUN_SMOKE=1 python -m pytest -q -s

The native PTY acceptance test additionally requires Linux, compliant Python
dependencies, the existing qwen3:8b model and the prepared isolated native
Ollama runtime in .ollama-linux-env/ollama-native/runtime. Set
REDVECTOR_UAT_MODELS to an existing model directory if it differs from
the current user's ~/.ollama/models. It never pulls weights:

    REDVECTOR_UAT_MODELS="$HOME/.ollama/models" REDVECTOR_RUN_SMOKE=1 REDVECTOR_RUN_KALI_UAT=1 python -m pytest -q -s

The 328 registrations do not guarantee that every external executable is
installed. The validation environment lacks gobuster, dirb, hydra, john and
hashcat. Those packages were not installed or changed. No exploitation,
privilege escalation, lateral movement or external-target scan was performed.
Fresh system-wide package installation was not repeated.

## Scope and security

The new agent defaults to diagnostics and empty target scope. Reviewed
assessment operations require exact human-authorized targets and separate
operator approval; arbitrary command arguments and unreviewed execution
remain blocked in this client. The existing clients retain their original
tool access. Ollama and backend defaults remain local; backend authentication
is inherited, not saved into model configuration.

The CRLF compatibility adapter preserves the existing launcher and runs a
private temporary LF copy where needed. Only the two new Bash entry points
are pinned to LF with Git attributes. The legacy Linux test fixture uses
canonical LF; Windows-managed CRLF has separate executable coverage.
The legacy SDK fixture restores only its own stubbed module keys.

Native validation also corrected a direct-script exception identity mismatch,
slow cold-model inference deadlines and tool-discovery ranking. Dedicated
regressions and real terminal execution cover these cases.

## Claude Desktop

The inspected Windows profile has no MCP entry; the Kali profile has no
Claude configuration file. The Windows file's modification predates this
integration work, and the earlier project report lists manual registration
as outstanding. No configuration was edited or auto-registered.
Source/compatibility preservation is verified; a live Claude Desktop
connection remains unverified.

## Commit hygiene

Only portable source, dependency declarations, tests, documentation and
narrow Git hygiene settings belong to this checkpoint. Local validation
environments, raw logs, terminal captures, machine-specific reports, resource
snapshots, tokens, model weights and runtime configuration are excluded and
retained locally where applicable. Raw evidence is intentionally not part
of the Git checkpoint.

The checkpoint is local to 0x7AK7/ollama-mcp-integration.
No push, merge, Pull Request, publication or protected-branch change is
authorized or performed by this checkpoint operation.

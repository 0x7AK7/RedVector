# Verified backend reuse across RedVector installations

Branch: `0x7AK7/ollama-mcp-integration`. Validation date: 2026-10-26.
No commit, push, merge, model download or operator-process changes in this task.

## Root cause and scope

The shared launcher compared the listener's executed script to exactly
this checkout's redvector_server.py pathname. It refused a valid RedVector
backend in another checkout before MCP initialization, regardless of health.

The Ollama bridge now uses an independently verified compatible-backend check
in its existing transient Bash adapter. The original start_redvector.sh,
redvector_backend_check.py, backend, MCP registrations, banner, Claude
installers/configuration and authorization policy remain unchanged. Original
Claude/standalone launcher behavior therefore remains as before.

## Reuse evidence and failure behavior

The verifier:

1. Reads kernel TCP listener ownership for the configured IPv4 loopback endpoint.
   Unknown owners, shared/ambiguous listeners and wildcard/public binding fail.
   A bind probe distinguishes an actually free endpoint from hidden occupation.
2. Reads the owner's actual Python executable, command line, working directory
   and creation time. The executable must match the running interpreter or a
   root-owned, protected executable chain. Command-line/interpreter mismatch,
   Python -c/-m, a different script, unreadable identity or different mount,
   root or network namespaces fail.
3. Requires the canonical backend script directory to equal the process working
   directory. Candidate script and banner paths must contain no symlinks. This
   conservative launch-layout requirement prevents source substitution through
   retargeted links or renamed directories. Other layouts are unverified and
   receive an explicit diagnostic rather than automatic reconfiguration.
4. Compares the backend and locally imported banner to the current trusted
   checkout's contents, normalizing only CRLF/LF. It checks bounded regular
   files, file metadata stability during reads and timestamps against the kernel
   startup time window. A different source revision requires review even if it
   reports API version 8.0.0. No other checkout's Python is imported/executed
   during verification.
5. Only after process/source evidence succeeds, checks healthy API version
   8.0.0, rejection of an unauthenticated protected GET, and acceptance of the
   explicitly configured API token on that same read-only route. HTTP proxies
   and redirects are disabled. Tokens are not read from the existing process,
   printed, persisted, overwritten or inferred.
6. Rechecks listener, process and source evidence after HTTP and again after
   MCP initialization/discovery. A replaced/disappeared backend fails and asks
   for an explicit retry. A private child-environment PID/start-time pin prevents
   the Bash launcher from starting a replacement if a pre-existing backend
   disappears between the preflight and its own check.

When the endpoint is free, normal launcher startup remains available. No
existing process is stopped, restarted, replaced, reconfigured or moved to a
different port. Refusals name the failing identity/source/version/authentication
check in the terminal. Legacy launcher details remain in the private MCP log.

This is conservative local evidence under the existing trusted checkout/OS
boundary, not cryptographic attestation of running Python memory or third-party
packages. Kernel start time has one scheduler-tick resolution (commonly about
10 ms); timestamp evidence cannot distinguish writes inside that start tick.
Wall time is sampled before the boot clock so scheduling delays cannot widen
the accepted window. Source timestamps alone are never treated as identity.

## Automated and real validation

The new unit coverage exercises same/other checkout paths, spaces in paths,
equivalent CRLF/LF copies, different backend/banner contents, command injection
through -c, missing process permissions, public binding, unknown owners,
namespace mismatch, changed sources, restarted process identities, hidden
occupied endpoints, API versions, missing authentication, invalid tokens,
symlink substitution, renamed directories and clock-sampling delay.

The real Kali test creates its own separate installation containing the
unchanged backend/banner/MCP files, on an independently selected free loopback
port with a fresh test token. It demonstrates the original strict checker
refusing that installation, then verifies:

- Compatible cross-checkout reuse with the same PID retained.
- Incorrect token rejected without changing the backend.
- Two actual MCP initializations and discovery of all 328 tools.
- Actual server_health({}) through MCP, returning healthy and version 8.0.0.
- Both bridge sessions exit while the reused backend remains running.

Only the test's own child is stopped in cleanup. The operator's pre-existing
backend is never signalled. A read-only inventory found no listener on the
configured default endpoint in the available Kali environment; consequently
the specifically reported external checkout/PID was not directly validated.
No diagnostic example PID, developer path or account is used by production code.

Final regression results (both subprocesses exited 0):

- Windows: **190 passed, 0 failed, 21 skipped; 59 subtests passed in
  50.68 seconds**. Skips are Linux/native and optional model-driven cases.
- Kali: **210 passed, 0 failed, 0 skipped; 66 subtests passed in
  216.92 seconds**. Real cross-checkout, normal Linux bridge and real
  backend/MCP smoke messages all confirmed success.

Protected-file checkpoint hashes, unchanged Claude configuration, branch,
identity and HEAD were verified after implementation. No source, policy,
launcher or backend file outside the listed scope was changed.

Commands use the prepared local test environments from the checkout:

```powershell
$env:REDVECTOR_RUN_SMOKE = "1"
$env:REDVECTOR_LIVE_MODEL = ""
python -m pytest -q -s
```

```bash
export PYTHONPATH="$PWD/.ollama-linux-env/backend-site:$PWD/.ollama-linux-env/site"
unset REDVECTOR_LIVE_MODEL
REDVECTOR_RUN_SMOKE=1 REDVECTOR_RUN_KALI_UAT=1 \
  .ollama-linux-env/bin/python3.13 -m pytest -q -s \
  --ignore=tests/test_ollama_kali_uat.py
```

The existing model-driven interactive installer acceptance is excluded from
this final Kali run because this change affects backend identity, not model
selection or inference. The real cross-checkout MCP and normal Linux bridge
smokes execute in this run. No model download is needed or performed.

Exact subprocess arguments, exit codes and complete stdout are recorded under
ignored docs/kali-uat/backend-reuse-{windows,kali}-{command.json,tests.txt}.
These local evidence files and prepared environments are not delivery files.
Initial failures in the new tests were resolved: a too-broad readlink mock,
a missing MCP file in the copied test installation, and a genuine startup-time
precision issue caused by whole-second Linux boot-time conversion. Review
also added regressions for symlink/renamed-directory substitution and clock
sampling order; no safety tests were deleted.

## Files and operational limits

Production: new redvector_ollama_backend.py; redvector_ollama_agent.py adapter
and pre/post-initialization proof checks.

Tests: new tests/test_ollama_backend.py and tests/test_ollama_backend_live.py;
tests/test_ollama_launcher_compatibility.py now executes the Ollama-specific
checker in the real Bash adapter fixture.

Documentation: README.md, this report, and
docs/superpowers/plans/2026-10-26-compatible-backend-reuse.md.

Linux proc metadata is required. Other-user services are supported only when
their identity metadata is readable; restricted ownership fails closed.
Equivalent audited source is supported across checkouts; independently patched
or older different code is intentionally unverified. Symlink source layouts,
alternate working directories, hidden namespaces and unrelated Python runtimes
without a verifiable executable chain are explicitly rejected. Individual
Debian/Ubuntu installations and the operator's external backend were not
tested live. Existing Claude configuration is preserved; a working Claude
Desktop session is not claimed by these MCP tests.

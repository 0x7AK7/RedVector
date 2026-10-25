# Portable Ollama storage capacity validation

Validated on 2026-10-25 on branch `0x7AK7/ollama-mcp-integration`.
No commit, push, merge, publication or model download was performed.

## Root cause and correction

The previous download preflight coupled filesystem capacity to directory access
checks. A running Ollama service could own private model storage that the
installer user could not read, even when metadata-only filesystem measurement
was possible. That was a production compatibility defect.

Capacity measurement now runs separately from file-access/ACL diagnostics.
On Linux it opens directory metadata with O_PATH and uses fstat/fstatvfs without
listing model files or changing permissions. A private leaf can therefore be
measured if its path can be traversed. Denied traversal remains unknown; the
installer never substitutes an accessible root filesystem for hidden storage.

## Discovery and filesystem proof

- Discover the actual executing UID and account/home through operating-system
  information. An unresolved account name remains a valid numeric UID. Do not
  construct a home directory from a guessed username.
- Verify API connectivity, associate a concrete loopback endpoint with the
  running Ollama process, and pin its start time, executable, UID and relevant
  namespaces. Verify listener ownership using process socket descriptors and
  network tables, including IPv4, IPv6 and mapped IPv4 addresses. Ambiguous
  listeners or restricted information produce uncertainty.
- Inspect effective process environment, discovered systemd service properties,
  drop-ins and readable environment files. Support custom system/user units
  and manually started servers. Actual runtime OLLAMA_MODELS and HOME take
  precedence over the installer shell's environment.
- A verified runtime path uses Ollama's path-cleaning semantics. Separately
  resolve blobs, manifests and manifests-v2 because any may be a symlink,
  mount or different volume. These layouts are present in the official
  [Ollama v0.40.11 path implementation](https://github.com/ollama/ollama/blob/v0.40.11/manifest/paths.go).
- Pin filesystem/device/mount identity through the opened descriptor. Resolve
  symlinks component by component. An ancestor is usable only after proving
  the remaining path is missing; permission errors, loops and unresolved
  mounts do not permit ancestor substitution. Untriggered autofs remains
  unknown.
- A remote server never inherits client disk-space values. The existing agent
  still requires a local loopback API; supporting remote agent execution was
  outside this change.

An optional manual absolute path is requested only when automatic discovery
cannot determine a path. Supplied configuration is not represented as verified
server identity or a successful capacity measurement.

## Capacity, permissions and cancellation

The preflight shows the model, approximate download size, detected storage,
measured or unknown available space, filesystem status and tool-call status.
Manifest size is used when available; the blob budget adds 15 percent plus
1 GB operational margin. Each metadata layout reserves 16 MiB. Reservations
are added when layouts share a device. Confirmed insufficient space and
read-only filesystems stop the download and cannot be overridden.

Unknown capacity defaults to cancellation. When a verified server UID is
available, the operator may explicitly choose a limited read-only measurement
under that numeric UID. This uses a fixed isolated Python program and a
verified, root-owned executable chain; it does not run repository code with
elevation, change files or enter a different service namespace. Failure remains
visible and unknown. The installer never invokes this probe automatically or
asks for the entire installer to run with sudo.

If capacity cannot be verified, the operator must type the exact word
UNVERIFIED and separately accept the ordinary download confirmation before
Ollama may attempt a download. This consent cannot override a known negative
result. Normal cancellation returns to the menu without an installation retry
loop. Downloads continue to use Ollama's official API.

No ownership, ACL or permission repair is performed. Filesystem free-space
measurements are snapshots, not reservations or promises of successful writes.
Service/account/project quotas, thin-provisioning/backing-store limits and
other restrictions that cannot be measured reliably are explicitly unverified.

## Changed files

Production code:

- redvector_ollama_capacity.py (new): isolated metadata measurement, filesystem
  and endpoint proof, structured results and optional approved service-UID probe.
- redvector_ollama_storage.py: dynamic identity/service discovery and separation
  of capacity from directory permission diagnostics.
- redvector_ollama_setup.py: actual preflight summary, capacity decisions,
  cancellation and the requested English model menu.

Regression coverage:

- tests/test_ollama_capacity.py (new).
- tests/test_ollama_storage.py.
- tests/test_ollama_setup.py.
- tests/test_ollama_edges.py.
- tests/test_ollama_schema_view.py.
- tests/test_ollama_kali_uat.py.

Documentation:

- README.md.
- docs/ollama-storage-design.md.
- docs/ollama-capacity-validation.md (this report).
- docs/superpowers/plans/2026-10-25-service-storage-capacity.md.

## Commands and actual results

Windows, from the development checkout with its existing test interpreter:

```powershell
$env:REDVECTOR_RUN_SMOKE = "1"
$env:REDVECTOR_LIVE_MODEL = ""
.\.ollama-test-env\Scripts\python.exe -m pytest -q -s
```

Actual result: **169 passed, 0 failed, 19 skipped, 56 subtests passed in
50.77 seconds**. Skips cover Linux-only/native acceptance and optional live
execution that is enabled separately on Kali. Real Windows MCP/backend smoke
initialized MCP, discovered 328 tools and verified real responses and
authentication.

Final Kali regressions (prepared existing dependencies on PYTHONPATH):

```bash
export PYTHONPATH="$PWD/.ollama-linux-env/backend-site:$PWD/.ollama-linux-env/site"
unset REDVECTOR_LIVE_MODEL
REDVECTOR_RUN_SMOKE=1 REDVECTOR_RUN_KALI_UAT=1 \
  .ollama-linux-env/bin/python3.13 -m pytest -q -s \
  --ignore=tests/test_ollama_kali_uat.py
```

Actual result: **187 passed, 0 failed, 0 skipped, 63 subtests passed in
149.57 seconds**. This rerun includes the final mapped-listener, bind-address
and failed-probe diagnostic regressions. Both the real Linux bridge and real
backend/MCP smoke passed with backend reuse and authentication enforced.

An earlier complete native Kali acceptance/regression run in this change used
the same interpreter and pytest command without the ignore option, with
REDVECTOR_RUN_KALI_UAT=1 and REDVECTOR_UAT_MODELS set externally to the operator's
existing model store. Actual result: **182 passed, 0 failed, 0 skipped,
58 subtests passed in 490.73 seconds**. The final address/diagnostic cases were
added afterward and exercised by the 187-test rerun. These are separate runs,
not an aggregate claim that one invocation executed every final test.

The local runners capture exact subprocess argv, exit status, environment
overrides and complete output under ignored docs/kali-uat evidence files:
capacity-delivery-windows-command.json, capacity-delivery-windows-tests.txt,
capacity-delivery-kali-command.json, capacity-delivery-kali-tests.txt and
capacity-final-kali-command.json/capacity-final-kali-tests.txt. Machine paths
and raw runtime transcripts remain ignored rather than part of this delivery.

## Real Kali acceptance

The real English Bash installer and interactive terminal were exercised under
an ordinary non-root Kali user with native Ollama 0.40.11. The existing
qwen3:8b model was reused. No download/pull was invoked and the model manifest
inventory remained unchanged.

Verified live: actual local process/storage detection; endpoint ownership;
unprivileged capacity for blobs and both manifest layouts; actual preflight;
declined download confirmation; installed-model selection; capability check;
invalid-input recovery; MCP diagnostics; service/backend reuse; restart and
model persistence; unsupported-model handling; unavailable service; EOF,
NO_COLOR, exit and declined installation.

The actual conversation discovered **328 MCP tools**, generated the structured
call **server_health({})**, executed it through the existing MCP/backend, and
returned the actual **healthy, version 8.0.0** response to qwen3:8b. Its final
summary included:

> The RedVector AI Tools API Server is operational and healthy, running version 8.0.0.

Tool discovery does not mean every external security executable is installed
or operational. No exploitation, privilege escalation or lateral movement was
performed.

## Preservation and remaining limits

The existing backend, MCP registrations, authentication and approval policy,
Claude installers/configuration, legacy launchers and shared terminal banner
were preserved. Protected-file hashes and Claude configuration are checked
against the saved checkpoint. The current Claude Desktop configuration has
no registered MCP entry; a working Desktop session cannot be claimed from
that configuration. No entry was added or overwritten.

Representative alternate accounts, custom systemd units, environment files,
restricted proc access, symlinks/mount identities, quotas, unknown capacity,
read-only storage and insufficient space are covered by isolated fixtures.
The live acceptance is Kali/WSL, not independent live Debian and Ubuntu hosts
or every administrator's systemd configuration.

A real model download remains **unverified**, as the operator explicitly
required installed-model reuse only. The optional privileged service-UID
probe is tested through isolated boundaries but was not executed with live
sudo. Hidden namespaces, unmeasurable quotas and future storage layouts retain
honest uncertainty rather than an invented success status.

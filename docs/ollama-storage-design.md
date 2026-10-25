# Portable Ollama model storage

Scope: existing Ollama installer only, on the Ollama integration branch.
Use endpoint-associated live process metadata first, systemd effective service
configuration/account metadata second, and an explicit manual directory only
when those sources cannot safely establish the actual local model location.
Do not infer an existing service's storage from the caller's environment.

A process OLLAMA_MODELS override wins; otherwise use its HOME. For restricted
systemd metadata use the configured service user/account home and merged
Environment/EnvironmentFiles only when the service, endpoint, launch command,
configuration freshness and filesystem namespace are consistent. Reject
ambiguous ownership, unreadable overrides and unsupported configuration rather
than guessing. Relative process paths resolve against that process's working
directory; no shell expansion or evaluation occurs.

Preserve localhost-only HTTP/security controls. Remote endpoints and known
forwarders cannot use a local disk-space assertion. Service metadata is read
only; never invoke sudo, change ownership/permissions or create model files.
Measure the actual directory, or its nearest existing parent for a missing
directory, with permission/readonly errors surfaced before any pull. Show
the model directory and storage requirement. Official Ollama pull remains
the only download operation. Change preset one to Qwen3 8B / qwen3:8b / 5.2 GB /
Tool Calling; preserve other choices and native capability/probe checks.

Tests: live-process and systemd fixtures for standard/custom users, HOME and
OLLAMA_MODELS precedence, environment files, relative paths, restricted metadata,
stale config, namespaces, foreign listeners/remote endpoints, inaccessible
directories, insufficient storage and cancellation. Run full Windows/Kali
regressions plus real local process detection and harmless native acceptance.
No commit or push.

## Detection boundaries

Live listener/process metadata is authoritative. If that metadata is
restricted, the systemd fallback queries the conventional ollama.service unit
read-only, checks its launch command/user/endpoint and config freshness,
and interprets supported Environment and EnvironmentFiles assignments.
Custom service names with restricted process metadata, manager environment
inheritance, complex multiline environment syntax and private filesystem
mappings require manual verification instead of a guessed directory.

Preflight measures existing directories or the nearest existing parent for
a not-yet-created model directory. It checks read-only status and, when the
service identity is available, directory access using actual primary and
supplementary groups and Linux POSIX access ACLs. It never changes access.
Metadata restrictions and unusual/unverifiable access result in clear errors.

The default path follows Ollama's own implementation: its OLLAMA_MODELS
override, otherwise its HOME-based model directory.
[Official Ollama environment implementation](https://github.com/ollama/ollama/blob/main/envconfig/config.go).
Combined ACL access follows individual matching group entries under the mask.
[Linux ACL implementation](https://github.com/torvalds/linux/blob/master/fs/posix_acl.c).

## Validation results

- Final Windows complete suite: 138 passed, 6 Linux-only skips, 51 subtests,
  in 50.15 seconds; real backend/MCP smoke and authentication checks enabled.
- Kali complete native acceptance/regression run: 143 passed, 58 subtests,
  no skips, in 490.11 seconds; actual qwen3:8b, actual listener process storage
  detection, 328 discovered tools and real server_health -> healthy / 8.0.0 ->
  correct model summary.
- Final focused storage suite: 38 passed on Windows and 38 passed on Kali.
  The custom service Group override case was added after the full Kali run's
  collection and is included in those focused results and final Windows suite.
  Thus that Linux case is verified separately rather than claimed as part of
  the 143-case run.

Systemd standard/custom users, environment overrides/files, stale configuration,
mount isolation and access restrictions were validated with explicit read-only
OS-boundary fixtures. No systemd unit was created, modified or restarted for
these cases. The native process/storage path assertion used the actual daemon.
No fresh model download or installation/permission repair was performed.

Independent review found and regression tests reproduced multiline environment
parsing, mount mapping and group/ACL issues; the corrections were reviewed
with no remaining material findings. The Windows negative CLI entry fixture
was corrected to import psutil's real OS backend before its Linux guard override.
Earlier failed attempts remain local; no unresolved test failures remain.

Changed files: redvector_ollama_storage.py (new), redvector_ollama_setup.py,
README.md, tests/test_ollama_storage.py (new), tests/test_ollama_setup.py,
tests/test_ollama_kali_uat.py, tests/test_ollama_cli_errors.py and this document.
The backend, original launchers, tool registrations, banner and Claude
configuration bytes remained unchanged during validation. At that time HEAD
remained at the previous published checkpoint and the improvements were
uncommitted. Saving and publishing the changes are separate operator-authorized
steps; validation itself performs no commit, push, merge or publication.

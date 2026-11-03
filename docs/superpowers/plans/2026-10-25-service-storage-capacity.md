# Service-owned Ollama capacity implementation plan

> Use executing-plans and test-driven development inline. No commits or pushes.

Goal: fix private service-storage preflight without assuming installer file access,
root-filesystem placement, usernames or service ownership.

Architecture: keep endpoint-associated storage discovery, add a structured
metadata-only capacity layer for the actual blobs and manifests paths, and let
the existing wizard render verified/unknown results and explicit decisions.
Use Linux O_PATH + fstat/fstatvfs rather than directory listings or permission
repair. Prove missing tails before measuring a resolved existing parent.
Permission denial, unresolved symlinks, autofs or unknown namespace are unknown,
never a guessed root filesystem result. Quota status is independently labeled.
Optional operator-approved read-only service-UID probing must be isolated,
bounded and executable-chain verified; it never enters private namespaces or
changes files. Unknown capacity needs explicit consent or cancellation; known
insufficient/read-only results cannot be bypassed.

Constraints: branch 0x7AK7/ollama-mcp-integration, existing backend/tools/banner/
Claude/security untouched, English red terminal, no additional models; user
explicitly selected existing-model-only acceptance on this turn.

- [x] Reproduce private-file/capacity conflation and add descriptor/private path,
  symlink/bind/nested mount, missing-tail, readonly/autofs/quota-unknown tests.
- [x] Implement capacity result and safe direct/read-only service-user probes;
  keep file-access/ACL checks separate from capacity.
- [x] Improve current-user/numeric-UID handling and discover systemd unit from
  verified process cgroup where feasible, never assume a service account/home.
- [x] Add real API preflight summary, large-download confirmation, explicit
  unknown consent and cancellation that returns to menus without retry loops.
- [x] Preserve/update old tests according to their original safety intent;
  never discard access, insufficient-space, capability or cancellation coverage.
- [x] Independent review of mount/privilege/unknown-state boundaries.
- [x] Full Windows/Kali regressions and native no-download qwen3 MCP acceptance,
  including actual unprivileged capacity measurement and restart.
- [x] Report exact counts, sources, preservation and remaining limits. Real
  model download remains unverified because the user explicitly disallowed it.

Review focus: blobs child may be a distinct mount; O_PATH does not trigger
autofs; missing symlink targets must resolve before ancestor fallback; service
UID does not reproduce service mount namespace/quotas; hidden metadata must
never become a successful capacity check.

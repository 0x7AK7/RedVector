# Reviewed assessment profiles and useful availability
User authorized opt-in backend handlers in existing routes; preserve legacy behavior,
authentication, 328 MCP names/signatures, Claude configuration, model selection,
evidence and banner. No commit/push/README/model download.

Investigations proved stock -sV contains proxy/forwarding/stateful probes and implicit
version NSE. Nuclei's MCP path forces recovery; scanner dependencies are missing.
Client-only flags are insufficient. Native profile module provisions/hashes an
isolated reviewed runtime, tiny TCP banner/origin-form GET probe DB and a no-op
version NSE sentinel; limits 32 ports/intensity0-2, output/deadline/concurrency.
Legacy calls remain unchanged; marker begins invalid Nmap option so older backends
fail closed. Capability metadata is authenticated and checked against verified
backend/module identity. No automatic backend restart/reconfiguration.

Implement:
1. Backend-owned service-version profile + negative and real loopback tests.
2. Opt-in existing nmap route and authenticated capabilities route; MCP session-only
   health enrichment. Preserve all tool schemas and original client behavior.
3. Trusted client profile gating/target binding, optional previous-open-port reuse,
   exact additional approval reasons, no redundant basic discovery prompts.
4. Runtime-backed Ready/Requires Approval/Restricted/Missing Dependency/Unsupported
   listing without duplicate warnings; detailed exact tool lookup.
5. Provenance-bound saved-evidence offline reporting through existing MCP formatter,
   never accept model-invented findings. Keep unsafe/missing scanners restricted;
   include explicit Nuclei template/destination/recovery safeguards.
6. Client source-reported version/product/confidence parsing, preserve uncertain
   fingerprints and original wire evidence.
7. Reproducible all328 schema/source/dependency/behavior inventory and risk/safeguard
   report. Unknown transitive/dynamic routes explicitly unresolved, not auto-enabled.
8. Full Windows/native regression and real authenticated MCP, owned-loopback
   service-version and offline-report acceptance. No public/lab rescans.

Review focus: legacy compatibility, marker failure on older backends, runtime
integrity, unsafe probes/NSE, backend recovery, false readiness, exact approval
scope, output facts and stored evidence, model custom selection preserved.

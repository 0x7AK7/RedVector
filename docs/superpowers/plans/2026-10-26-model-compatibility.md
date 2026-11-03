# Incremental model compatibility implementation plan

> Use test-driven development inline; no commit/push/README edits or model downloads.
> Preserve the already verified CLI/scope/MCP changes at current working bytes.

Goal: check exact selected model capabilities before any download, separate
supported/unsupported/unverified, then require real harmless post-selection
model/MCP verification. Presets remain recommendations, not an allowlist.

Authoritative capability evidence: successful exact-model Ollama /api/show
with a valid computed capabilities array. Presence of tools supports native
tool calling; an exhaustive valid API list without tools means unsupported.
Missing/malformed evidence is unverified.

Official registry limitation: manifest/config/template omissions do not provide
an exhaustive negative result. Ollama computes capabilities from several
sources including GGUF metadata. Fetch only capped official exact-tag manifest
and small config metadata, never model layers, scripts or weights. Unknown
schema, redirects, offline or incomplete evidence stays unverified; registry
declarations do not override a computed API result. No name/family allowlist.

Architecture:
- New redvector_ollama_models.py holds immutable evidence, exact identifier
  normalization, bounded digest-checked registry observations and state decisions.
- Existing setup delegates registry size lookup to the same observation to avoid
  repeated manifest calls within one selection. Keep all storage checks.
- Selection displays compatibility/size/download-required/source first.
  Unsupported choices offer another/back/exit without pulling or saving them.
  Unverified downloads need explicit DOWNLOAD UNVERIFIED consent followed by
  the existing storage/large-download confirmation. Nothing is deleted.
- Post-selection verifies local API/tag identity, advertised tools, actual
  structured server_health call and real backend response returned to model.
  Failure keeps the prior selection and offers recovery; no silent fallback.
- Existing runtime verify_tools gate and security policies remain enforced.
  Verification never scans a network or enables unreviewed operations.

Files: new models evidence module and tests, setup selection/registry adapter,
agent harmless verification helper, existing selection/native UAT fixtures and
a separate final report. README is frozen, including its pre-existing changes.

- [x] Add failing model evidence/registry safety tests, implement metadata layer.
- [x] Add failing selection consent/recovery tests, integrate compatibility UI.
- [x] Add real harmless model/MCP round-trip verification and failure tests.
- [x] Update existing fixtures without weakening CLI/scope/policy assertions.
- [x] Independent review, full Windows/Kali regression and native installed-model
  acceptance, preserving no-download rule and protected component hashes.
- [x] Report exact counts, reliable/unknown evidence, actual results and limits.


Resume ledger (2026-10-26):
- Recovered branch/remote/HEAD/identity and inspected all modified/untracked files.
  README matches the pre-interruption model-compatibility checkpoint.
- Earlier CLI/scope production files remain byte-identical to that checkpoint.
- Metadata, selection and post-selection helper implemented with failing-to-passing
  boundary regressions. No model downloads or model-library deletions.
- Ruling: registry configs cannot supply an exhaustive native capability verdict;
  computed exact-model API metadata is authoritative, registry-only stays unknown.
  This prevents both guessed support and false negative rejection by model name.
- Independent review identified terminal-control injection and contradictory
  prose acceptance. Fixed by extracting exact status/version JSON from the model,
  comparing both fields against actual MCP output and rendering sanitized English.
- Native acceptance exposed FastMCP's structuredContent result wrapper. Added a
  matching regression and unwrap it only for evidence comparison; original MCP
  response remains unchanged in model context.
- Existing failed-verification regression now exercises Back recovery and asserts
  that no selected model is returned and no pull occurs.
- Windows full regression before the envelope regression: 256 passed, 22 skipped,
  116 subtests. Final verification remains pending; do not treat earlier counts
  or the in-progress native run as final completion evidence.


- Native stable acceptance exposed a pre-existing CLI negation false positive.
  Ruling: correct direct negated scan-verb intent classification only; retain
  original destination validation and execution guards. This is a genuine issue
  found in the requested diagnostic path, not a general CLI rewrite.
- Three failure-to-pass regressions and independent review cover the correction.
  Full Windows result: 260 passed, 22 skipped, 116 subtests in 52.93 seconds.
- The next native Bash UAT and actual free-form model diagnostic both passed.
  New exact verifier independently returned real healthy / 8.0.0 through 328-tool
  MCP and validated actual model JSON; full Linux regression summary pending.


Final completion evidence:
- Windows: 260 passed, 22 skipped, zero failures, 116 subtests, 52.93 seconds.
- Kali: 282 passed, zero skipped/failed, 123 subtests, 700.85 seconds.
- Native Bash UAT passed including actual unchanged installed-model library,
  unknown-download cancellation, unsupported selection recovery and restart.
- Both free-form native agent and exact post-selection verifier used actual
  qwen3:8b -> server_health({}) -> real healthy/8.0.0 -> correct model response.
- Authenticated MCP discovery exposed all 328 registrations; scope/DNS/approval
  regressions and owned-loopback Nmap passed. No model download or Git publication.
- Final report: docs/ollama-model-compatibility-validation.md.

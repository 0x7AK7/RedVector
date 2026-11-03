# Artifact, runtime and advisory adapters implementation plan

> **For agentic workers:** Use superpowers:executing-plans. Continue inline within the already approved backend-profile architecture. Do not commit, push or remove prior work.

**Goal:** Add independently tested compatible MCP workflows through shared read-only artifact, runtime and public-advisory adapters.

**Architecture:** Existing MCP names/signatures stay unchanged. Opt-in backend profiles intercept reserved markers/routes before legacy handlers. Operator-selected artifacts are snapshotted, hashed and staged privately; native parsers run with a minimal read-only Bubblewrap filesystem/network namespace. Runtime dashboards expose actual sanitized measurements. Advisory retrieval uses a fixed official provider, public-IP pinning, verified TLS, bounded responses and exact operator approval.

**Tech stack:** Python, Flask, MCP SDK, GNU strings/objdump/readelf, Bubblewrap, standard-library hex formatting, NVD CVE API.

**Spec:** Current user continuation request and docs/ollama-assessment-profiles.md.

## Global constraints
- Branch 0x7AK7/ollama-mcp-integration only; preserve all 328 signatures.
- No commits, Git staging, pushes, merges, PRs or README edits.
- No models downloaded; existing Claude configuration and backend processes untouched.
- Backup first: completed external verified ZIP checkpoint; all144 source files and manifest checked.
- No artifact code execution, arbitrary file browsing, command options or unrestricted exploitation/lateral movement.
- Newly counted tools require real named MCP calls with positive actual results.

## Review focus
- File mutation/symlink/traversal: only an operator-selected regular-file snapshot is authorized.
- Malformed files/parser side effects: private readonly filesystem, no host network, resource/output/time bounds.
- False security conclusions: report only actual ELF evidence; unsupported protections are Unknown.
- Advisory privacy/applicability: explicit provider/query approval; no invented CVEs or claims a target is vulnerable.
- Empty/stale runtime data: actual backend jobs/measurements; no synthetic zeros or arbitrary PID access.

## Task1: Read-only selected-artifact adapter
Files: new redvector_reviewed_artifacts.py, redvector_ollama_artifacts.py; modify server/MCP/agent/policy/profile attestation/CLI/help; add artifact policy, sandbox and real MCP tests.
Interfaces: select_artifact(path) snapshots a regular file <=4MiB and stages bytes/sha through a verified authenticated control endpoint; policy emits only selected opaque artifact markers. Shared run_profile(tool,params) supports strings_extract, xxd_hexdump, objdump_analyze and checksec_analyze.
- [ ] RED: unselected/changed/symlink files, forged handles/options and limit violations denied.
- [ ] Implement private session-bound staging/expiry, source attestation and exact typed options.
- [ ] Implement real GNU strings/objdump/readelf sandbox; computed hex output explicitly identifies its Python engine. Checksec profile reports actual readelf NX/RELRO/ELF facts, never claims missing checksec CLI ran.
- [ ] Add /artifact [PATH|--clear] to shared command registry and deterministic dispatcher.
- [ ] GREEN: compile an owned harmless ELF, execute all four actual MCP interfaces; validate bytes, marker string, ELF metadata/security facts and sandbox confinement.

## Task2: Shared sanitized runtime adapter
Files: new redvector_reviewed_runtime.py; modify opt-in server/MCP/policy/agent; unit/live tests.
Interfaces: authenticated runtime snapshot returns actual psutil metrics and ProcessManager records, excluding command arguments/output. Specific PID lookup requires prior actual discovery.
- [ ] RED: missing measurements are not fabricated; undiscovered/system PIDs rejected.
- [ ] Implement opt-in list_active_processes, get_process_dashboard, get_live_dashboard, get_process_status and display_system_metrics through the shared existing backend state.
- [ ] GREEN: hold a test-owned harmless FIFO reader in the isolated backend's actual ProcessManager; discover and query it through each named MCP interface; release reader without terminating other processes.

## Task3: Public advisory adapter
Files: new redvector_reviewed_advisories.py; modify opt-in server/MCP/policy/profile attestation; provider parsing/confinement tests and opt-in live MCP test.
Interfaces: monitor_cve_feeds retrieves bounded NVD publications using explicit approved hours/severity/keywords. Advisory records remain separate from observed target vulnerabilities.
- [ ] RED: arbitrary providers/redirects/private DNS, malformed/oversized payloads, invalid queries and missing approval denied.
- [ ] Implement anonymous official NVD endpoint, TLS/public-IP pinning, bounded time/body/record counts and honest partial/error states.
- [ ] GREEN: actual public provider response through the named MCP tool; if provider unavailable, report unverified rather than count success.

## Task4: Final verification and evidence
- [ ] Freeze production sources before native/model acceptance; do not invalidate active tests by editing them.
- [ ] Run complete relevant Windows/native core regressions and actual MCP/Ollama selection/output interpretation using existing models.
- [ ] One independent read-only final review; fix important findings with regression tests.
- [ ] Compare signatures and preservation hashes, review sensitive/untracked files and identity.
- [ ] Update exact per-tool matrix, grouped roadmap and implementation report; do not inflate counts or sum overlapping test runs.

## Ledger
- Recovery ZIP created and verified before project edits:144 files; SHA256 8c5781c1ce90d38a3b0e42619952fb251483b216cba29e16eefc44e38d526898.
- Existing native dependencies observed: GNU strings/objdump/readelf/gcc and Bubblewrap. xxd/checksec/exiftool/binwalk absent from PATH.
- Ruling: use actual readonly Python hex computation and actual readelf security evidence for compatible existing names, explicitly identify engines — avoids pretending absent binaries ran; limitations are stated.
- Ruling: add deterministic /artifact authorization rather than infer filesystem scope from model text — preserves a trusted operator boundary; a new command is the necessary UI addition.
- User prohibition on commits overrides skill commit/checkpoint steps; recovery archive is the checkpoint.

- Task1: 4 actual artifact MCP interfaces passed native execution; snapshot bytes/hash and clearing verified.
- Task2: 5 actual runtime MCP interfaces passed against a real registered FIFO reader; no process mutation enabled.
- Task3: 2 actual NVD-backed advisory interfaces passed; earlier wrapper timeout remains unassigned, durable rerun passed 67.78s.
- Additional passive Nmap greetings and HTTP EOF/deadline issues reproduced and corrected; no extra probes.
- Ruling: reviewer labelled the hex boundary issue minor; graded important because displayed bytes contradicted requested bounds and returned-byte facts — corrected rather than deferred; cost if ignored is unreliable forensic evidence.
- Final fix pass: exact hex windows(1,17 bytes/nonzero offset) and preserving genuine parser errors both RED→GREEN; final suites pending.

# MCP functional coverage: current implementation and validation

**30 distinct registered MCP tools now have independently verified constrained workflows executed through real MCP/backend paths. Full 328-tool coverage is unfinished: 298 registrations still lack a verified client execution workflow.** These counts measure named MCP interfaces actually invoked with positive real results, not unrestricted support for every argument in those interfaces.

> **Critical pentest-workflow repair (post-29 baseline).** Three field-reported failures were root-caused and fixed: (1) full-range TCP discovery — added the reviewed `tcp-discovery-v1` profile (real attested native nmap `-sT`, 1–65535, XML open/closed/filtered states) with policy routing so a full-range request is never silently capped to the 128-port service profile, then service/version identification runs on the discovered open ports in ≤128 chunks; (2) the reviewed `ai_vulnerability_assessment` staged orchestrator (`redvector_reviewed_vulnscan.py`) chaining reviewed profiles into an evidence-ranked report with a per-stage audit trail (now verified → the +1 above), plus `availability.status` fixes so reviewed passive tools no longer report a native "Missing Dependency", clearer Nuclei checksum-vs-missing diagnostics, and HTTP-assess arg-routing that no longer hard-fails on benign arguments; (3) authorization UX — reviewed passive HTTP/TCP tools run within scope without prompts while high-impact scans still require explicit approval each time, case-insensitive `approve`/`deny`, and a distinct error taxonomy instead of treating a missing adapter as a denial. Verified: Windows 516/0/47, native Kali 555/0/6, plus full-range discovery and staged-assessment live tests against owned loopback services and real native nmap. The `qwen3:8b` MCP tool-selection against the operator's live environment and the authorized `192.168.5.130` lab target remain for the operator to exercise.

The complete matrix is docs/ollama-tool-coverage.md, with exact SDK schemas/source evidence in docs/ollama-tool-coverage.json. Runtime evidence is bound to current production-source checksums in docs/ollama-reviewed-validation.json. All 328 names/signatures/defaults remain unchanged.

## Completed shared integrations

The nine original diagnostic/reporting interfaces and the four shared scanner/HTTP interfaces remain verified: server_health, get_cache_stats, get_telemetry, error_handling_statistics, clear_cache, nmap_scan, create_scan_summary, create_vulnerability_report, format_tool_output_visual, nmap_advanced_scan, http_framework_test, http_repeater and nuclei_scan.

Five reviewed read-only adapter families add sixteen further verified registered tools:

- **Operator-selected artifact profile (4):** strings_extract, xxd_hexdump, objdump_analyze, checksec_analyze. An operator `/artifact PATH` selection is snapshotted as an immutable SHA256-verified regular file (1 byte..4 MiB). Native GNU strings/objdump/readelf run inside a minimal read-only Bubblewrap filesystem with an isolated network namespace; xxd_hexdump formats the actual selected bytes with a bounded Python engine and never claims an external xxd binary ran. checksec_analyze reports only actual readelf NX/RELRO/ELF-type facts.
- **Sanitized read-only runtime profile (5):** list_active_processes, get_process_dashboard, get_live_dashboard, get_process_status, display_system_metrics. These expose actual psutil metrics and existing-backend ProcessManager records with command arguments and output excluded. A specific PID requires prior real discovery; unknown PIDs are refused. No job mutation is enabled.
- **Fixed NVD advisory provider (1):** monitor_cve_feeds. Anonymous NVD CVE API 2.0 retrieval with public-IP pinning, verified TLS, bounded window/record/body limits and explicit operator approval. Keyword/severity filters stay local; no target or credential data is transmitted and no target applicability is inferred.
- **Confined passive HTTP assessment (4):** httpx_probe, nikto_scan, wafw00f_scan, jaeles_vulnerability_scan. Each reuses the existing reviewed root-response collector for ONE numeric-pinned, TLS-verified, no-redirect root GET and reports only actual observed evidence: httpx_probe returns status/title/server/technologies; wafw00f_scan matches passive WAF/CDN header signatures; nikto_scan reviews server/security-header/cookie configuration; jaeles_vulnerability_scan matches a fixed set of passive response signatures. The reserved profile marker rides in each tool's existing `additional_args` field (no MCP signature changed) and fails closed on legacy backends. See the distinction below — this is **not** full native httpx/Nikto/Wafw00f/Jaeles execution and runs no external scanner binary.
- **Bounded TCP discovery (2):** masscan_high_speed, rustscan_fast_scan. Neither native scanner is installed on the host and neither is executed. Both route (via a reserved `additional_args` marker, no signature change, fail-closed on legacy backends) to RedVector's own bounded Python `socket` TCP connect engine: a scope-pinned numeric target, 1..128 explicit ports, at most 64 concurrent connections, a 1s per-connect timeout and a 20s overall deadline, classifying each port open/closed/filtered from real connect() attempts. Unbounded full-range (`1-65535`) and high-speed/internet-scale scanning are refused. `SCAN_PROFILE` (`redvector-tcp-connect-v1`) becomes Ready only through genuine backend capability attestation. The result's `scanner.mode` and `engine` state plainly that this is the RedVector bounded connect engine, not native Masscan or RustScan.

## Reviewed assessment/discovery vs. full native scanners

The six HTTP-assessment and TCP-discovery tools are deliberately a bounded subset, never the native tools they are named for:

- **Bounded by design.** HTTP assessment is a single pinned, TLS-verified root GET with no redirects, proxies, credentials, bodies, cookies, crawling or active payloads — versus native httpx mass-probing, Nikto's thousands of active checks, Wafw00f's active WAF-triggering probes and Jaeles' active signature exploitation. TCP discovery is a scope-pinned connect() scan of at most 128 explicit ports with capped concurrency and timeouts — versus native Masscan's raw-socket internet-scale rates and RustScan's full 65,535-port sweeps.
- **No external binary is executed.** All evidence is computed by RedVector's own reviewed Python engines (`http.client` collector; `socket` TCP connect engine); each result's `scanner.mode`/`engine` states this explicitly, and no `httpx`/`nikto`/`wafw00f`/`jaeles`/`masscan`/`rustscan` process is spawned (Masscan and RustScan are not even installed on this host). No scanner is substituted while claiming native execution.
- **Observations, not verdicts.** Results describe actual observed response configuration or real connect() port states; absence of a finding is not proof of safety, and no exploitability is claimed.

## Confirmed correction in this validation pass

capabilities() in redvector_reviewed_artifacts.py caught ArtifactError/OSError/SubprocessError but not ProfileError. A single per-tool runtime-trust failure (for example a parser runtime that is not administrator-owned, raised by the shared `_trusted` check) therefore aborted the entire capability listing instead of being isolated to that one capability. ProfileError is now caught and that tool is reported Unsupported with its exact cause while other capabilities continue. The untrusted-parser isolation test is RED→GREEN, and the full Windows and native suites pass with the fix in place.

## Eight previously unresolved static routes, resolved with runtime evidence

The source inventory flagged eight registrations whose backend route it could not map statically. Actual source/dispatch inspection resolves all eight:

- **Composite orchestrators (call sibling MCP tools; no own REST route):** ai_generate_attack_suite calls ai_generate_payload per attack type; comprehensive_api_audit calls api_fuzzer and api_schema_analyzer; threat_hunting_assistant synthesizes a local playbook. These fan out to sibling tools that themselves still require adapters.
- **Dynamic f-string REST routes (Flask handlers confirmed present):** delete_file → `DELETE /api/files/delete`; get_process_status → `GET /api/processes/status/<int:pid>`; terminate_process → `POST /api/processes/terminate/<int:pid>`; pause_process → `POST /api/processes/pause/<int:pid>`; resume_process → `POST /api/processes/resume/<int:pid>`.

get_process_status is additionally served read-only through `GET /api/ollama/runtime` and is now verified via the runtime adapter. delete_file and terminate/pause/resume_process have working legacy routes but are intentionally **not** enabled through the reviewed read-only adapters; they remain high-impact and restricted pending per-effect approval and containment design.

## Exact successful test runs (this validation pass)

| Run | Passed | Failed | Skipped | Subtests |
|---|---:|---:|---:|---:|
| Windows full regression (current) | 507 | 0 | 45 | 129 |
| Native Kali core regression (smoke, current) | 544 | 0 | 6 | 136 |
| Artifact/runtime/advisory adapter real-execution (verbose) | 13 | 0 | 0 | — |
| HTTP assessment real-execution (1 full-bridge MCP + 9 unit) | 10 | 0 | 0 | — |
| Bounded TCP discovery real-execution (1 full-bridge MCP + 6 unit) | 7 | 0 | 0 | — |

Across this adapter series the Windows/native suites grew 492/527 → 501/537 (confined HTTP assessment) → 507/544 (bounded TCP discovery) as each family's tests were added. Two transient regressions occurred and were resolved honestly: the reviewed-allowlist guard test's hardcoded membership set (updated to include each newly reviewed tool — still exact-equality, not loosened), and a profile-attestation allowlist that did not register `redvector-tcp-connect-v1` (added to the assessment-module attestation set, same source-integrity gate). Both suites are green.

Counts in separate runs overlap and must not be summed. Exact commands:

    .ollama-test-env/Scripts/python.exe -m pytest -q -rs
    REDVECTOR_RUN_SMOKE=1 .ollama-linux-env/bin/python3.13 -m pytest -q -rs --ignore=tests/test_ollama_kali_uat.py --ignore=tests/test_ollama_unified_live.py
    REDVECTOR_RUN_SMOKE=1 REDVECTOR_RUN_PUBLIC_ADVISORY=1 .ollama-linux-env/bin/python3.13 -m pytest -v -rs tests/test_ollama_artifact_live.py tests/test_reviewed_artifact_sandbox_live.py tests/test_ollama_runtime_live.py tests/test_reviewed_assessment_live.py tests/test_reviewed_ports_live.py tests/test_reviewed_profiles_live.py tests/test_reviewed_banner_live.py tests/test_ollama_advisory_live.py
    REDVECTOR_RUN_SMOKE=1 .ollama-linux-env/bin/python3.13 -m pytest -v -rs tests/test_ollama_http_assessment_live.py tests/test_reviewed_http_assessment.py
    REDVECTOR_RUN_SMOKE=1 .ollama-linux-env/bin/python3.13 -m pytest -v -rs tests/test_ollama_tcp_scan_live.py tests/test_reviewed_tcp_scan.py

The native runs configured REDVECTOR_NUCLEI_BIN to the verified private dependency (.ollama-linux-env/reviewed-nuclei/nuclei, pinned v3.11.1). The adapter run additionally set REDVECTOR_RUN_PUBLIC_ADVISORY=1, which exercises the advisory tool against the real public NVD endpoint. No model was pulled.

The native core regression's six skips are the opt-in public-advisory test (run separately above), the opt-in installed-model acceptance (no operator model configured in this environment), two native PTY help tests, Windows DACL semantics and the shared-model live test. The heavy legacy Kali UAT and unified real-model terminal UAT were excluded by `--ignore`.

Named adapter real-execution results:

    REAL FOUR-ARTIFACT MCP PASS: 328 registrations; operator snapshot SHA matched; real strings/objdump/readelf and computed hex; four named interfaces; original file unchanged; cleared selection refused.
    REAL SANDBOX PASS: selected input read-only, outside files hidden, parser in a separate network namespace, excessive output reported as failure not success.
    REAL FIVE-RUNTIME MCP PASS: real managed FIFO reader discovered/queried; three read views and actual psutil metrics; command arguments/output excluded; unknown PID refused; 328 tools.
    REAL PUBLIC ADVISORY MCP PASS: fixed NVD provider; 64-char provider payload digest; bounded sampled records; no target/credential data transmitted.
    REAL NUCLEI / TLS / 128-PORT / PROFILE / BANNER PASS: native pinned v3.11.1, two actual findings and a clean control, numeric-pin TLS hostname preserved, 128 owned FTP banner endpoints, service-version profile with no redirects or extra payload.
    REAL FOUR-HTTP-ASSESSMENT MCP PASS: httpx/wafw00f/nikto/jaeles reviewed passive profiles; one confined GET each; actual response evidence; no external scanner binary; 328 tools.
    REAL TCP-DISCOVERY MCP PASS: masscan_high_speed/rustscan_fast_scan reviewed bounded connect engine; owned loopback open/closed classified; native scanners not executed; 328 tools.

## Independently verified tools by shared adapter group

| Group | Verified / total |
|---|---|
| Authenticated runtime diagnostics | 5 / 5 |
| Saved-evidence analysis and presentation | 5 / 8 |
| Bounded local-artifact analysis | 4 / 20 |
| Confined HTTP assessment | 7 / 7 |
| Owned-process management (read-only) | 3 / 6 |
| Bounded TCP scanners | 4 / 4 |
| Third-party enrichment | 1 / 16 |
| High-impact authorized workflows | 0 / 90 |
| Staged assessment/orchestration | 0 / 154 |
| Reference catalogs requiring purity review | 0 / 12 |
| Operator-workspace execution | 0 / 6 |

Groups cover 328 registrations exactly and do not authorize execution. 320 registrations have a statically mapped backend handler; eight were resolved above. Priorities remain shared per-stage authorization/provenance adapters, read-only evidence analysis, pure reference/data tools, bounded artifact processing and separately approved third-party enrichment. High-impact orchestration needs per-effect approvals, destination/callback containment and real owned-lab tests.

## Remaining limitations

- Bounded TCP discovery (masscan_high_speed/rustscan_fast_scan) is RedVector's own Python connect() engine, not native Masscan/RustScan (neither installed, neither executed): at most 128 explicit ports, ≤64 concurrent connections, 1s connect timeout, 20s deadline, scope-pinned; no raw sockets, UDP, OS detection, banners or high-speed rates.
- Confined HTTP assessment (httpx_probe/nikto_scan/wafw00f_scan/jaeles_vulnerability_scan) is one pinned TLS-verified root GET reporting observed evidence only; not the full native tools and no external scanner binary is run.
- Nuclei implements only two passive root-response header checks; arbitrary CVE/active templates, code/JS/headless/OAST are separate reviewed profiles.
- Nmap active service profile covers SSH/HTTP/FTP/SMTP/POP3/IMAP/MySQL greeting evidence, up to 128 explicit ports; NSE/UDP/OS detection and stealth timing remain outside it.
- The runtime profile is read-only; process pause/resume/terminate and delete_file are not enabled through it.
- The advisory profile samples anonymous NVD publications; it is not a statement of exploitability, global threat trends or target applicability.
- Real-model Ollama acceptance was not rerun in this pass because no operator model was configured in this environment; the prior qwen3:8b acceptance record predates the current source re-freeze.
- The source inventory is bounded automated analysis, not a completed manual audit of all 328 transitive behaviors.

## Preservation and repository state

Branch remains 0x7AK7/ollama-mcp-integration. Nothing was staged, committed, pushed, merged or published; README, banner, legacy launcher, installer/model-selection/storage/compatibility modules and the unified terminal presentation are unchanged. All 328 registered names/signatures/defaults are unchanged (328 `@mcp.tool` definitions confirmed). Existing backend processes and Ollama model manifests were not modified; only test-owned processes/artifacts were used. Git author/committer remain the requested 0x7AK7 identity.

docs/ollama-reviewed-validation.json now records runtime evidence bound to the current production-source checksums (re-frozen this pass, after the earlier checkpoint had drifted from edited sources). The previous checkpoint remains nested there.

## Exact cumulative changed files

- docs/ollama-artifact-advisory-profiles.md
- docs/ollama-assessment-profiles.md
- docs/ollama-execution-review.md
- docs/ollama-reviewed-validation.json
- docs/ollama-tool-coverage.json
- docs/ollama-tool-coverage.md
- docs/superpowers/plans/2026-10-26-artifact-advisory-adapters.md
- docs/superpowers/plans/2026-10-26-reviewed-tools.md
- redvector_mcp.py
- redvector_ollama_agent.py
- redvector_ollama_artifacts.py
- redvector_ollama_availability.py
- redvector_ollama_backend.py
- redvector_ollama_cli.py
- redvector_ollama_help.py
- redvector_ollama_policy.py
- redvector_ollama_presentation.py
- redvector_ollama_profiles.py
- redvector_ollama_reporting.py
- redvector_ollama_results.py
- redvector_reviewed_advisories.py
- redvector_reviewed_artifacts.py
- redvector_reviewed_assessment.py
- redvector_reviewed_profiles.py
- redvector_reviewed_runtime.py
- redvector_server.py
- tests/ollama_profile_runtime.py
- tests/test_ollama_advisory_live.py
- tests/test_ollama_agent_responses.py
- tests/test_ollama_artifact_live.py
- tests/test_ollama_artifact_policy.py
- tests/test_ollama_assessment_model_live.py
- tests/test_ollama_assessment_policy.py
- tests/test_ollama_availability.py
- tests/test_ollama_http_assessment_live.py
- tests/test_ollama_tcp_scan_live.py
- tests/test_reviewed_http_assessment.py
- tests/test_reviewed_tcp_scan.py
- tests/test_ollama_interactive_help.py
- tests/test_ollama_legacy_profile_trust.py
- tests/test_ollama_linux_bridge.py
- tests/test_ollama_nmap_live.py
- tests/test_ollama_profile_client.py
- tests/test_ollama_profile_routes.py
- tests/test_ollama_reviewed_policy.py
- tests/test_ollama_runtime_live.py
- tests/test_ollama_scope_extended.py
- tests/test_ollama_scope_regression.py
- tests/test_ollama_shared_model_live.py
- tests/test_ollama_unified_presentation.py
- tests/test_reviewed_adapter_routes.py
- tests/test_reviewed_advisories.py
- tests/test_reviewed_artifact_sandbox_live.py
- tests/test_reviewed_artifacts.py
- tests/test_reviewed_assessment.py
- tests/test_reviewed_assessment_live.py
- tests/test_reviewed_banner_live.py
- tests/test_reviewed_dependency_install.py
- tests/test_reviewed_ports_live.py
- tests/test_reviewed_profile_expansion.py
- tests/test_reviewed_profiles.py
- tests/test_reviewed_profiles_live.py
- tests/test_reviewed_runtime.py
- tools/install_reviewed_nuclei.py
- tools/review_ollama_tool_inventory.py

# RedVector v8.0 W7 — VMware Kali Acceptance Checklist

**Branch**: `0x7AK7/ollama-mcp-integration`  
**Date**: complete this column during the acceptance run  
**Operator**: (your username / date / Kali kernel)

> This checklist is evidence-gated. Every row must be marked **PASS** with real observed output
> before declaring that capability complete. Do not mark PASS from memory or from Windows test
> results alone.

---

## Pre-flight (run first, all must pass before any native test)

| # | Step | Expected | Result | Notes |
|---|------|----------|--------|-------|
| P1 | `python3 --version` | 3.x | | |
| P2 | `git branch` shows `0x7AK7/ollama-mcp-integration` | ✓ | | |
| P3 | `grep -c "@mcp.tool" redvector_mcp.py` | `328` | | |
| P4 | `./.ollama-test-env/bin/python -m pytest tests/ -q` (Windows equivalent on Kali) or `python3 -m pytest tests/ -q` | All pass (≥749), 0 failures | | |
| P5 | `python3 -c "import redvector_tool_manager as tm; print(tm.discover_tools()['nikto'])"` | Shows `nikto-native-v1` with `state` field | | |

---

## N0 — Tool discovery (`redvector_tool_manager`)

| # | Step | Expected | Result | Notes |
|---|------|----------|--------|-------|
| N0-1 | `python3 -c "import redvector_tool_manager as tm; lines=tm.format_tool_report(tm.discover_tools()); [print(l) for l in lines]"` | At least one ✓ line for Nmap (Ready); Nikto, Nuclei, Searchsploit state visible | | |
| N0-2 | Confirm `nikto-native-v1` state is `Ready` (binary present) | `state: Ready` | | |
| N0-3 | Confirm `searchsploit-v1` state is `Ready` | `state: Ready` | | |
| N0-4 | Confirm `nse-vuln-v1` state is `Unsupported` (allowlist empty) | `state: Unsupported`, detail mentions allowlist | | Curation is a separate step |
| N0-5 | `unavailability_reason` for `nse-vuln-v1` starts with `"not run:"` | ✓ | | |

---

## N1 — Nuclei 3.11.0 candidate build

> Run these **before** requesting the enablement commit. The SHA must match exactly.

| # | Step | Expected | Result | Notes |
|---|------|----------|--------|-------|
| N1-1 | `sha256sum /usr/bin/nuclei` | Record the exact SHA256 here: __________________ | | Compare with `NUCLEI_BUILDS` in `redvector_reviewed_assessment.py` |
| N1-2 | `dpkg -V nuclei` (or `apt show nuclei`) | Clean (no modified files); version 3.11.0 | | |
| N1-3 | `python3 -c "from redvector_reviewed_assessment import capabilities; print(capabilities())"` | If SHA matches: `Ready`; if not: `Unsupported: Nuclei SHA256 not in approved builds registry` | | If Unsupported, collect SHA and request enablement commit |
| N1-4 | **(After enablement commit only)** `RV_LAB_TARGET=http://127.0.0.1:8080 python3 tests/test_w6_native_acceptance.py` test `N1_NucleiCandidate` | Mode A, offline header profile, findings parse | | |

---

## N2 — Native Nikto

| # | Step | Expected | Result | Notes |
|---|------|----------|--------|-------|
| N2-1 | `which nikto && nikto -Version` | `/usr/bin/nikto`, version ≥2.x | | |
| N2-2 | `sha256sum $(which nikto)` | Record SHA here: __________________ | | Nikto is a Perl script; SHA covers the script file |
| N2-3 | `python3 -c "from redvector_reviewed_nikto import capabilities; print(capabilities())"` | `{'nikto-native-v1': {'state': 'Ready', ...}}` | | |
| N2-4 | Start a loopback HTTP service (e.g. `python3 -m http.server 8888`) then: `python3 -c "from redvector_reviewed_nikto import run_nikto; import json; r=run_nikto({'target':'http://127.0.0.1:8888/','additional_args':'--redvector-nikto-native-v1'}); print(r['execution_mode'], r.get('findings_count'), r.get('binary'))"` | `A <count> /usr/bin/nikto` | | execution_mode A = native binary executed |
| N2-5 | Repeat N2-4 against `RV_LAB_TARGET` (your owned lab host) | Mode A; findings parse; no crash | | |
| N2-6 | In the assessment workflow: `python3 redvector_ollama_cli.py` → authorize lab target → assess → confirm NATIVE TOOL EXECUTION table shows `native Nikto` with `native_executed: true` | ✓ | | |
| N2-7 | Confirm passive collector row does NOT appear when native Nikto ran | `RedVector passive HTTP collector (NOT native Nikto)` absent | | |

---

## N3 — Searchsploit in workflow

| # | Step | Expected | Result | Notes |
|---|------|----------|--------|-------|
| N3-1 | `which searchsploit && searchsploit --version` | `/usr/bin/searchsploit`, version shown | | |
| N3-2 | `python3 -c "from redvector_reviewed_searchsploit import capabilities; print(capabilities())"` | `searchsploit-v1: Ready` | | |
| N3-3 | `python3 -c "from redvector_reviewed_searchsploit import run_searchsploit; import json; r=run_searchsploit({'search':'Apache 2.4 RCE','additional_args':'--redvector-searchsploit-native-v1'}); print(r['execution_mode'], len(r.get('parsed',{}).get('results',[])), 'results')"` | Mode A, results list printed | | |
| N3-4 | In assessment workflow against a lab host running Apache: confirm SEARCHSPLOIT row in ENGINE table shows mode A | ✓ | | |

---

## N4 — Finding correlation (W7-C)

| # | Step | Expected | Result | Notes |
|---|------|----------|--------|-------|
| N4-1 | After a full assessment, confirm no finding is labelled "Confirmed" from a Searchsploit reference alone | All Searchsploit entries labelled "Candidate CVE" or "Exploit Reference" | | |
| N4-2 | Apache httpd service: Searchsploit references for "Apache HTTP Server" match; references for unrelated products ("Apache ActiveMQ") do NOT match | ✓ | | |
| N4-3 | Version-exact match promotes applicability to `applicable`; version-missing stays `candidate` | ✓ | | |

---

## N5 — NSE curation (prerequisite for nse-vuln-v1 enablement)

> NSE stays **disabled** until this step is complete and reviewed.

| # | Step | Expected | Result | Notes |
|---|------|----------|--------|-------|
| N5-1 | `python3 tools/collect_kali_evidence.py` | Generates `nse.vuln_and_safe` (and other inventory files) | | |
| N5-2 | Review `nse.vuln_and_safe` — remove any script that writes, exploits, or is not read-only | Curated list ready | | Share with RedVector team for allowlist commit |
| N5-3 | **(After allowlist commit only)** `python3 -c "from redvector_reviewed_profiles import capabilities; c=capabilities(); print(c.get('nse-vuln-v1'))"` | `state: Ready` | | |

---

## N6 — Full NL session (end-to-end)

Run after N1–N4 are all PASS.

| # | Phrase | Expected | Result |
|---|--------|----------|--------|
| N6-1 | `"Authorize <LAB_IP> as my lab target."` | One confirmation; scope set | |
| N6-2 | `"Scan all 65535 TCP ports using native Nmap and identify services."` | One NL confirmation; DISCOVERY shows `65535 requested / 65535 completed`; service batch uses only discovered ports | |
| N6-3 | `"Find critical and high vulnerability candidates using verified native Kali scanners."` | Assessment runs; native Nikto and/or Nuclei (if N1 enabled) in ENGINE table; Searchsploit references labelled correctly | |
| N6-4 | `"Which native tools actually executed?"` | Provenance table; correct execution_mode per tool | |
| N6-5 | `"Show the original execution evidence without scanning again."` | Evidence summary; NO rescan; raw JSON not auto-dumped | |
| N6-6 | `"Export the latest assessment as JSON."` | Valid JSON file produced | |

---

## W6 rerun after fix commit (Nuclei SHA + Nikto JSON)

> Run these steps after the Nuclei SHA enablement commit is merged.

| # | Step | Expected |
|---|------|----------|
| R1 | `export REDVECTOR_RUN_SMOKE=1 REDVECTOR_NUCLEI_ALLOW_CANDIDATE=testing REDVECTOR_NUCLEI_CANDIDATE_SHA256=141b859667fd2cc97a648adc09d4c0ddbc2449b780ebb4d851edebc0f5b24710` | env set |
| R2 | `python3 -m pytest tests/test_w6_native_acceptance.py -v` | **4 PASSED, 0 FAILED** |
| R3 | Confirm `test_nuclei_candidate_build_validation` prints `NUCLEI candidate: /usr/bin/nuclei … detected v3.11.0` | ✓ |
| R4 | Confirm `test_native_nikto_adapter` prints `NIKTO … binary /usr/bin/nikto findings <N>` | mode A, no JSON error |
| R5 | `python3 -m pytest tests/test_w8_native_regression.py -v` | **10 PASSED, 0 FAILED** |

---

## Sign-off

| Criterion | Signed off by | Date |
|-----------|---------------|------|
| N0 Tool discovery — all states correct on Kali | | |
| N1 Nuclei 3.11.0 — SHA collected / enablement commit requested | | |
| N2 Native Nikto — mode A confirmed on loopback + lab | | |
| N3 Searchsploit — mode A in workflow | | |
| N4 Correlation — no false "Confirmed" labels | | |
| N5 NSE curation — list collected (enablement separate) | | |
| N6 Full NL session — all 6 phrases pass | | |
| 328 MCP signatures intact | | |
| No commit/push without explicit operator approval | | |

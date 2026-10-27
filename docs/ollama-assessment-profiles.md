# Reviewed assessment workflows

These are constrained operational profiles, not blanket permission for every argument exposed by a registered MCP tool. All 328 names and signatures remain unchanged.

## Shared adapters

- **TCP service profile:** nmap_scan and nmap_advanced_scan share the same backend-owned native Nmap executor. Active scans accept 1–128 explicit TCP ports, exclude printer ports 9100–9107, and require exact operator approval. Passive banners recognize OpenSSH, ProFTPD and Postfix; an origin-form GET recognizes HTTP Server product/version headers. Unidentified versions remain unverified.
- **Root response profile:** http_framework_test and http_repeater share one direct pinned HTTP(S) GET/HEAD collector. No environment proxies, redirects, query strings, custom paths, credentials, cookies or request bodies. Two concurrent captures maximum; 64 KiB response body, bounded headers and a ten-second deadline. TLS verifies the original authorized hostname while connecting only to its authorized numeric pin.
- **Nuclei profile:** nuclei_scan reuses that collector, then evaluates the captured response using the real pinned Nuclei engine in passive mode. The scanner cannot create network sockets under a Linux seccomp filter. Its input is a canonical header-only representation, preventing decoded chunked bodies from invalidating framing; matches must agree with actual captured header names or the assessment fails. Two app-owned templates observe absent X-Content-Type-Options and X-Frame-Options headers. Findings are informational configuration observations; exploitability is not assessed. Secure controls produce zero findings.
- **Evidence/reporting:** the existing three reporting interfaces use saved real MCP findings. The two Nuclei observations propagate into an actual vulnerability report without inventing CVEs or promoting severity.

The Nmap port-discovery rate limit is not a claimed application-probe rate limit. Application work is bounded structurally by the fixed two-probe database, explicit port count, one scanner process and execution deadline. Deadline exhaustion reports failure/partial evidence, not fabricated completion.

## Dependency setup

The reviewed Nuclei dependency is Linux amd64 v3.11.1. It is separate from Ollama models and does not require any model download.

Run the installer with an explicitly chosen private absolute directory:

    python3 tools/install_reviewed_nuclei.py --directory /YOUR/PRIVATE/DEPENDENCY/DIRECTORY

Configure REDVECTOR_NUCLEI_BIN in the backend environment to the printed executable path. Existing differing files are refused, never overwritten. The installer changes no global PATH, service configuration or existing filesystem ownership/permissions.

Archive SHA256: ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6

Binary SHA256: c49588140f357cbdddd5436dec11201953a4c5390faeec90777f9ee2cfd70251

Sources: [official release](https://github.com/projectdiscovery/nuclei/releases/tag/v3.11.1), [official passive-scan documentation](https://github.com/projectdiscovery/nuclei-docs/blob/main/docs/nuclei/get-started.md#passive-scan), [pinned CLI documentation](https://github.com/projectdiscovery/nuclei/blob/v3.11.1/README.md).

The dependency installer and runtime verify the pinned checksums. Other versions/architectures remain Unsupported until separately reviewed and tested. Capability metadata distinguishes a configured reviewed executable from absence on the general PATH.

An existing backend is never restarted automatically. Updated profile source must be present before that backend starts; a source/process mismatch requires the operator to reconnect to a verified compatible instance. No automatic port change conceals conflicts.

## Operator usage

Set explicit host/CIDR scope through /scope first. Supply an authorized root HTTP(S) URL to nuclei_scan, http_framework_test or http_repeater. The client validates scope and DNS pins and translates arguments into the reserved backend profile marker. The agent cannot choose arbitrary templates or request modifications.

Use /tools nuclei or /tools http to refresh actual verified capabilities. Ready means the selected constrained profile is available; it does not claim arbitrary registered options work. Native high-impact approval and existing discovery bounds are preserved.

## Remaining assessment work

Broad CVE template libraries, authenticated scanning, arbitrary paths/queries, custom headers/bodies, crawling, OAST, code/JavaScript/headless execution, UDP, OS detection and arbitrary NSE are not enabled by these profiles. Each needs an audited request/effect budget, destination handling and real positive/negative tests. Jaeles and Clair remain separate dependency/integration projects.

The complete per-tool matrix groups the remaining registrations by reusable adapter family, dependency evidence and risk. Registration, category membership and executable presence alone never establish successful execution.

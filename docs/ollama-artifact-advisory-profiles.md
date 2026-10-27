# Shared artifact, runtime and advisory profiles

These opt-in paths preserve the328 existing MCP registrations. Counts represent actual independently invoked named interfaces, not unrestricted support for every registered argument.

## Operator-selected artifacts

Use /artifact PATH to select one regular file (quoted or unquoted paths with spaces are accepted). The local file is snapshotted and hashed without modifying it. Only that snapshot is authorized. Re-select after local edits; /artifact displays its filename/size/SHA256, and /artifact --clear revokes local authorization immediately.

The client stages actual bytes through a separately authenticated localhost control endpoint after backend process/source verification. The endpoint accepts no filesystem paths. Handles bind a random session, private artifact ID and SHA256. Model tool schemas accept only the literal selected marker; they cannot choose files or upload bytes.

Bounds:1 byte..4MiB;16 private snapshots per backend;15-minute expiry with physical cleanup scheduled shortly afterward; two parser jobs;512KiB output;12-second job deadline;5 CPU seconds;512MiB parser address space; no core files. Failed cleanup does not retain client authorization.

| Registered interface | Actual reviewed engine | Supported operation |
|---|---|---|
| strings_extract | GNU strings | ASCII strings with minimum length4..64 and actual offsets |
| xxd_hexdump | Bounded Python byte formatting | Exact offset/length windows, maximum4096 bytes; no external xxd binary claimed |
| objdump_analyze | GNU objdump | Static headers or bounded disassembly; no free-form flags |
| checksec_analyze | GNU readelf | Actual ELF type, GNU_STACK NX and GNU_RELRO/BIND_NOW evidence; no absent checksec binary claimed |

Native parsers execute only a verified administrator-owned tool. Bubblewrap provides a minimal read-only filesystem containing that tool, trusted shared libraries and the private selected input. Host files are not mounted; the network/PID namespaces are separate. Uploaded artifacts are data, never executed. The wrapper prevents privilege gain and applies resource bounds.

This is static analysis, not malware detonation or a replacement for a hardened dedicated malware-analysis VM. Unsupported native/user-namespace configurations fail preflight; they do not fall back to unrestricted host execution. Larger files, additional protections such as stack canaries and other metadata engines remain explicit integration work.

## Sanitized backend runtime views

list_active_processes, get_process_dashboard, get_live_dashboard, get_process_status and display_system_metrics share actual existing ProcessManager records and psutil measurements.

Command arguments, raw process output and process objects are omitted. Only registered backend jobs are listed, at most256 records with a partial flag if more exist. A specific PID must have been discovered through a real preceding MCP result and must retain its recorded start time. No arbitrary OS process inspection, suspension, resumption or termination is enabled.

Missing measurements fail; zero values are never fabricated as defaults. A real test-owned FIFO reader was created through the isolated backend's existing allowed head command, discovered and queried, then released normally. No existing backend process was stopped or reconfigured.

## Official public advisory sampling

monitor_cve_feeds and vulnerability_intelligence_dashboard use the official NVD CVE API. The anonymous publication-window query requires exact operator approval. Keywords and severity filters run locally: no target names, IPs, artifact data, credentials or keywords are sent to NVD.

The provider hostname is fixed, DNS answers must be public, the connection is numerically pinned and TLS verifies the NVD hostname. No environment proxies, redirects or arbitrary providers are accepted. Bounds:1..168 hours, at most100 records and2MiB, bounded DNS/connection/response time, provider cooldown and60-second cache. Payload SHA256 and retrieval/window timestamps accompany results.

A dashboard reports statistics from that retrieved sample only. It does not invent threat actors, exploit availability or global trends. Advisory presence does not establish target applicability or exploitability. If the response is incomplete, filtered, unavailable or malformed, that state is explicit; no false-clean result is inferred.

Source: [NVD CVE API documentation](https://nvd.nist.gov/developers/vulnerabilities).

## Extra source-evidence and compatibility checks

The Nmap service profile retains two probes, its128-port bound and exact approval. Additional NULL-greeting matches recognize vsFTPd/Exim versions, Dovecot POP3/IMAP products and MySQL/MariaDB-reported greeting versions. These are source-reported identifiers, not proof of a vulnerable binary build. No new protocol commands were added.

HTTP capture now retains the active response socket for its deadline and rejects truncated declared-length bodies. These corrections prevent partial data being labelled a completed read.

All new backend modules are included in profile source attestation. Current and explicitly reviewed prior backend fingerprints can be identified independently across checkouts, while new profiles require their own matching source evidence. An existing backend is never automatically restarted or moved to another port. If code changes after startup, reconnect to an operator-started compatible instance.

## Recovery checkpoint

Before this continuation, a non-destructive external ZIP backed up144 tracked/untracked source files with per-file SHA256, the exact working-tree patch, branch/HEAD and Git refs. Ignored environments, models and logs were excluded. Archive SHA256:

8c5781c1ce90d38a3b0e42619952fb251483b216cba29e16eefc44e38d526898

The archive location is reported in the conversation; it is outside the checkout. No commits, Git staging or history changes were used.

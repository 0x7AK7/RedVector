# RedVector Security-Tool Integration Layer

> Generated from `tests/fixtures/security_tool_compatibility_manifest.json` (the Phase-3 compatibility contract). Do not hand-edit tool rows; regenerate from source.

## Overview

RedVector exposes **134** security-tool integrations under `/api/tools/*`. Of these, **55** have their command construction driven declaratively by a typed `SecurityToolSpec` in the `SecurityToolRegistry` (`redvector/security_tools.py`), and **79** remain explicit custom handlers whose behavior is not exactly representable by the declarative command model (multi-command orchestration, output parsers, file/temp artifacts, dynamic commands, or response-derived logic).

## Execution model

For a declarative tool, the Flask route delegates command construction to `SECURITY_TOOL_REGISTRY.build_command(name, params)`; the resulting command string is executed through the unchanged Phase-1 backend (`execute_command` -> `EnhancedCommandExecutor`). Command construction is a frozen compatibility contract: same executable, flags, order, quoting, defaults, and optional-argument inclusion as the original hand-written wrappers.

If an external binary is missing, the execution backend returns the tool's existing failure result/`stderr`; RedVector does not install dependencies and does not change exit-code handling.

## Execution backends

- `execute_command`: 125 integrations
- `none`: 6 integrations
- `recovery_toggle`: 3 integrations

## Declarative integrations (55)

| Tool | Route | Executable |
|---|---|---|
| `api_schema_analyzer` | `/api/tools/api_schema_analyzer` | `curl` |
| `binwalk` | `/api/tools/binwalk` | `binwalk` |
| `checkov` | `/api/tools/checkov` | `checkov` |
| `checksec` | `/api/tools/checksec` | `checksec` |
| `clair` | `/api/tools/clair` | `clairctl` |
| `cloudmapper` | `/api/tools/cloudmapper` | `cloudmapper` |
| `commix` | `/api/tools/commix` | `commix` |
| `dirb` | `/api/tools/dirb` | `dirb` |
| `dirsearch` | `/api/tools/dirsearch` | `dirsearch` |
| `dnsenum` | `/api/tools/dnsenum` | `dnsenum` |
| `dnsrecon` | `/api/tools/dnsrecon` | `dnsrecon` |
| `docker-bench-security` | `/api/tools/docker-bench-security` | `docker-bench-security` |
| `dotdotpwn` | `/api/tools/dotdotpwn` | `dotdotpwn` |
| `enum4linux` | `/api/tools/enum4linux` | `enum4linux` |
| `exiftool` | `/api/tools/exiftool` | `exiftool` |
| `feroxbuster` | `/api/tools/feroxbuster` | `feroxbuster` |
| `fierce` | `/api/tools/fierce` | `fierce` |
| `foremost` | `/api/tools/foremost` | `foremost` |
| `hashpump` | `/api/tools/hashpump` | `hashpump` |
| `httpx` | `/api/tools/httpx` | `httpx` |
| `jaeles` | `/api/tools/jaeles` | `jaeles` |
| `kube-bench` | `/api/tools/kube-bench` | `kube-bench` |
| `lazagne` | `/api/tools/lazagne` | `lazagne` |
| `linux-exploit-suggester` | `/api/tools/linux-exploit-suggester` | `linux-exploit-suggester.sh` |
| `masscan` | `/api/tools/masscan` | `masscan` |
| `nbtscan` | `/api/tools/nbtscan` | `nbtscan` |
| `nikto` | `/api/tools/nikto` | `nikto` |
| `nosqlmap` | `/api/tools/nosqlmap` | `nosqlmap` |
| `one-gadget` | `/api/tools/one-gadget` | `one_gadget` |
| `paramspider` | `/api/tools/paramspider` | `paramspider` |
| `prowler` | `/api/tools/prowler` | `prowler` |
| `pwninit` | `/api/tools/pwninit` | `pwninit` |
| `qsreplace` | `/api/tools/qsreplace` | `echo` |
| `responder` | `/api/tools/responder` | `timeout` |
| `ropgadget` | `/api/tools/ropgadget` | `ROPgadget` |
| `rustscan` | `/api/tools/rustscan` | `rustscan` |
| `searchsploit` | `/api/tools/searchsploit` | `searchsploit` |
| `smbmap` | `/api/tools/smbmap` | `smbmap` |
| `sqlmap` | `/api/tools/sqlmap` | `sqlmap` |
| `strings` | `/api/tools/strings` | `strings` |
| `subfinder` | `/api/tools/subfinder` | `subfinder` |
| `terrascan` | `/api/tools/terrascan` | `terrascan` |
| `theharvester` | `/api/tools/theharvester` | `theHarvester` |
| `trivy` | `/api/tools/trivy` | `trivy` |
| `uro` | `/api/tools/uro` | `echo` |
| `volatility` | `/api/tools/volatility` | `volatility` |
| `volatility3` | `/api/tools/volatility3` | `vol.py` |
| `wafw00f` | `/api/tools/wafw00f` | `wafw00f` |
| `waybackurls` | `/api/tools/waybackurls` | `waybackurls` |
| `wfuzz` | `/api/tools/wfuzz` | `wfuzz` |
| `whois` | `/api/tools/whois` | `whois` |
| `windows-exploit-suggester` | `/api/tools/windows-exploit-suggester` | `windows-exploit-suggester.py` |
| `wpscan` | `/api/tools/wpscan` | `wpscan` |
| `x8` | `/api/tools/x8` | `x8` |
| `xxd` | `/api/tools/xxd` | `xxd` |

## Custom-handler integrations (79)

Retained as explicit handlers (see `custom_behavior` in the manifest for the reason per tool).

| Tool | Route |
|---|---|
| `amass` | `/api/tools/amass` |
| `anew` | `/api/tools/anew` |
| `angr` | `/api/tools/angr` |
| `api_fuzzer` | `/api/tools/api_fuzzer` |
| `arjun` | `/api/tools/arjun` |
| `arp-scan` | `/api/tools/arp-scan` |
| `autorecon` | `/api/tools/autorecon` |
| `bloodhound-python` | `/api/tools/bloodhound-python` |
| `browser-agent` | `/api/tools/browser-agent` |
| `burpsuite-alternative` | `/api/tools/burpsuite-alternative` |
| `cctv-config-audit` | `/api/tools/cctv-config-audit` |
| `cctv-default-creds` | `/api/tools/cctv-default-creds` |
| `cctv-discovery` | `/api/tools/cctv-discovery` |
| `cctv-firmware-cve` | `/api/tools/cctv-firmware-cve` |
| `cctv-rtsp-probe` | `/api/tools/cctv-rtsp-probe` |
| `chisel` | `/api/tools/chisel` |
| `dalfox` | `/api/tools/dalfox` |
| `enum4linux-ng` | `/api/tools/enum4linux-ng` |
| `evil-winrm` | `/api/tools/evil-winrm` |
| `falco` | `/api/tools/falco` |
| `ffuf` | `/api/tools/ffuf` |
| `gau` | `/api/tools/gau` |
| `gdb` | `/api/tools/gdb` |
| `gdb-peda` | `/api/tools/gdb-peda` |
| `ghidra` | `/api/tools/ghidra` |
| `gobuster` | `/api/tools/gobuster` |
| `graphql_scanner` | `/api/tools/graphql_scanner` |
| `gtfobins-lookup` | `/api/tools/gtfobins-lookup` |
| `hakrawler` | `/api/tools/hakrawler` |
| `hashcat` | `/api/tools/hashcat` |
| `http-framework` | `/api/tools/http-framework` |
| `hydra` | `/api/tools/hydra` |
| `impacket-psexec` | `/api/tools/impacket-psexec` |
| `impacket-secretsdump` | `/api/tools/impacket-secretsdump` |
| `impacket-smbexec` | `/api/tools/impacket-smbexec` |
| `impacket-wmiexec` | `/api/tools/impacket-wmiexec` |
| `john` | `/api/tools/john` |
| `jwt_analyzer` | `/api/tools/jwt_analyzer` |
| `katana` | `/api/tools/katana` |
| `kerbrute` | `/api/tools/kerbrute` |
| `kube-hunter` | `/api/tools/kube-hunter` |
| `libc-database` | `/api/tools/libc-database` |
| `ligolo-ng` | `/api/tools/ligolo-ng` |
| `linpeas` | `/api/tools/linpeas` |
| `lolbas-lookup` | `/api/tools/lolbas-lookup` |
| `metasploit` | `/api/tools/metasploit` |
| `metasploit-search` | `/api/tools/metasploit-search` |
| `mimikatz` | `/api/tools/mimikatz` |
| `msfvenom` | `/api/tools/msfvenom` |
| `netexec` | `/api/tools/netexec` |
| `netexec-exec` | `/api/tools/netexec-exec` |
| `nmap` | `/api/tools/nmap` |
| `nmap-advanced` | `/api/tools/nmap-advanced` |
| `nuclei` | `/api/tools/nuclei` |
| `objdump` | `/api/tools/objdump` |
| `pacu` | `/api/tools/pacu` |
| `payload-staging` | `/api/tools/payload-staging` |
| `persistence-manager` | `/api/tools/persistence-manager` |
| `powersploit` | `/api/tools/powersploit` |
| `proxychains` | `/api/tools/proxychains` |
| `pspy` | `/api/tools/pspy` |
| `pwntools` | `/api/tools/pwntools` |
| `radare2` | `/api/tools/radare2` |
| `reverse-shell-generator` | `/api/tools/reverse-shell-generator` |
| `ropper` | `/api/tools/ropper` |
| `rpcclient` | `/api/tools/rpcclient` |
| `scout-suite` | `/api/tools/scout-suite` |
| `sherlock` | `/api/tools/sherlock` |
| `shodan` | `/api/tools/shodan` |
| `ssh-tunnel` | `/api/tools/ssh-tunnel` |
| `steghide` | `/api/tools/steghide` |
| `sudo-check` | `/api/tools/sudo-check` |
| `suid-finder` | `/api/tools/suid-finder` |
| `tcpdump` | `/api/tools/tcpdump` |
| `testssl` | `/api/tools/testssl` |
| `tshark` | `/api/tools/tshark` |
| `winpeas` | `/api/tools/winpeas` |
| `xsser` | `/api/tools/xsser` |
| `zap` | `/api/tools/zap` |

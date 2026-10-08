<div align="center">
  <img src="assets/Redvector-logo4.png" alt="RedVector" width="320"/>

  # RedVector

  AI-assisted security testing platform

  ![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
  ![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)
  ![REST API](https://img.shields.io/badge/API-Flask-black.svg)
  ![MCP Tools](https://img.shields.io/badge/MCP%20Tools-328-brightgreen.svg)
  ![Security Tools](https://img.shields.io/badge/Security%20Integrations-134-orange.svg)
  ![Use](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-red.svg)
</div>

## Overview

RedVector is an AI-assisted offensive security platform that connects AI clients such as Claude, ChatGPT, Cursor, and other MCP-compatible tools with a wide range of real-world cybersecurity tools for ethical hacking, penetration testing, red teaming, vulnerability discovery, security validation, and automated security workflows. RedVector also supports AI providers such as Ollama and DeepSeek through its provider integration layer.

RedVector puts a large set of security tools behind one API. It runs a Flask backend that exposes each tool as a REST route, and an MCP server so an AI assistant can call those tools directly. RedVector does not replace the tools; it runs the ones you have installed, passes your arguments through, and returns their output in a consistent shape.

Use it only against systems you are allowed to test.

## Why RedVector?

1. **One interface for many tools.** RedVector brings 134 security-tool integrations together behind a consistent API, so you drive them the same way instead of remembering each tool's flags.

2. **Built for AI workflows.** AI clients connect over MCP and use RedVector to run supported tools and read structured results.

3. **Structured configuration.** Tools and configuration are defined with typed specifications, which keeps the project easier to read, maintain, and extend.

4. **Simple AI setup.** The AI Integration Manager configures supported clients and providers for you, so you do not have to hand-edit JSON config files.

5. **For authorized testing.** RedVector is meant for penetration testing, security research, CTFs, labs, and other work where you have permission to test.

## How it works

1. Start the Flask backend (default `127.0.0.1:8888`).
2. Connect an AI client over MCP, or call the REST API directly.
3. Ask for a task you are authorized to run.
4. RedVector validates the request and routes it to the right integration.
5. The external tool runs on your host and RedVector returns the output.

## Architecture

```
AI client (Claude Desktop / Cursor / ChatGPT)
        |  MCP
        v
RedVector MCP (redvector_mcp.py)
        |  REST
        v
RedVector backend (redvector_server.py)  ->  security-tool integrations  ->  external tools
        |
        v
AI providers (Claude / Gemini / DeepSeek / Ollama)   used by RedVector
```

The MCP layer exposes 328 tools (171 generated from typed specs, 157 custom handlers). The security-tool layer has 134 integrations (55 with declarative command builders, 79 custom). See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## AI Integration

Keep two ideas separate:

- **MCP clients connect to RedVector.** Claude Desktop, Cursor, ChatGPT, and other MCP clients talk to RedVector as an MCP server.
- **AI providers are used by RedVector.** RedVector can call Claude, Gemini, DeepSeek, or a local Ollama model.

The AI Integration Manager sets up one-click MCP config for Claude Desktop and Cursor (with backup and rollback), and a guided flow for ChatGPT, which is configured in the ChatGPT app rather than a local file. See [docs/AI_INTEGRATION.md](docs/AI_INTEGRATION.md).

### Supported AI providers

| Provider | Type | API key | Model discovery |
|---|---|---|---|
| Ollama | local | no | yes |
| Claude (Anthropic) | cloud | yes | yes |
| Gemini (Google) | cloud | yes | yes |
| DeepSeek | cloud | yes | yes |

## Installation

```bash
git clone <your-fork-url> redvector
cd redvector
python -m venv .venv
# Linux/macOS: source .venv/bin/activate   |   Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Full guide: [docs/INSTALLATION.md](docs/INSTALLATION.md).

## Quick start

```bash
python redvector_server.py            # backend on 127.0.0.1:8888
curl http://127.0.0.1:8888/health     # check it is up
```

Connect an MCP client with `redvector_mcp.py` (see [docs/AI_INTEGRATION.md](docs/AI_INTEGRATION.md)).

## Configuration

Environment variables, defaults, and precedence are in [docs/CONFIGURATION.md](docs/CONFIGURATION.md). Defaults: host `127.0.0.1`, port `8888`.

## Security Tools Arsenal

**134 security-tool integrations covering 114 unique underlying tools**

RedVector runs the tools you have installed and returns their output in a consistent shape. Some tools are exposed through more than one integration (for example Nmap and the Impacket suite), and a few integrations are RedVector workflows built on top of these tools.

<details>
<summary>🔍 <strong>Network Reconnaissance & Scanning</strong></summary>

- **arp-scan** - Layer-2 host discovery
- **AutoRecon** - Multi-tool reconnaissance orchestration
- **Masscan** - High-speed internet-scale port scanning
- **nbtscan** - NetBIOS name scanning
- **Nmap** - Network discovery, port scanning, and service enumeration
- **Nmap (advanced)** - Nmap with NSE scripts and tuned timing
- **RustScan** - Fast port scanning
- **tcpdump** - Packet capture
- **TShark** - Packet capture and protocol analysis
- **wafw00f** - Web application firewall detection

</details>

<details>
<summary>🌐 <strong>Web Application Security</strong></summary>

- **anew** - Append-only new-line filtering for recon pipelines
- **Arjun** - HTTP parameter discovery
- **Browser agent** - Headless-browser page inspection
- **Commix** - Command injection testing
- **Dalfox** - XSS scanning and parameter analysis
- **dirb** - Directory brute forcing
- **dirsearch** - Web path discovery
- **DotDotPwn** - Path traversal fuzzing
- **feroxbuster** - Recursive content discovery
- **ffuf** - Fast web fuzzing
- **gau** - Fetch known URLs from public sources
- **Gobuster** - Directory, file, virtual-host, and DNS enumeration
- **hakrawler** - Fast web endpoint crawling
- **HTTP testing framework** - Scoped requests, repeater, and intruder-style testing
- **httpx** - HTTP probing and fingerprinting
- **Jaeles** - Signature-based web scanning
- **Katana** - Web crawling and endpoint discovery
- **Nikto** - Web server vulnerability scanning
- **NoSQLMap** - NoSQL injection testing
- **OWASP ZAP** - Web application security scanning
- **ParamSpider** - Parameter discovery from archived URLs
- **Proxy scanning workflow** - Interception-style request scanning (Burp-equivalent workflow)
- **qsreplace** - Query-string value rewriting
- **SQLMap** - Automated SQL injection testing
- **testssl.sh** - TLS/SSL configuration testing
- **uro** - URL list de-duplication and filtering
- **waybackurls** - Fetch historical URLs from the Wayback Machine
- **Wfuzz** - Web application fuzzing
- **WPScan** - WordPress security scanning
- **x8** - Hidden parameter discovery
- **XSSer** - Cross-site scripting testing

</details>

<details>
<summary>🛡️ <strong>Vulnerability Scanning</strong></summary>

- **Nuclei** - Template-based vulnerability scanning
- **SearchSploit** - Exploit-DB search
- **Shodan** - Internet exposure search (API)

</details>

<details>
<summary>🔌 <strong>API Security</strong></summary>

- **API fuzzer** - API endpoint fuzzing
- **API schema analyzer** - OpenAPI/schema review
- **GraphQL scanner** - GraphQL introspection and testing
- **JWT analyzer** - JSON Web Token inspection and weakness checks

</details>

<details>
<summary>🔑 <strong>Authentication & Password Security</strong></summary>

- **Hashcat** - GPU password hash cracking
- **HashPump** - Hash length-extension attacks
- **Hydra** - Network login brute forcing
- **John the Ripper** - Password hash auditing and recovery
- **Kerbrute** - Kerberos username and password testing

</details>

<details>
<summary>💥 <strong>Exploitation & Post-Exploitation</strong></summary>

- **Chisel** - TCP/UDP tunneling
- **Evil-WinRM** - WinRM remote shell
- **Ligolo-ng** - Tunneling and network pivoting
- **Metasploit Framework** - Exploitation framework
- **Metasploit module search** - Exploit/module lookup
- **Mimikatz** - Windows credential extraction
- **MSFvenom** - Payload generation
- **Payload staging** - Payload hosting and delivery
- **Persistence manager** - Host persistence techniques
- **PowerSploit** - PowerShell post-exploitation
- **ProxyChains** - Proxy routing for other tools
- **Responder** - LLMNR/NBT-NS poisoning and credential capture
- **Reverse shell generator** - Reverse shell payload generation
- **SSH tunneling** - SSH port forwarding

</details>

<details>
<summary>⬆️ <strong>Privilege Escalation</strong></summary>

- **GTFOBins lookup** - Unix binary abuse reference
- **LinPEAS** - Linux privilege-escalation enumeration
- **Linux Exploit Suggester** - Kernel exploit suggestions
- **LOLBAS lookup** - Windows living-off-the-land reference
- **pspy** - Unprivileged process monitoring
- **Sudo checker** - sudo misconfiguration checks
- **SUID finder** - SUID/SGID binary discovery
- **Windows Exploit Suggester** - Missing-patch exploit suggestions
- **WinPEAS** - Windows privilege-escalation enumeration

</details>

<details>
<summary>🪟 <strong>Active Directory & Windows Security</strong></summary>

- **BloodHound.py** - Active Directory data collection
- **enum4linux** - SMB/Samba enumeration
- **enum4linux-ng** - SMB/Samba enumeration (rewrite)
- **Impacket psexec** - Remote execution over SMB
- **Impacket secretsdump** - Credential and hash dumping
- **Impacket smbexec** - Remote execution over SMB
- **Impacket wmiexec** - Remote execution over WMI
- **NetExec** - Network protocol enumeration and attacks
- **NetExec (command execution)** - Remote command execution over SMB/WinRM
- **rpcclient** - MS-RPC enumeration
- **SMBMap** - SMB share enumeration

</details>

<details>
<summary>🧩 <strong>Binary Analysis & Reverse Engineering</strong></summary>

- **angr** - Symbolic execution and analysis
- **Binwalk** - Firmware and file carving analysis
- **checksec** - Binary hardening checks
- **GDB** - Binary debugging
- **GDB + PEDA** - Exploit-focused debugging
- **Ghidra** - Reverse engineering and decompilation
- **libc-database** - libc identification and lookup
- **objdump** - Disassembly and object inspection
- **one_gadget** - libc one-gadget search
- **pwninit** - pwn challenge setup
- **pwntools** - Exploit development toolkit
- **radare2** - Reverse engineering framework
- **ROPgadget** - ROP gadget search
- **Ropper** - ROP/JOP gadget search
- **strings** - Printable-string extraction
- **xxd** - Hex dumps

</details>

<details>
<summary>🧪 <strong>CTF & Forensics</strong></summary>

- **ExifTool** - Metadata extraction
- **Foremost** - File carving and recovery
- **LaZagne** - Local credential recovery
- **Steghide** - Steganography extraction
- **Volatility** - Memory forensics
- **Volatility 3** - Memory forensics (v3)

</details>

<details>
<summary>☁️ <strong>Cloud & Container Security</strong></summary>

- **Checkov** - Infrastructure-as-code scanning
- **Clair** - Container image vulnerability scanning
- **CloudMapper** - AWS environment analysis
- **Docker Bench Security** - Docker CIS benchmarking
- **Falco** - Runtime security monitoring
- **kube-bench** - Kubernetes CIS benchmarking
- **kube-hunter** - Kubernetes attack-surface scanning
- **Pacu** - AWS exploitation framework
- **Prowler** - AWS security assessment
- **Scout Suite** - Multi-cloud security auditing
- **Terrascan** - Infrastructure-as-code scanning
- **Trivy** - Container and filesystem vulnerability scanning

</details>

<details>
<summary>🕵️ <strong>OSINT & Reconnaissance</strong></summary>

- **Amass** - Subdomain enumeration and mapping
- **dnsenum** - DNS enumeration
- **DNSRecon** - DNS reconnaissance
- **Fierce** - DNS reconnaissance
- **Sherlock** - Username search across sites
- **Subfinder** - Passive subdomain discovery
- **theHarvester** - Email, host, and subdomain OSINT
- **whois** - Domain registration lookup

</details>

<details>
<summary>📹 <strong>CCTV & IoT Security</strong></summary>

- **CCTV config audit** - Camera configuration review
- **CCTV default credentials** - Default-credential checks for cameras
- **CCTV discovery** - Camera and NVR discovery
- **CCTV firmware CVE** - Camera firmware CVE mapping
- **CCTV RTSP probe** - RTSP stream probing

</details>

## How tools run

RedVector builds a command line for each external tool and runs the tool you installed. It does not bundle or install these tools. If a tool is missing, that integration returns a clear failure and the rest keep working. The tools remain under their own licenses.

## Platform support

Windows, macOS, and Linux. Which tools you can run depends on what you install on your system.

## Project structure

```
redvector/
  README.md  LICENSE  THIRD_PARTY_NOTICES.md  requirements.txt  .gitignore
  redvector_server.py          # Flask backend + routes
  redvector_mcp.py             # MCP server
  redvector_mcp_core.py        # MCP registry + transport
  redvector_mcp_declarative.py # declarative MCP tool generation
  redvector_security_tools.py  # security-tool registry + command builder
  redvector_config.py          # typed configuration
  redvector_ai_integration.py  # AI Integration Manager
  redvector_core.py  redvector_workflows.py  redvector_payloads.py
  redvector_cve_intelligence.py  redvector_error_handling.py  redvector_cache_process.py
  assets/   docs/
```

## Documentation

- [Installation](docs/INSTALLATION.md)
- [Architecture](docs/ARCHITECTURE.md)
- [AI Integration](docs/AI_INTEGRATION.md)
- [Configuration](docs/CONFIGURATION.md)
- [Security Tools](docs/SECURITY_TOOLS.md)
- [Security / Authorized Use](docs/SECURITY.md)

## Security and authorized use

Use RedVector only for security testing you are explicitly authorized to perform. You are responsible for following all applicable laws and for getting written permission before testing. The backend binds to `127.0.0.1` by default; set a strong `REDVECTOR_API_TOKEN` and add TLS and network controls before exposing it anywhere else. See [docs/SECURITY.md](docs/SECURITY.md).

## License

RedVector is distributed under the MIT License. See [LICENSE](LICENSE). RedVector includes original work along with portions derived from MIT-licensed upstream software; the applicable notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Author

Adam Karim.

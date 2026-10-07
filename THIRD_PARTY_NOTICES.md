# Third-Party Notices

RedVector includes original RedVector components and modifications, alongside portions derived from MIT-licensed upstream software. This file records the applicable notices. It is not promotional and makes no legal determination; where obligations are unclear, a legal review is advised.

---

## 1. RedVector original work

The following components are original RedVector implementation (typed/declarative architecture, configuration, and AI integration), authored for this project:

- `redvector_config.py` — typed configuration & startup model
- `redvector_mcp_core.py` — MCP registry + transport adapter
- `redvector_mcp_declarative.py` — declarative MCP tool generation
- `redvector_security_tools.py` — typed security-tool registry + command builder
- `redvector_ai_integration.py` — AI Integration Manager (providers + MCP clients)

These original contributions are licensed under the MIT License, Copyright (c) 2026 Adam Karim (see `LICENSE`).

## 2. Upstream-derived portions (HexStrike)

RedVector's security-tool server/MCP integration layer and several supporting modules (`redvector_server.py`, `redvector_mcp.py`, `redvector_core.py`, `redvector_workflows.py`, `redvector_payloads.py`, `redvector_error_handling.py`, and parts of `redvector_cve_intelligence.py`) contain substantial portions derived from the MIT-licensed **HexStrike** project. The upstream MIT copyright and permission notice is preserved here as required by that license:

```
HexStrike — https://github.com/0x4m4/hexstrike-ai

MIT License

Copyright (c) 2026 Muhammad Osama (0x4m4) <contact@0x4m4.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 3. Third-party Python dependencies

RedVector depends on the following packages, installed separately via `requirements.txt`. Each is distributed under its own license by its own authors; RedVector does not bundle their source. As standard pip dependencies, they do not require a source-notice to be embedded in this repository, but their licenses are recorded here for transparency.

| Package | Constraint | License | Source |
|---|---|---|---|
| Flask | >=2.3.0,<4.0.0 | BSD-3-Clause | PyPI |
| requests | >=2.31.0,<3.0.0 | Apache-2.0 | PyPI |
| psutil | >=5.9.0,<7.0.0 | BSD-3-Clause | PyPI |
| fastmcp | >=0.2.0,<1.0.0 | Apache-2.0 (verified via PyPI metadata) | PyPI |
| beautifulsoup4 | >=4.12.0,<5.0.0 | MIT | PyPI |
| selenium | >=4.15.0,<5.0.0 | Apache-2.0 | PyPI |
| webdriver-manager | >=4.0.0,<5.0.0 | Apache-2.0 | PyPI |
| aiohttp | >=3.8.0,<4.0.0 | Apache-2.0 (with contributor notices) | PyPI |
| mitmproxy | >=9.0.0,<11.0.0 | MIT | PyPI |
| keyring (optional) | not pinned | MIT | PyPI |

No GPL/AGPL/LGPL dependencies are declared. License identifiers are indicative; consult each package's distribution for authoritative terms.

## 4. External security tools (not bundled)

RedVector **invokes** external command-line security tools (e.g. nmap, nuclei, trivy, and others) that the user installs separately. These tools are not bundled, modified, or redistributed with RedVector; only their names appear, used to construct command-line invocations. Each tool is governed by its own license and terms of use, independent of RedVector.

## 5. Scope of these notices

- **Dependencies (Section 3):** installed with RedVector via pip; their licenses apply to those packages.
- **External tools (Section 4):** separate programs invoked at runtime; not part of RedVector's distributed code.
- **Upstream-derived source (Section 2):** MIT-licensed HexStrike code incorporated into RedVector's source; its notice is retained above.

RedVector's own original contributions are MIT-licensed (© 2026 Adam Karim). RedVector does not claim sole ownership of the upstream-derived portions; those remain under the HexStrike MIT notice above.

# Third-Party Notices

RedVector AI is distributed under the MIT License (see `LICENSE`). It includes,
and is derived in part from, the third-party software listed below. Each
component remains under its own license and copyright; those terms are
reproduced here in full.

This file and `LICENSE` carry the same third-party attribution; the source
headers of `redvector_mcp.py` and `redvector_server.py` point to both.

---

## HexStrike AI

RedVector is based in part on and contains work derived from **HexStrike AI**.

- Upstream project: https://github.com/0x4m4/hexstrike-ai
- License: MIT

```
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

---

## Runtime dependencies

RedVector's Python runtime dependencies (declared in `requirements.txt`, e.g.
Flask, requests, psutil, and the official `mcp` SDK) are **not vendored** in this
distribution. They are installed separately from their respective package
indexes and remain governed by their own licenses as published by their
maintainers. No third-party dependency source is bundled in the RedVector
release package.

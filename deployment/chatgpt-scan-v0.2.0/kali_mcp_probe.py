#!/usr/bin/env python3
"""Read-only post-install verification probe for RedVector Scan Plugin v0.2.0-dev.

Runs on Kali AFTER the development plugin files are in place. It drives the
plugin's stdio adapter directly (the same binary ChatGPT Desktop launches) to
verify, WITHOUT performing any network scan:

  * MCP initialize + tool discovery == exactly the 4 expected tools,
  * the three diagnostics operate (and report live backend reachability),
  * an out-of-scope scan_tcp_ports request is REJECTED before any backend call,
  * scan_tcp_ports is present and ready for a (separately approved) IP-only test.

It performs NO scan, starts no service, needs no API token, follows no redirect,
and only reads /health via the diagnostics. Backend host/port come from the
environment (REDVECTOR_HOST / REDVECTOR_PORT). Usage:

    python3 kali_mcp_probe.py /path/to/redvector_scan_adapter.py

Exit code 0 only if every structural check passes.
"""
import json
import os
import subprocess
import sys
import time

ADAPTER = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("RV_ADAPTER", "")
if not ADAPTER or not os.path.isfile(ADAPTER):
    print("ERROR: pass the adapter path: python3 kali_mcp_probe.py /path/to/redvector_scan_adapter.py")
    sys.exit(2)

PYEXE = sys.executable
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(bool(ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" :: {detail}" if detail else ""))


def drive(lines, extra_env=None, timeout=20):
    env = dict(os.environ)
    # Negative-scan isolation vars are set per call; clear any inherited ones.
    for k in ("REDVECTOR_SCAN_SCOPE", "REDVECTOR_SCAN_SCOPE_FILE",
              "REDVECTOR_API_TOKEN", "REDVECTOR_SCAN_ALLOW_HOSTNAMES"):
        env.pop(k, None)
    if extra_env:
        env.update({k: str(v) for k, v in extra_env.items()})
    stdin = "".join(l + "\n" for l in lines)
    p = subprocess.run([PYEXE, ADAPTER], input=stdin, env=env,
                       capture_output=True, text=True, timeout=timeout)
    out = []
    for ln in p.stdout.splitlines():
        ln = ln.strip()
        if ln:
            try:
                out.append(json.loads(ln))
            except ValueError:
                pass
    return {r.get("id"): r for r in out if isinstance(r, dict)}, p.stdout


def rpc(i, method, params=None):
    m = {"jsonrpc": "2.0", "id": i, "method": method}
    if params is not None:
        m["params"] = params
    return json.dumps(m)


def sc(resp):
    return (resp or {}).get("result", {}).get("structuredContent")


print("== adapter:", ADAPTER)
print("== backend:", os.environ.get("REDVECTOR_HOST", "127.0.0.1"),
      "port", os.environ.get("REDVECTOR_PORT", "(unset)"))

# 1) discovery + diagnostics (read-only; diagnostics may hit live /health)
m, _ = drive([
    rpc(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}}),
    rpc(2, "tools/list"),
    rpc(3, "tools/call", {"name": "backend_health"}),
    rpc(4, "tools/call", {"name": "service_status"}),
    rpc(5, "tools/call", {"name": "backend_version"}),
])
info = m.get(1, {}).get("result", {}).get("serverInfo", {})
tools = m.get(2, {}).get("result", {}).get("tools", [])
names = sorted(t.get("name") for t in tools)
check("initialize ok (serverInfo present)", bool(info), str(info))
check("exactly 4 tools discovered", names == ["backend_health", "backend_version",
      "scan_tcp_ports", "service_status"], str(names))
check("scan_tcp_ports present & ready", "scan_tcp_ports" in names)
bh, ss, bv = sc(m.get(3)), sc(m.get(4)), sc(m.get(5))
check("backend_health operates (well-formed)", isinstance(bh, dict) and "available" in bh, str(bh))
check("service_status operates (well-formed)", isinstance(ss, dict) and "configured" in ss, str(ss))
check("backend_version operates (well-formed)", isinstance(bv, dict) and "version" in bv, str(bv))
print("    --> backend reachable:", bool(bh and bh.get("available")),
      "| version:", (bv or {}).get("version"))

# 2) NEGATIVE scan: out-of-scope target must be rejected BEFORE any backend call.
m2, _ = drive([rpc(1, "tools/call", {"name": "scan_tcp_ports",
              "arguments": {"target": "203.0.113.9", "authorized": True}})],
              {"REDVECTOR_SCAN_SCOPE": "192.0.2.0/24", "REDVECTOR_API_TOKEN": "probe-nonlive"})
r = sc(m2.get(1))
check("out-of-scope scan rejected", r and r.get("status") == "rejected" and r.get("category") == "scope", str(r))
check("no backend request issued for rejected scan",
      r and r.get("evidence") == "no-backend-request", str(r and r.get("evidence")))

# 3) NEGATIVE scan: missing authorization also rejected without backend.
m3, _ = drive([rpc(1, "tools/call", {"name": "scan_tcp_ports",
              "arguments": {"target": "192.0.2.10"}})],
              {"REDVECTOR_SCAN_SCOPE": "192.0.2.0/24", "REDVECTOR_API_TOKEN": "probe-nonlive"})
r3 = sc(m3.get(1))
check("unauthorized scan rejected (no backend)",
      r3 and r3.get("category") == "authorization" and r3.get("evidence") == "no-backend-request", str(r3))

# 4) hostname disabled by default (IP-only) - no scan performed
m4, _ = drive([rpc(1, "tools/call", {"name": "scan_tcp_ports",
              "arguments": {"target": "localhost", "authorized": True}})],
              {"REDVECTOR_SCAN_SCOPE": "127.0.0.0/8 localhost", "REDVECTOR_API_TOKEN": "probe-nonlive"})
r4 = sc(m4.get(1))
check("hostname target disabled by default (IP-only)",
      r4 and r4.get("category") == "policy", str(r4))

print("\n== SUMMARY ==")
passed = sum(1 for ok in RESULTS if ok)
print(f"{passed}/{len(RESULTS)} structural checks passed  (NO scan performed)")
sys.exit(0 if passed == len(RESULTS) else 1)

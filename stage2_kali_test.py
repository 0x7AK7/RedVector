#!/usr/bin/env python3
"""Stage 2 (Kali) isolated runtime test for RedVector Diagnostic Plugin v0.1.

Result categories are labelled explicitly:
  [KALI-ADAPTER]  adapter runtime on this machine (protocol / allowlist / errors)
  [VERIFIED-BACKEND]  read-only GET /health against a RUNNING, IDENTIFIED RedVector backend
  [MOCK]  throwaway loopback fixture - proves HTTP logic only, NOT the real backend

Safety (read-only):
  * Runs ONLY the isolated diagnostic adapter as a separate process (never imports it,
    never runs start_redvector.sh or redvector_mcp.py, never any offensive tool).
  * Never starts, stops, restarts or modifies the RedVector backend.
  * All connections it makes itself are loopback-validated; non-loopback is refused.
  * Installs nothing, writes/deletes no files, changes no configuration.
  * Backend host/port come from REDVECTOR_HOST / REDVECTOR_PORT (no hardcoding).
  * A live connection is reported "VERIFIED" only after the /health response
    structure AND the RedVector application identity are confirmed.

Usage:
    export REDVECTOR_PORT=<running backend port>        # omit to skip the live test
    python3 stage2_kali_test.py [PLUGIN_DIR] [SHA256SUMS]
      PLUGIN_DIR  default: ~/redvector-diagnostic-plugin
      SHA256SUMS  optional: Stage-1 source manifest to re-verify before running
"""
import hashlib, ipaddress, json, os, socket, subprocess, sys, threading, time, pathlib
import urllib.request, urllib.error
from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, HTTPServer

PLUGIN_DIR = pathlib.Path(sys.argv[1] if len(sys.argv) > 1
                          else os.path.expanduser("~/redvector-diagnostic-plugin"))
ADAPTER = PLUGIN_DIR / "adapter" / "redvector_diag_adapter.py"
PY = sys.executable or "python3"
FILES = ["adapter/redvector_diag_adapter.py", "mcp.json", "plugin.json", "README.md", "SECURITY-REVIEW.md"]

if not ADAPTER.is_file():
    sys.exit(f"adapter not found: {ADAPTER} (extract the Stage-1 ZIP first)")


def _sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(65536), b""):
            h.update(b)
    return h.hexdigest()


# ---- Point 8: checksum pre-check (fail-closed) OR explicit prerequisite notice ----
sums_path = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else (
    pathlib.Path(os.environ["SHA256SUMS"]) if os.environ.get("SHA256SUMS") else None)
if sums_path and sums_path.is_file():
    want = {}
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and "  " in line:
            digest, rel = line.split("  ", 1)
            want[rel.strip()] = digest.strip()
    bad = []
    for rel in FILES:
        fp = PLUGIN_DIR / rel
        if not fp.is_file() or rel not in want or _sha256(fp) != want[rel]:
            bad.append(rel)
    if bad:
        sys.exit(f"CHECKSUM MISMATCH/MISSING (fail-closed): {bad}")
    print("[OK] package checksums match Stage-1 SHA256SUMS\n")
else:
    print("PREREQUISITE: no SHA256SUMS supplied - run the Stage-1 check "
          "(`sha256sum -c SHA256SUMS`) before trusting these results.\n")


def _is_loopback(host):
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def run_adapter(lines, env_extra=None, timeout=15):
    env = dict(os.environ)
    for k in ("REDVECTOR_HOST", "REDVECTOR_PORT", "REDVECTOR_DIAG_TIMEOUT"):
        env.pop(k, None)
    if env_extra:
        env.update({k: str(v) for k, v in env_extra.items()})
    data = "".join(l + "\n" for l in lines)
    t0 = time.time()
    try:
        p = subprocess.run([PY, str(ADAPTER)], input=data, env=env,
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        # Point 9: hung adapter is handled, not crashed.
        return [{"_timeout": True}], time.time() - t0
    out = []
    for ln in p.stdout.splitlines():
        ln = ln.strip()
        if ln:
            try:
                out.append(json.loads(ln))
            except ValueError:
                out.append({"_raw": ln})
    return out, time.time() - t0


def by_id(r):
    return {x.get("id"): x for x in r if isinstance(x, dict)}


def payload(r):
    return r.get("result", {}).get("structuredContent") if r and "result" in r else None


R = []
def check(name, ok, detail=""):
    R.append(bool(ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" :: {detail}" if detail else ""))


print(f"adapter : {ADAPTER}")
print(f"python  : {PY}  ({sys.version.split()[0]})")
print(f"host    : {' '.join(os.uname()) if hasattr(os, 'uname') else sys.platform}\n")

print("===== A. [KALI-ADAPTER] PROTOCOL / ALLOWLIST / ERROR HANDLING =====")
reqs = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "evil_tool"}},
    {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "backend_health; rm -rf /"}},
    {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {}},
    {"jsonrpc": "2.0", "id": 7, "method": "ping"},
    {"jsonrpc": "2.0", "id": 8, "method": "no/such/method"},
]
lines = [json.dumps(x) for x in reqs] + ["{ not valid json", json.dumps({"jsonrpc": "2.0", "id": 6, "result": {}})]
resp, _ = run_adapter(lines, {"REDVECTOR_HOST": "127.0.0.1", "REDVECTOR_PORT": 9})
m = by_id(resp)
t = m.get(2, {}).get("result", {}).get("tools", [])
names = sorted(x.get("name") for x in t)
check("initialize serverInfo", m.get(1, {}).get("result", {}).get("serverInfo", {}).get("name") == "redvector-diagnostics")
check("tools/list == exactly the three approved tools", names == ["backend_health", "backend_version", "service_status"], str(names))
check("all tools readOnlyHint:true", all(x.get("annotations", {}).get("readOnlyHint") is True for x in t))
check("unknown tool rejected (-32601)", m.get(3, {}).get("error", {}).get("code") == -32601)
check("shell-metachar name rejected", m.get(4, {}).get("error", {}).get("code") == -32601)
check("missing name rejected", m.get(5, {}).get("error", {}).get("code") == -32601)
check("malformed JSON -> parse error (-32700,null)", any(x.get("id") is None and x.get("error", {}).get("code") == -32700 for x in resp))
check("method-less message ignored (no id-6 reply)", 6 not in m)
check("ping -> {}", m.get(7, {}).get("result") == {})
check("unknown method -> -32601", m.get(8, {}).get("error", {}).get("code") == -32601)

print("\n===== B. [KALI-ADAPTER] NOT CONFIGURED / NON-LOOPBACK REFUSAL =====")
resp, _ = run_adapter([json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "backend_health"}})],
                      {"REDVECTOR_HOST": "127.0.0.1"})
check("no REDVECTOR_PORT -> 'not configured'", "not configured" in (payload(by_id(resp).get(1)) or {}).get("detail", ""))
resp, el = run_adapter([json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "backend_health"}})],
                       {"REDVECTOR_HOST": "8.8.8.8", "REDVECTOR_PORT": 80})
ph = payload(by_id(resp).get(1)) or {}
check("non-loopback refused, no round-trip (<2s)", ph.get("available") is False and "refused" in ph.get("detail", "") and el < 2.0, f"{ph} {el:.2f}s")

print("\n===== C. [VERIFIED-BACKEND] live read-only /health (only if running AND identified) =====")
live_host = os.environ.get("REDVECTOR_HOST", "127.0.0.1")
live_port = os.environ.get("REDVECTOR_PORT", "")
if not live_port.isdigit():
    print("SKIPPED: REDVECTOR_PORT not set. (Export it to a running backend's port for live results.)")
elif not _is_loopback(live_host):
    print(f"REFUSED: REDVECTOR_HOST='{live_host}' is not loopback; live test does not contact non-loopback hosts.")
else:
    lp = int(live_port)
    up = False
    try:
        with socket.create_connection((live_host, lp), timeout=1):
            up = True
    except OSError:
        up = False
    if not up:
        print(f"SKIPPED: nothing listening on {live_host}:{lp}. (The backend was NOT started by this test.)")
    else:
        # Point 11: confirm structure + RedVector identity via a loopback-only,
        # no-redirect GET /health before claiming a verified backend.
        identity_ok, ident_detail, data = False, "", None
        url = "http://{0}:{1}/health".format("[%s]" % live_host if ":" in live_host else live_host, lp)
        if _is_loopback(urlsplit(url).hostname or ""):
            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **k):
                    return None
            try:
                with urllib.request.build_opener(_NoRedirect).open(
                        urllib.request.Request(url, method="GET"), timeout=3) as rsp:
                    code = getattr(rsp, "status", None) or rsp.getcode()
                    body = rsp.read(65536).decode("utf-8", "replace")
                data = json.loads(body) if body else None
                if code == 200 and isinstance(data, dict) \
                        and isinstance(data.get("version"), str) and data.get("version") \
                        and "status" in data \
                        and "redvector" in str(data.get("message", "")).lower():
                    identity_ok = True
                    ident_detail = f"version={data.get('version')} status={data.get('status')}"
                else:
                    ident_detail = "a service responded but did NOT match the RedVector /health identity"
            except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, OSError, ValueError) as e:
                ident_detail = f"health probe failed: {type(e).__name__}"
        else:
            ident_detail = "assembled URL was not loopback"

        if not identity_ok:
            print(f"NOT VERIFIED: {ident_detail}. Not reporting a RedVector connection.")
        else:
            resp, _ = run_adapter([
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "backend_health"}}),
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "backend_version"}}),
                json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "service_status"}}),
            ], {"REDVECTOR_HOST": live_host, "REDVECTOR_PORT": lp})
            m = by_id(resp)
            print(f"IDENTITY CONFIRMED (RedVector): {ident_detail}")
            print("  [VERIFIED-BACKEND] backend_health :", payload(m.get(1)))
            print("  [VERIFIED-BACKEND] backend_version:", payload(m.get(2)))
            print("  [VERIFIED-BACKEND] service_status :", payload(m.get(3)))

print("\n===== D. [MOCK] loopback fixture - proves HTTP logic only, NOT the backend =====")
class Mock(BaseHTTPRequestHandler):
    mode = "healthy"
    def log_message(self, *a):
        pass
    def do_GET(self):
        if self.path != "/health":
            self.send_response(404); self.end_headers(); return
        if Mock.mode == "redirect":
            self.send_response(302); self.send_header("Location", "http://8.8.8.8/"); self.end_headers(); return
        if Mock.mode == "slow":
            time.sleep(3)
        b = json.dumps({"status": "healthy", "message": "mock", "version": "9.9.9-mock", "uptime": 1}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

srv = HTTPServer(("127.0.0.1", 0), Mock)
mport = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
try:
    Mock.mode = "healthy"
    resp, _ = run_adapter([json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "backend_version"}})],
                          {"REDVECTOR_HOST": "127.0.0.1", "REDVECTOR_PORT": mport})
    check("[MOCK] reads running version from /health", (payload(by_id(resp).get(1)) or {}).get("version") == "9.9.9-mock")
    Mock.mode = "redirect"
    resp, _ = run_adapter([json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "backend_health"}})],
                          {"REDVECTOR_HOST": "127.0.0.1", "REDVECTOR_PORT": mport})
    ph = payload(by_id(resp).get(1)) or {}
    check("[MOCK] redirect NOT followed (302, not healthy)", ph.get("available") is False and ph.get("http_status") == 302)
    Mock.mode = "slow"
    resp, el = run_adapter([json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "backend_health"}})],
                           {"REDVECTOR_HOST": "127.0.0.1", "REDVECTOR_PORT": mport, "REDVECTOR_DIAG_TIMEOUT": 1})
    check("[MOCK] slow backend times out gracefully (<3s)", (payload(by_id(resp).get(1)) or {}).get("available") is False and el < 3.0, f"{el:.2f}s")
finally:
    srv.shutdown()

print(f"\n===== SUMMARY: {sum(R)}/{len(R)} asserted checks passed =====")
print("Only the [VERIFIED-BACKEND] section (if present and identity-confirmed) reflects the real")
print("RedVector backend. [KALI-ADAPTER] = adapter runtime; [MOCK] = loopback fixture, not the backend.")
sys.exit(0 if all(R) else 1)

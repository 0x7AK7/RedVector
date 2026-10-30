"""W6 native acceptance (VMware Kali). Skipped unless native Linux and REDVECTOR_RUN_SMOKE=1.

These tests run the REAL installed binaries against owned loopback listeners (and, only when the
operator sets RV_LAB_TARGET, against that authorized lab host). They are the evidence required before
an engine is enabled; Windows mocks never substitute for them. Nothing here changes production
configuration: a Nuclei candidate build is exercised via a test-local registry entry built from the
operator-supplied expected SHA256 (REDVECTOR_NUCLEI_CANDIDATE_SHA256), never registered in product code.
No production target, tool version or absolute path is hardcoded."""
import hashlib
import http.server
import os
import shutil
import socket
import subprocess
import sys
import threading
import pytest

NATIVE = sys.platform.startswith("linux") and os.environ.get("REDVECTOR_RUN_SMOKE") == "1"
pytestmark = pytest.mark.skipif(not NATIVE, reason="Requires native Linux (VMware Kali) and REDVECTOR_RUN_SMOKE=1")
LAB = os.environ.get("RV_LAB_TARGET", "")


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


@pytest.fixture
def http_listener(tmp_path):
    handler = lambda *a, **k: _Quiet(*a, directory=str(tmp_path), **k)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()


@pytest.fixture
def tcp_listener():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0)); srv.listen(16); srv.settimeout(0.5)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = srv.accept(); conn.close()
            except (socket.timeout, OSError):
                pass
    thread = threading.Thread(target=serve, daemon=True); thread.start()
    yield srv.getsockname()[1]
    stop.set(); srv.close()


# ---- N0: full-range native Nmap discovery, then <=128-port service batches -----------------------

def test_full_range_discovery_then_service_batch(tcp_listener):
    import redvector_reviewed_profiles as prof
    out = prof.run_discovery("nmap_scan", {"target": "127.0.0.1", "ports": "1-65535",
                                           "scan_type": prof.DISCOVERY_PROFILE, "additional_args": "", "use_recovery": False})
    assert out["success"], out.get("error")
    rp = out["reviewed_profile"]
    assert rp["ports_count"] == 65535 and rp["coverage"]["completed"] == 65535 and rp["coverage"]["scan_complete"]
    assert rp["binary"] and rp["runtime_sha256"]
    open_ports = sorted(int(p["port"]) for p in out["parsed"]["open_ports"])
    assert tcp_listener in open_ports
    batch = ",".join(str(p) for p in open_ports[:128])
    svc = prof.run_profile("nmap_scan", {"target": "127.0.0.1", "ports": batch, "scan_type": prof.NMAP_PROFILE,
                                         "additional_args": "--version-intensity 1", "use_recovery": False})
    assert svc["success"], svc.get("error")
    print("\nNMAP binary:", rp["binary"], "version:", rp.get("version"), "sha256:", rp["runtime_sha256"])


# ---- N1: Nuclei candidate build (validated, NOT enabled) -----------------------------------------

def test_nuclei_candidate_build_validation(http_listener):
    expected = os.environ.get("REDVECTOR_NUCLEI_CANDIDATE_SHA256", "").lower()
    if not expected:
        pytest.skip("Set REDVECTOR_NUCLEI_CANDIDATE_SHA256 to the operator-reported SHA256 of the installed nuclei")
    path = shutil.which("nuclei")
    assert path, "nuclei not on PATH"
    real = os.path.realpath(path)
    assert _sha256(real) == expected, "installed nuclei differs from the operator-reported SHA256"
    verify = subprocess.run(["dpkg", "-V", "nuclei"], capture_output=True, text=True)
    assert verify.returncode == 0 and not verify.stdout.strip(), "dpkg -V reports modified package files: " + verify.stdout
    package = subprocess.run(["dpkg-query", "-W", "-f=${Version}", "nuclei"], capture_output=True, text=True).stdout.strip()
    import redvector_reviewed_assessment as ra
    banner = subprocess.run([real, "-version"], capture_output=True, timeout=30)
    detected = ra.nuclei_version(banner.stdout + banner.stderr)
    assert detected, "could not read nuclei -version"
    # Exercise the fixed offline header profile with a TEST-LOCAL registry entry for this exact build.
    candidate = {expected: {"version": detected, "platform": "linux/amd64", "capabilities": ["offline-root-response-header-templates"],
                            "template_requirements": "fixed reviewed templates", "evidence": "native acceptance candidate"}}
    old_builds, old_env = dict(ra.NUCLEI_BUILDS), os.environ.get("REDVECTOR_NUCLEI_BIN")
    ra.NUCLEI_BUILDS.clear(); ra.NUCLEI_BUILDS.update(candidate); os.environ["REDVECTOR_NUCLEI_BIN"] = real
    try:
        assert ra.capabilities()[ra.NUCLEI_PROFILE]["state"] == "Ready"
        targets = ["http://127.0.0.1:" + str(http_listener) + "/"]
        if LAB:
            targets.append("http://" + LAB + ":" + os.environ.get("RV_LAB_HTTP_PORT", "80") + "/")
        for url in targets:
            out = ra.run_nuclei({"target": url, "severity": "", "tags": "", "template": ra.NUCLEI_PROFILE,
                                 "additional_args": "", "use_recovery": False})
            assert out["success"], (url, out.get("error"))
            assert out["scanner"]["sha256"] == expected
    finally:
        ra.NUCLEI_BUILDS.clear(); ra.NUCLEI_BUILDS.update(old_builds)
        if old_env is None:
            os.environ.pop("REDVECTOR_NUCLEI_BIN", None)
        else:
            os.environ["REDVECTOR_NUCLEI_BIN"] = old_env
    print("\nNUCLEI candidate:", real, "package", package, "detected", detected, "sha256", expected)


# ---- N2: native Nikto adapter (verified before wiring) -------------------------------------------

def test_native_nikto_adapter(http_listener):
    import redvector_reviewed_nikto as nk
    assert nk.capabilities()[nk.PROFILE]["state"] == "Ready", nk.capabilities()
    targets = ["http://127.0.0.1:" + str(http_listener) + "/"]
    if LAB:
        targets.append("http://" + LAB + ":" + os.environ.get("RV_LAB_HTTP_PORT", "80") + "/")
    for url in targets:
        out = nk.run_nikto({"target": url, "additional_args": nk.NIKTO_MARKER})
        assert out["execution_mode"] == "A", (url, out.get("error"))
        assert out["binary"] and out["runtime_sha256"]
        assert isinstance(out["parsed"]["findings"], list)
        print("\nNIKTO", url, "binary", out["binary"], "findings", out["findings_count"], "rc", out["return_code"])


# ---- N3: native Searchsploit (offline, read-only) -------------------------------------------------

def test_native_searchsploit_lookup():
    import redvector_reviewed_searchsploit as ss
    assert ss.capabilities()[ss.PROFILE]["state"] == "Ready", ss.capabilities()
    out = ss.run_searchsploit({"query": "OpenSSH", "additional_args": ss.SEARCHSPLOIT_MARKER})
    assert out["execution_mode"] == "A", out.get("error")
    assert out["binary"] and out["results_count"] >= 1
    import redvector_cve_correlation as corr
    # references are leads, never proof: correlation never yields a validated class
    applic = corr.exploit_reference_applicability("OpenSSH", "", out["parsed"]["results"][0]["title"])
    assert applic in ("candidate", "applicable", "not_applicable")
    print("\nSEARCHSPLOIT binary", out["binary"], "results", out["results_count"])

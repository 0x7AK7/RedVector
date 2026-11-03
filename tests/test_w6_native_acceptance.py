"""W6 native acceptance (VMware Kali). Skipped unless native Linux and REDVECTOR_RUN_SMOKE=1.

These tests run the REAL installed binaries against owned loopback listeners (and, only when the
operator sets RV_LAB_TARGET, against that authorized lab host). They are the evidence required before
an engine is enabled; Windows mocks never substitute for them. Nothing here changes production
configuration: a Nuclei candidate build is exercised via a test-local registry entry built from the
operator-supplied expected SHA256 (REDVECTOR_NUCLEI_CANDIDATE_SHA256), never registered in product code.
No production target, tool version or absolute path is hardcoded."""
import hashlib
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
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

    def handle_one_request(self):
        # Nikto probes paths with embedded null bytes; os.path.join() raises ValueError in
        # translate_path() when it encounters them.  Catch here so the server thread survives.
        try:
            super().handle_one_request()
        except (ValueError, UnicodeDecodeError):
            try:
                self.send_error(400)
            except Exception:
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
    """Validate a candidate Nuclei build through the real subprocess execution path.

    Requires two env vars set by the operator before invoking pytest:
      REDVECTOR_NUCLEI_CANDIDATE_SHA256=<sha256 of installed /usr/bin/nuclei>
      REDVECTOR_NUCLEI_ALLOW_CANDIDATE=testing   (explicit test-mode gate)

    Design: the production API (capabilities(), run_nuclei()) is intentionally blocked for
    unregistered candidate builds — that is the correct production behaviour and is asserted here.
    The subprocess execution path is tested directly via ra._command() so that the binary's real
    execution through the seccomp sandbox and offline template restrictions is verified without
    touching production-facing assessment functions.
    """
    expected = os.environ.get("REDVECTOR_NUCLEI_CANDIDATE_SHA256", "").lower()
    if not expected:
        pytest.skip("Set REDVECTOR_NUCLEI_CANDIDATE_SHA256 to the SHA256 of the installed nuclei binary")
    if os.environ.get("REDVECTOR_NUCLEI_ALLOW_CANDIDATE") != "testing":
        pytest.skip("Set REDVECTOR_NUCLEI_ALLOW_CANDIDATE=testing to enable the candidate test-mode gate")
    path = shutil.which("nuclei")
    assert path, "nuclei not on PATH"
    real = os.path.realpath(path)
    assert _sha256(real) == expected, "installed nuclei SHA differs from REDVECTOR_NUCLEI_CANDIDATE_SHA256"
    verify = subprocess.run(["dpkg", "-V", "nuclei"], capture_output=True, text=True)
    assert verify.returncode == 0 and not verify.stdout.strip(), "dpkg -V reports modified files: " + verify.stdout
    package = subprocess.run(["dpkg-query", "-W", "-f=${Version}", "nuclei"], capture_output=True, text=True).stdout.strip()
    import redvector_reviewed_assessment as ra
    binary = Path(real)

    old_bin = os.environ.get("REDVECTOR_NUCLEI_BIN")
    os.environ["REDVECTOR_NUCLEI_BIN"] = real
    try:
        # 1. Production API must refuse an unregistered binary — this is the correct behaviour.
        cap = ra.capabilities()[ra.NUCLEI_PROFILE]
        assert cap["state"] != "Ready", (
            "Production capabilities must NOT report Ready for an unregistered candidate binary. "
            "Add the binary to NUCLEI_BUILDS with mode-A evidence before production use. state=" + cap["state"]
        )

        # 2. Test the subprocess execution path directly via ra._command().
        #    _env() propagates CANDIDATE_SHA256 only because ALLOW_CANDIDATE=testing is set;
        #    the subprocess __main__ then validates the SHA and execv's the binary.
        #    No production-facing function (capabilities / run_nuclei) is called from here on.

        # Step 2a: subprocess must accept and execute -version
        with tempfile.TemporaryDirectory(prefix="rv-cand-v-") as d:
            result = ra._command(binary, ["-version"], Path(d))
            assert result.returncode == 0, (
                "Subprocess rejected or failed to execute candidate binary. "
                "stderr: " + (result.stderr.decode("utf-8", "replace") if result.stderr else "")[:300]
            )
            detected = ra.nuclei_version(result.stdout + result.stderr)
            assert detected, "Could not read version from candidate nuclei binary"

        # Step 2b: subprocess must run the offline header template scan within the seccomp sandbox
        targets = ["http://127.0.0.1:" + str(http_listener) + "/"]
        if LAB:
            targets.append("http://" + LAB + ":" + os.environ.get("RV_LAB_HTTP_PORT", "80") + "/")
        for url in targets:
            captured = ra.fetch(url)
            with tempfile.TemporaryDirectory(prefix="rv-cand-scan-") as d:
                directory = Path(d)
                responses = directory / "responses"; responses.mkdir()
                header_input = captured["raw"].split("\r\n", 1)[0] + "\r\n"
                for key, value in captured["headers"].items():
                    if key.lower() not in {"transfer-encoding", "content-encoding", "content-length", "trailer", "connection"}:
                        header_input += key + ": " + value + "\r\n"
                header_input += "Content-Length: 0\r\n\r\n"
                (responses / "response.txt").write_text(header_input, encoding="utf-8")
                templates_dir = directory / "templates"; templates_dir.mkdir()
                for ident, header in [("rv-missing-nosniff", "X-Content-Type-Options"),
                                       ("rv-missing-frame-options", "X-Frame-Options")]:
                    (templates_dir / (ident + ".yaml")).write_text(ra.template(ident, header), encoding="utf-8")
                result = ra._command(binary, [
                    "-passive", "-u", str(responses), "-t", str(templates_dir),
                    "-ni", "-duc", "-dr", "-nh", "-no-stdin", "-jsonl", "-silent",
                    "-nc", "-omit-raw", "-c", "1", "-bs", "1", "-timeout", "3", "-retries", "0"
                ], directory)
                assert result.returncode == 0, (
                    "Offline scan failed for " + url + ". "
                    "stderr: " + (result.stderr.decode("utf-8", "replace") if result.stderr else "")[:300]
                )
                # Output must contain only the two allowed template IDs (template allowlist enforced)
                for line in result.stdout.decode("utf-8", "strict").splitlines():
                    item = json.loads(line)
                    ident = item.get("template-id")
                    assert ident in ("rv-missing-nosniff", "rv-missing-frame-options"), (
                        "Unexpected template in candidate scan output: " + str(ident)
                    )
    finally:
        if old_bin is None:
            os.environ.pop("REDVECTOR_NUCLEI_BIN", None)
        else:
            os.environ["REDVECTOR_NUCLEI_BIN"] = old_bin
    print("\nNUCLEI candidate subprocess validated:", real, "package", package, "detected", detected, "sha256", expected)


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

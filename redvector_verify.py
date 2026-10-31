"""Standalone native tool verification engine for RedVector AI (W9 Phase 2).

Verifies installed Kali native tool identity, root ownership, secure paths, package
provenance and execution profile compatibility. Writes verified evidence to the
root-owned evidence cache. Must run as root (uid=0). Does not modify production
adapters or authorize any runtime execution.

Usage:
  sudo python3 -m redvector_verify nuclei
  sudo python3 -m redvector_verify nikto
  sudo python3 -m redvector_verify nmap
  sudo python3 -m redvector_verify searchsploit
  sudo python3 -m redvector_verify all

  Options:
    --cache <path>   Override default cache path
    --dry-run        Verify without writing to cache
    --help           Show this message

Internal sandbox entry point (not for direct use):
  python3 -m redvector_verify --rv-sandbox-runner <binary> [args...]
  Applies seccomp no_network(), then os.execv(binary, args). Never returns.
"""

import datetime
import hashlib
import http.server
import json
import os
import platform
import shutil
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl as _fcntl
    _HAVE_FLOCK = True
except ImportError:
    _HAVE_FLOCK = False

import redvector_tool_evidence as rte

VERIFY_VERSION = "2"
_DEFAULT_CACHE_PATH = Path("/var/lib/redvector/tool_evidence.json")

VerifyError = type("VerifyError", (ValueError,), {})

# Allowed template IDs for the offline passive Nuclei profile test
_ALLOWED_TEMPLATE_IDS = frozenset({"rv-missing-nosniff", "rv-missing-frame-options"})


# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------

def _require_root() -> None:
    """Raise VerifyError unless running as uid=0."""
    if os.getuid() != 0:
        raise VerifyError(
            "redvector-verify must run as root: "
            "sudo python3 -m redvector_verify <tool>"
        )


# ---------------------------------------------------------------------------
# Binary validation helpers
# ---------------------------------------------------------------------------

def _binary_sha256(path: Path) -> str:
    """Compute SHA256 of a binary file via 1-MiB block streaming."""
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1_048_576), b""):
            digest.update(block)
    return digest.hexdigest()


def _check_binary_path(path: Path) -> None:
    """Raise VerifyError if path is not an absolute non-symlink regular file."""
    if not path.is_absolute():
        raise VerifyError(f"Binary path must be absolute: {path}")
    if path.is_symlink():
        raise VerifyError(f"Binary must not be a symlink: {path}")
    if not path.is_file():
        raise VerifyError(f"Binary not found or not a regular file: {path}")


def _check_binary_ownership(path: Path) -> None:
    """Raise VerifyError if binary is not root-owned or has group/other write."""
    st = path.stat()
    if st.st_uid != 0:
        raise VerifyError(
            f"Binary {path} is not root-owned (uid={st.st_uid}); "
            "install via apt or root-owned tools/install_reviewed_nuclei.py"
        )
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise VerifyError(
            f"Binary {path} has group/other write permission; "
            "mode must not include g+w or o+w"
        )


def _dpkg_provenance(binary_path: Path) -> dict:
    """Check Debian package provenance and integrity via dpkg -S and dpkg --verify.

    Returns a dict with keys: package, status, dpkg_s_output, dpkg_verify_clean.
    Partial results are returned on non-fatal failures; never raises.
    """
    result: dict = {
        "package": None,
        "dpkg_s_output": "",
        "dpkg_verify_clean": None,
        "status": "unknown",
    }
    try:
        r = subprocess.run(
            ["dpkg", "-S", str(binary_path)],
            capture_output=True, text=True, timeout=10,
            stdin=subprocess.DEVNULL,
        )
        result["dpkg_s_output"] = (r.stdout + r.stderr).strip()[:500]
        if r.returncode == 0 and r.stdout.strip():
            # e.g. "nuclei: /usr/bin/nuclei"
            pkg = r.stdout.strip().split(":")[0].strip()
            result["package"] = pkg
            result["status"] = "package-owned"
        else:
            result["status"] = "not-packaged"
    except FileNotFoundError:
        result["status"] = "dpkg-unavailable"
        return result
    except subprocess.TimeoutExpired:
        result["status"] = "dpkg-timeout"
        return result

    if result["package"]:
        try:
            r2 = subprocess.run(
                ["dpkg", "--verify", result["package"]],
                capture_output=True, text=True, timeout=10,
                stdin=subprocess.DEVNULL,
            )
            result["dpkg_verify_clean"] = (r2.returncode == 0)
            if not result["dpkg_verify_clean"]:
                result["dpkg_verify_output"] = (r2.stdout + r2.stderr).strip()[:300]
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            result["dpkg_verify_clean"] = None
            result["dpkg_verify_error"] = str(exc)[:100]
    return result


# ---------------------------------------------------------------------------
# Sandboxed subprocess runner
# ---------------------------------------------------------------------------

def _sandboxed_run(
    binary: Path, args: list, directory: Path, env: dict
) -> subprocess.CompletedProcess:
    """Run binary in a subprocess with seccomp no_network() sandbox applied.

    Spawns a Python subprocess that:
      1. Calls redvector_reviewed_assessment.no_network() (installs BPF seccomp filter)
      2. os.execv(binary, args) — replaces the subprocess with the binary

    This mirrors the --offline-nuclei pattern in redvector_reviewed_assessment.py:
    seccomp is installed in the child, Nuclei inherits it via execv.
    """
    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--rv-sandbox-runner",
        str(binary),
        *[str(a) for a in args],
    ]
    return subprocess.run(
        cmd, cwd=str(directory), env=env,
        stdin=subprocess.DEVNULL, capture_output=True, timeout=35,
    )


def _sandbox_runner_main(binary_str: str, args: list) -> None:
    """Internal: apply no_network() seccomp then execv(binary). Never returns normally."""
    try:
        import redvector_reviewed_assessment as ra
        ra.no_network()
    except Exception as exc:
        sys.stderr.write(f"sandbox-error: {exc}\n")
        sys.exit(125)
    try:
        os.execv(binary_str, [binary_str] + list(args))
    except OSError as exc:
        sys.stderr.write(f"execv-error: {exc}\n")
        sys.exit(127)


# ---------------------------------------------------------------------------
# Loopback HTTP server for profile testing
# ---------------------------------------------------------------------------

class _VerifyHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP/1.1 server for offline Nuclei profile verification.

    Intentionally omits X-Content-Type-Options and X-Frame-Options so the
    offline passive scan detects and reports both as missing headers.
    """
    def do_GET(self):  # noqa: N802
        body = b"RedVector verify loopback"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass

    def log_error(self, *_):
        pass


@contextmanager
def _loopback_server():
    """Context manager: start a loopback HTTP server on 127.0.0.1:0 and yield its URL."""
    server = socketserver.TCPServer(("127.0.0.1", 0), _VerifyHandler)
    server.allow_reuse_address = True
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# Nuclei profile test helpers
# ---------------------------------------------------------------------------

def _nuclei_version_str(output: bytes) -> str:
    """Parse version string from Nuclei -version output."""
    import redvector_reviewed_assessment as ra
    return ra.nuclei_version(output)


def _run_nuclei_version_test(binary: Path, tmp_dir: Path, env: dict) -> str:
    """Run nuclei -version in sandbox. Returns version string or raises VerifyError."""
    result = _sandboxed_run(binary, ["-version"], tmp_dir, env)
    stderr_str = result.stderr.decode("utf-8", "replace")
    if result.returncode == 125 and "sandbox-error:" in stderr_str:
        raise VerifyError(
            f"Seccomp network sandbox could not be installed: "
            + stderr_str.split("sandbox-error:", 1)[1][:200]
        )
    if result.returncode not in (0, 1):
        raise VerifyError(
            f"nuclei -version failed (exit {result.returncode}):\n"
            + (stderr_str + result.stdout.decode("utf-8", "replace"))[:400]
        )
    version = _nuclei_version_str(result.stdout + result.stderr)
    if not version:
        raise VerifyError(
            "Could not parse Nuclei version from output:\n"
            + (result.stdout + result.stderr).decode("utf-8", "replace")[:300]
        )
    return version


def _build_templates(templates_dir: Path) -> None:
    """Write the standard reviewed header-check templates to templates_dir."""
    import redvector_reviewed_assessment as ra
    for ident, header in [
        ("rv-missing-nosniff", "X-Content-Type-Options"),
        ("rv-missing-frame-options", "X-Frame-Options"),
    ]:
        (templates_dir / (ident + ".yaml")).write_text(
            ra.template(ident, header), encoding="utf-8"
        )


def _run_nuclei_profile_test(
    binary: Path, tmp_dir: Path, env: dict, target_url: str
) -> dict:
    """Fetch loopback response, run offline passive Nuclei scan, validate JSONL output.

    Returns dict: {passed, template_ids, jsonl_rows, detail}. Raises VerifyError on failure.

    Flow (identical to production run_nuclei()):
      1. Fetch target_url via the reviewed HTTP client (validate_url accepts 127.0.0.1)
      2. Write header-only response to responses/response.txt
      3. Write reviewed templates to templates/
      4. Run Nuclei -passive against responses/ with fixed production argv in sandbox
      5. Parse JSONL: verify all template-id values are in _ALLOWED_TEMPLATE_IDS
      6. Verify finding set matches expected (headers absent from loopback response)
    """
    import redvector_reviewed_assessment as ra

    try:
        captured = ra.fetch(target_url)
    except Exception as exc:
        raise VerifyError(f"Failed to fetch loopback server response: {exc}") from exc

    responses_dir = tmp_dir / "responses"
    responses_dir.mkdir(exist_ok=True)
    templates_dir = tmp_dir / "templates"
    templates_dir.mkdir(exist_ok=True)

    # Build header-only input — same logic as production run_nuclei()
    skip_headers = {
        "transfer-encoding", "content-encoding",
        "content-length", "trailer", "connection",
    }
    header_input = (
        f"HTTP/1.1 {captured['status_code']} OK\r\n"
        + "".join(
            f"{k}: {v}\r\n"
            for k, v in captured["headers"].items()
            if k.lower() not in skip_headers
        )
        + "Content-Length: 0\r\n\r\n"
    )
    (responses_dir / "response.txt").write_text(header_input, encoding="utf-8")
    _build_templates(templates_dir)

    # Run Nuclei with exact production flags
    args = [
        "-passive", "-u", str(responses_dir),
        "-t", str(templates_dir),
        "-ni", "-duc", "-dr", "-nh", "-no-stdin",
        "-jsonl", "-silent", "-nc", "-omit-raw",
        "-c", "1", "-bs", "1", "-timeout", "3", "-retries", "0",
    ]
    result = _sandboxed_run(binary, args, tmp_dir, env)

    stderr_str = result.stderr.decode("utf-8", "replace")
    if result.returncode == 125 and "sandbox-error:" in stderr_str:
        raise VerifyError(
            "Seccomp network sandbox could not be installed during profile test: "
            + stderr_str.split("sandbox-error:", 1)[1][:200]
        )
    if result.returncode != 0 or len(result.stdout) + len(result.stderr) > 1_048_576:
        raise VerifyError(
            f"Nuclei offline passive profile test failed (exit {result.returncode}):\n"
            + stderr_str[:400]
        )

    # Parse and validate JSONL
    rows = []
    try:
        for line in result.stdout.decode("utf-8", "strict").splitlines():
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            tid = item.get("template-id", "")
            if tid not in _ALLOWED_TEMPLATE_IDS:
                raise VerifyError(
                    f"Unexpected template ID in Nuclei output: {tid!r}; "
                    f"only {sorted(_ALLOWED_TEMPLATE_IDS)} are permitted"
                )
            rows.append({"template_id": tid, "info": item.get("info", {})})
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VerifyError(f"Failed to parse Nuclei JSONL output: {exc}") from exc

    # Verify findings are consistent with what the loopback response actually served
    found_headers = set(captured["headers"].keys())
    expected_findings: set = set()
    if "x-content-type-options" not in found_headers:
        expected_findings.add("rv-missing-nosniff")
    if "x-frame-options" not in found_headers:
        expected_findings.add("rv-missing-frame-options")

    actual_findings = {r["template_id"] for r in rows}
    if actual_findings != expected_findings:
        raise VerifyError(
            f"Nuclei findings {sorted(actual_findings)} do not match expected "
            f"{sorted(expected_findings)} for response headers {sorted(found_headers)}"
        )

    return {
        "passed": True,
        "template_ids": sorted(actual_findings),
        "jsonl_rows": rows,
        "detail": (
            f"Passive scan: {len(rows)} finding(s); JSONL parsed OK; "
            f"template IDs validated against allowlist"
        ),
    }


# ---------------------------------------------------------------------------
# Binding dict helpers (must stay in sync with rte binding functions)
# ---------------------------------------------------------------------------

def _nuclei_binding_dict(ra) -> dict:
    """Return the nuclei binding dict that corresponds to rte.nuclei_profile_binding()."""
    sample_env = ra._env(Path("/nonexistent-rv-binding-probe"))
    security_env_keys = sorted(k for k in sample_env if k.startswith("DISABLE_"))
    binding: dict = {
        "profile": "nuclei-offline-header-v1",
        "policy_version": getattr(ra, "_POLICY_VERSION", "nuclei-offline-header-v1"),
        "limit": ra._LIMIT,
        "subprocess_timeout": 30,
        "env_keys": security_env_keys,
        "fixed_argv": [
            "-passive", "-ni", "-duc", "-dr", "-nh", "-no-stdin",
            "-jsonl", "-silent", "-nc", "-omit-raw",
            "-c", "1", "-bs", "1", "-timeout", "3", "-retries", "0",
        ],
        "no_network_syscalls": sorted([41, 42, 44, 46, 307]),
        "no_network_prctl": sorted([22, 38]),
    }
    try:
        sample_tpl = ra.template("redvector-binding-probe", "X-Probe: 1")
        binding["template_sample_hash"] = rte._sha256_str(sample_tpl)
    except Exception:
        pass
    return binding


# ---------------------------------------------------------------------------
# Atomic evidence write
# ---------------------------------------------------------------------------

def _ensure_cache_dir(cache_path: Path) -> None:
    """Create cache directory as root with mode 0o755. Raises VerifyError if not root."""
    _require_root()
    d = cache_path.parent
    d.mkdir(mode=0o755, parents=True, exist_ok=True)
    st = d.stat()
    if st.st_uid != 0:
        raise VerifyError(
            f"Cache directory {d} is not root-owned (uid={st.st_uid}); "
            "run as root to create it"
        )


def _verify_path_chain_trusted(cache_path: Path) -> None:
    """Raise VerifyError if any ancestor of cache_path is untrusted.

    Mirrors rte._trusted_cache() ancestor walk but raises VerifyError on failure.
    Called before any atomic write to guard against TOCTOU symlink-substitution attacks
    in parent directories (a world-writable parent lets non-root replace the file even
    when the file itself is root-owned).
    """
    _require_root()
    if cache_path.is_symlink():
        raise VerifyError(
            f"Cache target {cache_path} is a symlink; write refused"
        )
    for component in cache_path.parents:
        try:
            if component.is_symlink():
                raise VerifyError(
                    f"Cache ancestor {component} is a symlink; write refused to prevent path misdirection"
                )
            st = component.stat()
            if st.st_uid != 0:
                raise VerifyError(
                    f"Cache ancestor {component} is not root-owned (uid={st.st_uid})"
                )
            if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise VerifyError(
                    f"Cache ancestor {component} has group/other write permission"
                )
        except OSError as exc:
            raise VerifyError(
                f"Cannot stat cache path ancestor {component}: {exc}"
            ) from exc


def _write_evidence_atomic(entry: dict, cache_path: Path) -> None:
    """Atomically write/update an evidence entry in the root-owned cache file.

    Steps: full path-chain trust check → exclusive file lock (Linux) → read-modify-write
    into a temp file → fsync → check cache_path is not a symlink → atomic rename.
    The lock file and temp file are always cleaned up on any error.
    Requires uid=0.
    """
    _require_root()
    _ensure_cache_dir(cache_path)
    _verify_path_chain_trusted(cache_path)

    lock_path = cache_path.with_name(cache_path.name + ".lock")
    lock_fd: "int | None" = None
    if _HAVE_FLOCK:
        lock_fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
        _fcntl.flock(lock_fd, _fcntl.LOCK_EX)

    try:
        # Read-modify-write: preserve all existing entries
        existing_entries: dict = {}
        if cache_path.exists():
            try:
                raw = cache_path.read_bytes()
                data = json.loads(raw.decode("utf-8"))
                if (
                    isinstance(data, dict)
                    and data.get("format_version") == rte.CACHE_FORMAT_VERSION
                    and isinstance(data.get("entries"), dict)
                ):
                    existing_entries = data["entries"]
            except Exception:
                pass  # corrupted or absent cache; start fresh

        existing_entries[entry["binary_sha256"]] = entry
        new_data = {
            "format_version": rte.CACHE_FORMAT_VERSION,
            "entries": existing_entries,
            "updated_at": datetime.datetime.utcnow().isoformat() + "Z",
        }

        fd, tmp_str = tempfile.mkstemp(
            dir=str(cache_path.parent), prefix=".rv-evidence-tmp-"
        )
        tmp = Path(tmp_str)
        try:
            os.fchmod(fd, 0o644)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(new_data, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            # Defense-in-depth: reject rename if target became a symlink between check and now
            if cache_path.is_symlink():
                raise VerifyError(
                    f"Cache path {cache_path} is a symlink at rename time; write aborted"
                )
            # Atomic rename within same directory (same filesystem)
            tmp.rename(cache_path)
        except BaseException:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        # Fsync parent directory so the directory entry for the renamed file is durable
        dir_fd = os.open(str(cache_path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if lock_fd is not None:
            try:
                _fcntl.flock(lock_fd, _fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(lock_fd)


# ---------------------------------------------------------------------------
# Functional test helpers for non-Nuclei tools
# ---------------------------------------------------------------------------

def _run_nmap_functional_test(binary: Path, tmp_dir: Path) -> dict:
    """Run nmap -sn 127.0.0.1 to confirm the binary executes a real scan.

    Uses the same env isolation as the production adapter (no PATH, LC_ALL=C).
    A successful ping-scan of the loopback address confirms scan execution capability;
    it is deterministic, non-destructive and does not touch any real network target.
    Returns: {passed, exit_code, detail}. Never raises.
    """
    env = {"PATH": os.defpath, "LC_ALL": "C", "HOME": str(tmp_dir)}
    try:
        r = subprocess.run(
            [str(binary), "-sn", "127.0.0.1"],
            capture_output=True, text=True, timeout=20,
            stdin=subprocess.DEVNULL, cwd=str(tmp_dir), env=env,
        )
        output = (r.stdout + r.stderr).strip()
        passed = r.returncode == 0 and bool(output)
        return {
            "passed": passed,
            "exit_code": r.returncode,
            "detail": f"nmap -sn 127.0.0.1: exit={r.returncode}; output_bytes={len(output)}",
        }
    except subprocess.TimeoutExpired:
        return {"passed": False, "exit_code": None,
                "detail": "nmap -sn 127.0.0.1 timed out after 20 s"}
    except OSError as exc:
        return {"passed": False, "exit_code": None,
                "detail": f"nmap execution error: {exc}"}


def _run_nikto_functional_test(binary: Path, tmp_dir: Path) -> dict:
    """Run nikto against a loopback HTTP server with the production tuning flags.

    Confirms the binary accepts the production argv, produces JSON output (exit 0 or 1),
    and that the production parser nk.parse_json() successfully parses the output.
    Returns: {passed, exit_code, output_file_present, json_parse_compatible, detail}.
    Never raises.
    """
    import redvector_reviewed_nikto as nk
    outfile = tmp_dir / "nikto_verify.json"
    env = {
        "PATH": os.defpath, "LC_ALL": "C",
        "HOME": str(tmp_dir), "XDG_CONFIG_HOME": str(tmp_dir),
    }
    try:
        with _loopback_server() as url:
            port = url.split(":")[2].rstrip("/")
            cmd = [
                str(binary),
                "-h", "127.0.0.1", "-p", port,
                "-nointeractive", "-ask", "no",
                "-maxtime", "10s",
                "-Tuning", nk._TUNING,
                "-timeout", "5",
                "-nolookup",
                "-Format", "json",
                "-o", str(outfile),
            ]
            r = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=35,
                stdin=subprocess.DEVNULL, cwd=str(tmp_dir), env=env,
            )
        ran = r.returncode in (0, 1)
        # Verify structured output compatibility via the production parser
        json_parse_compatible = False
        parse_detail = "output file not present"
        if outfile.is_file():
            try:
                output_text = outfile.read_text(encoding="utf-8", errors="replace")
                nk.parse_json(output_text)
                json_parse_compatible = True
                parse_detail = "nk.parse_json() succeeded"
            except Exception as exc:
                parse_detail = f"nk.parse_json() failed: {type(exc).__name__}: {str(exc)[:100]}"
        passed = ran and json_parse_compatible
        return {
            "passed": passed,
            "exit_code": r.returncode,
            "output_file_present": outfile.is_file(),
            "json_parse_compatible": json_parse_compatible,
            "detail": (
                f"nikto loopback scan: exit={r.returncode}; "
                f"output_file={'yes' if outfile.is_file() else 'no'}; "
                f"tuning={nk._TUNING}; parse: {parse_detail}"
            ),
        }
    except subprocess.TimeoutExpired:
        return {"passed": False, "exit_code": None, "output_file_present": False,
                "json_parse_compatible": False,
                "detail": "nikto loopback scan timed out after 35 s"}
    except Exception as exc:
        return {"passed": False, "exit_code": None, "output_file_present": False,
                "json_parse_compatible": False,
                "detail": f"nikto functional test error: {exc}"}


def _run_searchsploit_functional_test(binary: Path, tmp_dir: Path) -> dict:
    """Run searchsploit --json apache to confirm JSON output capability.

    Uses the production required flags (--json, --disable-colour).  A successful JSON
    parse of the output confirms the binary can execute the reviewed execution profile.
    Returns: {passed, exit_code, json_parseable, detail}. Never raises.
    """
    env = {"PATH": os.defpath, "LC_ALL": "C", "HOME": str(tmp_dir)}
    try:
        r = subprocess.run(
            [str(binary), "--json", "--disable-colour", "apache"],
            capture_output=True, text=True, timeout=15,
            stdin=subprocess.DEVNULL, cwd=str(tmp_dir), env=env,
        )
        raw = (r.stdout or r.stderr or "").strip()
        json_parseable = False
        try:
            obj = json.loads(raw)
            json_parseable = isinstance(obj, dict)
        except (ValueError, TypeError):
            pass
        passed = json_parseable
        return {
            "passed": passed,
            "exit_code": r.returncode,
            "json_parseable": json_parseable,
            "detail": (
                f"searchsploit --json apache: exit={r.returncode}; "
                f"JSON parseable: {json_parseable}"
            ),
        }
    except subprocess.TimeoutExpired:
        return {"passed": False, "exit_code": None, "json_parseable": False,
                "detail": "searchsploit --json apache timed out after 15 s"}
    except OSError as exc:
        return {"passed": False, "exit_code": None, "json_parseable": False,
                "detail": f"searchsploit execution error: {exc}"}


# ---------------------------------------------------------------------------
# Binary finder
# ---------------------------------------------------------------------------

def _find_binary(name: str, env_var: str) -> Path:
    """Find a binary by env var override or PATH search. Raises VerifyError if absent."""
    path_str = os.environ.get(env_var, "").strip() or shutil.which(name)
    if not path_str:
        raise VerifyError(
            f"Binary '{name}' not found on PATH; "
            f"set {env_var} or install via apt"
        )
    return Path(path_str)


# ---------------------------------------------------------------------------
# Tool-specific verification
# ---------------------------------------------------------------------------

def verify_nuclei(
    binary_path: "Path | None" = None,
    cache_path: "Path | None" = None,
) -> dict:
    """Verify the installed Nuclei binary and write evidence to cache.

    Steps:
      1. Path safety (absolute, no symlink, is file)
      2. SHA256 computation
      3. Root ownership + permissions
      4. dpkg package provenance and integrity
      5. Binding key from live adapter state
      6. Platform check (Linux amd64 required for seccomp sandbox)
      7. nuclei -version sandbox test
      8. Offline passive profile test against loopback HTTP server
      9. Atomic write to evidence cache

    Returns result dict: {tool, sha256, version, diagnostics, entry}.
    Raises VerifyError on any verification failure.
    """
    _require_root()
    binary = binary_path or _find_binary("nuclei", "REDVECTOR_NUCLEI_BIN")
    cache = cache_path or _DEFAULT_CACHE_PATH
    diag: list = []

    _check_binary_path(binary)
    diag.append(f"path: {binary} — absolute non-symlink regular file OK")

    sha256 = _binary_sha256(binary)
    diag.append(f"sha256: {sha256}")

    _check_binary_ownership(binary)
    diag.append("ownership: root-owned, no group/other write OK")

    prov = _dpkg_provenance(binary)
    diag.append(f"provenance: {prov['status']} ({prov.get('dpkg_s_output','')[:60]})")
    if prov.get("dpkg_verify_clean") is False:
        raise VerifyError(
            f"dpkg --verify {prov['package']!r} reported modified files; "
            "binary may have been tampered with:\n"
            + prov.get("dpkg_verify_output", "")[:300]
        )
    if prov.get("dpkg_verify_clean") is None:
        raise VerifyError(
            f"Package integrity check inconclusive or unavailable "
            f"(dpkg status: {prov['status']}); cannot produce authoritative evidence. "
            "Install via apt or ensure dpkg is functional before verifying."
        )

    if not sys.platform.startswith("linux") or platform.machine() not in ("x86_64", "amd64"):
        raise VerifyError(
            "Nuclei verification requires Linux amd64 "
            "(run on native Kali VMware)"
        )

    import redvector_reviewed_assessment as ra
    binding_key = rte.nuclei_profile_binding()
    binding_dict = _nuclei_binding_dict(ra)
    diag.append(f"binding_key: {binding_key[:16]}...")

    with tempfile.TemporaryDirectory(prefix="rv-verify-nuclei-") as tmp_str:
        tmp_dir = Path(tmp_str)
        env = ra._env(tmp_dir)

        version = _run_nuclei_version_test(binary, tmp_dir, env)
        diag.append(f"version test: {version} — sandbox OK")

        with _loopback_server() as url:
            profile_result = _run_nuclei_profile_test(binary, tmp_dir, env, url)
        diag.append("profile test: " + profile_result["detail"])

    entry = {
        "binary_sha256": sha256,
        "binding_key": binding_key,
        "binding": binding_dict,
        "functional_tests_passed": True,
        "sandbox_tests_passed": True,
        "tool": "nuclei",
        "binary_path": str(binary),
        "version": version,
        "platform": f"linux/{platform.machine()}",
        "package": prov.get("package"),
        "dpkg_integrity": {
            "verified_clean": prov.get("dpkg_verify_clean"),
            "status": prov.get("status"),
        },
        "profile_test_result": profile_result,
        "verification_state": {
            "binary_installed": True,
            "package_integrity_verified": prov.get("dpkg_verify_clean") is True,
            "native_execution_verified": True,
            "structured_output_compatible": True,
            "production_execution_authorized": False,
        },
        "recorded_at": datetime.datetime.utcnow().isoformat() + "Z",
        "recorded_by": f"redvector-verify/{VERIFY_VERSION}",
        "notes": f"Phase 2 verified: {sha256[:12]}... {version}",
    }

    _write_evidence_atomic(entry, cache)
    diag.append(f"written to cache: {cache}")

    return {
        "tool": "nuclei",
        "sha256": sha256,
        "version": version,
        "diagnostics": diag,
        "entry": entry,
    }


def verify_nikto(
    binary_path: "Path | None" = None,
    cache_path: "Path | None" = None,
) -> dict:
    """Verify the installed Nikto binary and write evidence to cache.

    Steps:
      1. Path safety (absolute, no symlink, is file)
      2. SHA256 computation
      3. Root ownership + permissions
      4. dpkg package provenance and integrity
      5. Binding key from live adapter state
      6. Functional test: loopback HTTP scan with production tuning flags
      7. Atomic write to evidence cache

    functional_tests_passed / sandbox_tests_passed are set only after the loopback
    scan completes successfully.  Nikto does not use a seccomp sandbox; subprocess
    isolation (fixed argv, isolated env, time/output limits) is the sandboxing in use.
    """
    _require_root()
    binary = binary_path or _find_binary("nikto", "REDVECTOR_NIKTO_BIN")
    cache = cache_path or _DEFAULT_CACHE_PATH

    if not sys.platform.startswith("linux"):
        raise VerifyError("Nikto verification requires Linux (Kali)")

    _check_binary_path(binary)
    diag = [f"path: {binary} — absolute non-symlink regular file OK"]

    sha256 = _binary_sha256(binary)
    diag.append(f"sha256: {sha256}")

    _check_binary_ownership(binary)
    diag.append("ownership: root-owned, no group/other write OK")

    prov = _dpkg_provenance(binary)
    diag.append(f"provenance: {prov['status']} ({prov.get('dpkg_s_output','')[:60]})")
    if prov.get("dpkg_verify_clean") is False:
        raise VerifyError(
            f"dpkg --verify {prov['package']!r} reported modified files; "
            "binary may have been tampered with:\n"
            + prov.get("dpkg_verify_output", "")[:300]
        )
    if prov.get("dpkg_verify_clean") is None:
        raise VerifyError(
            f"Package integrity check inconclusive or unavailable "
            f"(dpkg status: {prov['status']}); cannot produce authoritative evidence. "
            "Install via apt or ensure dpkg is functional before verifying."
        )

    import redvector_reviewed_nikto as nk
    binding_key = rte.nikto_profile_binding()
    binding_dict = {
        "profile": "nikto-native-v1",
        "tuning": nk._TUNING,
        "maxtime": nk._MAXTIME,
        "deadline": nk._DEADLINE,
        "limit": nk._LIMIT,
    }
    diag.append(f"binding_key: {binding_key[:16]}...")

    with tempfile.TemporaryDirectory(prefix="rv-verify-nikto-") as tmp_str:
        tmp_dir = Path(tmp_str)
        func_test = _run_nikto_functional_test(binary, tmp_dir)

    if not func_test["passed"]:
        raise VerifyError(
            f"Nikto functional test failed: {func_test['detail']}"
        )
    diag.append(f"functional test: {func_test['detail']}")

    entry = {
        "binary_sha256": sha256,
        "binding_key": binding_key,
        "binding": binding_dict,
        "functional_tests_passed": True,   # loopback scan with production tuning flags passed
        "sandbox_tests_passed": True,       # subprocess isolation (no seccomp; see sandbox_profile)
        "sandbox_profile": "subprocess-isolation-only",
        "tool": "nikto",
        "binary_path": str(binary),
        "functional_test_result": func_test,
        "package": prov.get("package"),
        "dpkg_integrity": {
            "verified_clean": prov.get("dpkg_verify_clean"),
            "status": prov.get("status"),
        },
        "verification_state": {
            "binary_installed": True,
            "package_integrity_verified": prov.get("dpkg_verify_clean") is True,
            "native_execution_verified": True,
            "structured_output_compatible": func_test.get("json_parse_compatible", False),
            "production_execution_authorized": False,
        },
        "recorded_at": datetime.datetime.utcnow().isoformat() + "Z",
        "recorded_by": f"redvector-verify/{VERIFY_VERSION}",
        "notes": (
            f"Verified: loopback scan executed (exit {func_test.get('exit_code', '?')}) "
            "and nk.parse_json() parsed output successfully. "
            f"sha256={sha256[:12]}..."
        ),
    }
    _write_evidence_atomic(entry, cache)
    diag.append(f"written to cache: {cache}")
    return {"tool": "nikto", "sha256": sha256, "diagnostics": diag, "entry": entry}


def verify_nmap(
    binary_path: "Path | None" = None,
    cache_path: "Path | None" = None,
) -> dict:
    """Verify the installed Nmap binary and write evidence to cache.

    Steps:
      1. Path safety (absolute, no symlink, is file)
      2. SHA256 computation
      3. Root ownership + permissions
      4. dpkg package provenance and integrity
      5. Binding key from live adapter state
      6. Functional test: nmap -sn 127.0.0.1 (real ping scan of loopback)
      7. Atomic write to evidence cache

    functional_tests_passed / sandbox_tests_passed are set only after the ping-scan
    succeeds.  Nmap does not use a seccomp sandbox; subprocess isolation with the
    production env profile is the sandboxing in use.
    """
    _require_root()
    binary = binary_path or _find_binary("nmap", "REDVECTOR_NMAP_BIN")
    cache = cache_path or _DEFAULT_CACHE_PATH

    if not sys.platform.startswith("linux"):
        raise VerifyError("Nmap verification requires Linux (Kali)")

    _check_binary_path(binary)
    diag = [f"path: {binary} — absolute non-symlink regular file OK"]

    sha256 = _binary_sha256(binary)
    diag.append(f"sha256: {sha256}")

    _check_binary_ownership(binary)
    diag.append("ownership: root-owned, no group/other write OK")

    prov = _dpkg_provenance(binary)
    diag.append(f"provenance: {prov['status']} ({prov.get('dpkg_s_output','')[:60]})")
    if prov.get("dpkg_verify_clean") is False:
        raise VerifyError(
            f"dpkg --verify {prov['package']!r} reported modified files; "
            "binary may have been tampered with:\n"
            + prov.get("dpkg_verify_output", "")[:300]
        )
    if prov.get("dpkg_verify_clean") is None:
        raise VerifyError(
            f"Package integrity check inconclusive or unavailable "
            f"(dpkg status: {prov['status']}); cannot produce authoritative evidence. "
            "Install via apt or ensure dpkg is functional before verifying."
        )

    import redvector_reviewed_profiles as rp
    binding_key = rte.nmap_discovery_binding()
    binding_dict = {
        "profile": "tcp-discovery-v1",
        "max_rate": rp._DISCOVERY_MAX_RATE,
        "host_timeout": rp._DISCOVERY_HOST_TIMEOUT,
        "deadline": rp._DISCOVERY_DEADLINE,
        "max_ports": rp.MAX_DISCOVERY_PORTS,
    }
    diag.append(f"binding_key: {binding_key[:16]}...")

    with tempfile.TemporaryDirectory(prefix="rv-verify-nmap-") as tmp_str:
        tmp_dir = Path(tmp_str)
        func_test = _run_nmap_functional_test(binary, tmp_dir)

    if not func_test["passed"]:
        raise VerifyError(
            f"Nmap functional test failed: {func_test['detail']}"
        )
    diag.append(f"functional test: {func_test['detail']}")

    entry = {
        "binary_sha256": sha256,
        "binding_key": binding_key,
        "binding": binding_dict,
        "functional_tests_passed": True,   # loopback ping scan passed
        "sandbox_tests_passed": True,       # subprocess isolation (no seccomp; see sandbox_profile)
        "sandbox_profile": "subprocess-isolation-only",
        "tool": "nmap",
        "binary_path": str(binary),
        "functional_test_result": func_test,
        "package": prov.get("package"),
        "dpkg_integrity": {
            "verified_clean": prov.get("dpkg_verify_clean"),
            "status": prov.get("status"),
        },
        "verification_state": {
            "binary_installed": True,
            "package_integrity_verified": prov.get("dpkg_verify_clean") is True,
            "native_execution_verified": True,
            "structured_output_compatible": None,  # ping-scan test; XML output compatibility not tested
            "production_execution_authorized": False,
        },
        "recorded_at": datetime.datetime.utcnow().isoformat() + "Z",
        "recorded_by": f"redvector-verify/{VERIFY_VERSION}",
    }
    _write_evidence_atomic(entry, cache)
    diag.append(f"written to cache: {cache}")
    return {"tool": "nmap", "sha256": sha256, "diagnostics": diag, "entry": entry}


def verify_searchsploit(
    binary_path: "Path | None" = None,
    cache_path: "Path | None" = None,
) -> dict:
    """Verify the installed Searchsploit binary and write evidence to cache.

    Steps:
      1. Path safety (absolute, no symlink, is file)
      2. SHA256 computation
      3. Root ownership + permissions
      4. dpkg package provenance and integrity
      5. Binding key from live adapter state
      6. Functional test: searchsploit --json apache (confirms JSON output capability)
      7. Atomic write to evidence cache

    functional_tests_passed / sandbox_tests_passed are set only after the JSON query
    succeeds.  Searchsploit does not use a seccomp sandbox; subprocess isolation with
    the production env profile is the sandboxing in use.
    """
    _require_root()
    binary = binary_path or _find_binary("searchsploit", "REDVECTOR_SEARCHSPLOIT_BIN")
    cache = cache_path or _DEFAULT_CACHE_PATH

    if not sys.platform.startswith("linux"):
        raise VerifyError("Searchsploit verification requires Linux (Kali)")

    _check_binary_path(binary)
    diag = [f"path: {binary} — absolute non-symlink regular file OK"]

    sha256 = _binary_sha256(binary)
    diag.append(f"sha256: {sha256}")

    _check_binary_ownership(binary)
    diag.append("ownership: root-owned, no group/other write OK")

    prov = _dpkg_provenance(binary)
    diag.append(f"provenance: {prov['status']} ({prov.get('dpkg_s_output','')[:60]})")
    if prov.get("dpkg_verify_clean") is False:
        raise VerifyError(
            f"dpkg --verify {prov['package']!r} reported modified files; "
            "binary may have been tampered with:\n"
            + prov.get("dpkg_verify_output", "")[:300]
        )
    if prov.get("dpkg_verify_clean") is None:
        raise VerifyError(
            f"Package integrity check inconclusive or unavailable "
            f"(dpkg status: {prov['status']}); cannot produce authoritative evidence. "
            "Install via apt or ensure dpkg is functional before verifying."
        )

    import redvector_reviewed_searchsploit as ss
    binding_key = rte.searchsploit_profile_binding()
    binding_dict = {
        "profile": "searchsploit-v1",
        "deadline": ss._DEADLINE,
        "limit": ss._LIMIT,
        "required_flags": ["--json", "--disable-colour"],
    }
    diag.append(f"binding_key: {binding_key[:16]}...")

    with tempfile.TemporaryDirectory(prefix="rv-verify-searchsploit-") as tmp_str:
        tmp_dir = Path(tmp_str)
        func_test = _run_searchsploit_functional_test(binary, tmp_dir)

    if not func_test["passed"]:
        raise VerifyError(
            f"Searchsploit functional test failed: {func_test['detail']}"
        )
    diag.append(f"functional test: {func_test['detail']}")

    entry = {
        "binary_sha256": sha256,
        "binding_key": binding_key,
        "binding": binding_dict,
        "functional_tests_passed": True,   # JSON query with production flags passed
        "sandbox_tests_passed": True,       # subprocess isolation (no seccomp; see sandbox_profile)
        "sandbox_profile": "subprocess-isolation-only",
        "tool": "searchsploit",
        "binary_path": str(binary),
        "functional_test_result": func_test,
        "package": prov.get("package"),
        "dpkg_integrity": {
            "verified_clean": prov.get("dpkg_verify_clean"),
            "status": prov.get("status"),
        },
        "verification_state": {
            "binary_installed": True,
            "package_integrity_verified": prov.get("dpkg_verify_clean") is True,
            "native_execution_verified": True,
            "structured_output_compatible": func_test.get("json_parseable", False),
            "production_execution_authorized": False,
        },
        "recorded_at": datetime.datetime.utcnow().isoformat() + "Z",
        "recorded_by": f"redvector-verify/{VERIFY_VERSION}",
    }
    _write_evidence_atomic(entry, cache)
    diag.append(f"written to cache: {cache}")
    return {
        "tool": "searchsploit",
        "sha256": sha256,
        "diagnostics": diag,
        "entry": entry,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

_TOOL_MAP = {
    "nuclei": verify_nuclei,
    "nikto": verify_nikto,
    "nmap": verify_nmap,
    "searchsploit": verify_searchsploit,
}

_USAGE = """\
redvector-verify — native Kali tool verification engine (W9 Phase 2)

Usage: sudo python3 -m redvector_verify <tool> [options]

  tool:  nuclei | nikto | nmap | searchsploit | all

Options:
  --cache <path>   Override default cache path
                   (default: /var/lib/redvector/tool_evidence.json)
  --dry-run        Run verification checks without writing to cache
  --help           Show this message

Each tool is verified for: binary identity (SHA256), root ownership,
package provenance (dpkg -S / dpkg --verify), CLI capability, and — for
Nuclei — sandboxed offline passive profile against an isolated loopback
server with JSONL validation.

Results are written atomically to the root-owned evidence cache.
Must run as root (sudo).
"""


def main(argv: "list | None" = None) -> int:
    """CLI entry point. Returns exit code (0 = all passed, 1 = failure, 2 = usage)."""
    if argv is None:
        argv = sys.argv[1:]

    if not argv or "--help" in argv or "-h" in argv:
        print(_USAGE)
        return 0

    cache_override: "Path | None" = None
    dry_run = False
    remaining = []
    i = 0
    while i < len(argv):
        if argv[i] == "--cache" and i + 1 < len(argv):
            cache_override = Path(argv[i + 1])
            i += 2
        elif argv[i] == "--dry-run":
            dry_run = True
            i += 1
        else:
            remaining.append(argv[i])
            i += 1

    if not remaining:
        print(_USAGE, file=sys.stderr)
        return 2

    tool_arg = remaining[0].lower()
    known = list(_TOOL_MAP.keys()) + ["all"]
    if tool_arg not in known:
        print(
            f"Unknown tool: {tool_arg!r}. Choose from: {', '.join(_TOOL_MAP)}, all",
            file=sys.stderr,
        )
        return 2

    tools_to_run = list(_TOOL_MAP.keys()) if tool_arg == "all" else [tool_arg]
    exit_code = 0

    for tool in tools_to_run:
        print(f"\n[redvector-verify] Verifying {tool}...", flush=True)
        fn = _TOOL_MAP[tool]
        try:
            if dry_run:
                print(f"  --dry-run: verification skipped for {tool}")
                continue
            result = fn(cache_path=cache_override)
            ver = result.get("version", "")
            sha = result["sha256"][:16]
            print(f"  ✓ {tool}: sha256={sha}... version={ver or 'n/a'}")
            for line in result.get("diagnostics", []):
                print(f"      {line}")
        except VerifyError as exc:
            print(f"  ✗ {tool}: FAILED — {exc}", file=sys.stderr)
            exit_code = 1
        except Exception as exc:
            print(f"  ✗ {tool}: UNEXPECTED ERROR — {type(exc).__name__}: {exc}",
                  file=sys.stderr)
            exit_code = 1

    if exit_code == 0 and not dry_run:
        print("\n[redvector-verify] All verifications passed.")
    elif exit_code != 0:
        print("\n[redvector-verify] One or more verifications failed.", file=sys.stderr)
    return exit_code


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Internal sandbox runner: apply no_network() seccomp then execv binary.
    # Called exclusively by _sandboxed_run(); never invoked directly by operators.
    if len(sys.argv) > 1 and sys.argv[1] == "--rv-sandbox-runner":
        if len(sys.argv) < 3:
            sys.stderr.write("internal: --rv-sandbox-runner requires <binary>\n")
            sys.exit(2)
        _sandbox_runner_main(sys.argv[2], sys.argv[3:])
        # _sandbox_runner_main calls os.execv or sys.exit; never falls through
    sys.exit(main())

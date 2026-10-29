"""Opt-in backend-owned reviewed NATIVE Nikto web-server assessment.

Runs the real installed `nikto` binary (not an internal collector) against one explicit,
already-authorized root URL whose host the policy has pinned to a numeric address. Execution is a
fixed argv vector (no shell), bounded by a wall-clock deadline, an output-size limit and nikto's
own `-maxtime`, with a non-destructive `-Tuning` selection (DoS, command-exec, injection, SQLi and
file-upload test groups are excluded) and interaction disabled. The execution mode is reported
honestly:

  * ``A`` — native nikto executed (real scan ran),
  * ``D`` — missing dependency (nikto not installed),
  * ``E`` — unsupported (non-Linux host, runtime integrity, or output not recognized),
  * ``R`` — reviewed input rejected (strict validation failed; nothing executed).

It NEVER reports mode ``A`` unless the native binary ran, and it is never labeled as a substitute
for, or by, the RedVector passive HTTP collector. The authenticated caller supplies
scope/authorization; this module does not replace API authentication. Self-contained so it can be
attested by its own source hash, mirroring the other reviewed adapters.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import selectors
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

NIKTO_MARKER = "--redvector-nikto-native-v1"
PROFILE = "nikto-native-v1"
_LOCK = threading.Lock()
_LIMIT = 1024 * 1024          # 1 MiB output cap
_DEADLINE = 210              # overall wall-clock seconds (nikto is slow; bounded)
_MAXTIME = "120s"            # nikto's own run cap
# Non-destructive tuning: 1 interesting files, 2 misconfig, 3 info disclosure, b software identification.
# Explicitly EXCLUDES 4 (injection/XSS), 6 (DoS), 8 (command exec), 9 (SQLi), 0 (file upload), a (auth bypass).
_TUNING = "123b"


class NiktoError(ValueError):
    pass


def _digest(path):
    digest = hashlib.sha256()
    if path.stat().st_size > 32 * _LIMIT:
        raise NiktoError("Runtime file exceeds reviewed size")
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _trusted(path):
    path = Path(path)
    if path.is_symlink():
        raise NiktoError("Runtime symlinks are not supported")
    for parent in (path, *path.parents):
        info = parent.stat()
        if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise NiktoError("Nikto runtime must be administrator-owned and not writable by other users")
    if not path.is_file():
        raise NiktoError("Missing native nikto runtime")
    return _digest(path)


def _runtime():
    if not sys.platform.startswith("linux"):
        raise NiktoError("Unsupported: reviewed native Nikto requires native Linux")
    import shutil
    executable = shutil.which("nikto")
    if not executable:
        raise NiktoError("Missing Dependency: native nikto binary unavailable")
    executable = Path(executable).resolve()
    _trusted(executable)
    return executable


def _validate(tool, params):
    if tool != "nikto_scan" or not isinstance(params, dict):
        raise NiktoError("Unsupported reviewed tool")
    if set(params) - {"target", "additional_args"}:
        raise NiktoError("Unexpected reviewed nikto arguments")
    if params.get("additional_args") != NIKTO_MARKER:
        raise NiktoError("Reviewed native nikto profile marker required")
    url = params.get("target")
    if not isinstance(url, str) or not url:
        raise NiktoError("One explicit authorized root URL is required")
    u = urlsplit(url)
    if u.scheme not in ("http", "https") or u.username or u.password or u.query or u.fragment or u.path not in ("", "/"):
        raise NiktoError("Reviewed nikto permits one root HTTP(S) URL, without credentials, queries or fragments")
    host = u.hostname or ""
    try:
        address = ipaddress.ip_address(host)                 # policy pins to a numeric destination
    except ValueError:
        raise NiktoError("A numeric pinned host is required (policy pins the destination)") from None
    if address.is_multicast or address.is_unspecified or str(address) != host:
        raise NiktoError("A canonical unicast numeric host is required")
    try:
        port = u.port
    except ValueError:
        raise NiktoError("Invalid URL port") from None
    port = port if port else (443 if u.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise NiktoError("Invalid URL port")
    return {"host": host, "port": str(port), "ssl": u.scheme == "https", "version": address.version}


def _command(executable, spec, outfile):
    command = [str(executable), "-h", spec["host"], "-p", spec["port"], "-nointeractive", "-ask", "no",
               "-maxtime", _MAXTIME, "-Tuning", _TUNING, "-timeout", "10", "-nolookup",
               "-Format", "json", "-o", str(outfile)]
    if spec["ssl"]:
        command.append("-ssl")
    return command


def _execute(command, directory, timeout=_DEADLINE):
    env = {"PATH": os.defpath, "LC_ALL": "C", "HOME": str(directory), "XDG_CONFIG_HOME": str(directory)}
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=directory,
                               env=env, stdin=subprocess.DEVNULL, start_new_session=True)
    deadline = time.monotonic() + timeout
    output = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise NiktoError("Reviewed nikto deadline exceeded")
                for key, _ in selector.select(min(.2, remaining)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = output[key.data]
                    if len(buffer) + len(chunk) > _LIMIT:
                        raise NiktoError("Reviewed nikto output limit exceeded")
                    buffer.extend(chunk)
            code = process.wait(timeout=max(.01, deadline - time.monotonic()))
            return code, output["stdout"].decode("utf-8", "replace"), output["stderr"].decode("utf-8", "replace")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def parse_json(text):
    """Parse nikto JSON output into a bounded, structured result. nikto emits either a single
    object or a list of host objects. Raises NiktoError (Unsupported) when unrecognizable."""
    text = (text or "").strip()
    if not text:
        return {"host": "", "port": "", "findings": [], "note": "Empty nikto output"}
    try:
        obj = json.loads(text)
    except ValueError:
        raise NiktoError("Unsupported: nikto JSON output was not recognized")
    hosts = obj if isinstance(obj, list) else [obj]
    findings = []
    host = port = ""
    for entry in hosts:
        if not isinstance(entry, dict):
            continue
        host = host or str(entry.get("host", entry.get("ip", "")))
        port = port or str(entry.get("port", ""))
        vulns = entry.get("vulnerabilities")
        for item in vulns if isinstance(vulns, list) else []:
            if not isinstance(item, dict):
                continue
            findings.append({"id": str(item.get("id", "")), "method": str(item.get("method", "")),
                             "url": str(item.get("url", ""))[:500], "message": str(item.get("msg", ""))[:500],
                             "references": str(item.get("references", ""))[:300]})
    return {"host": host, "port": port, "findings": findings}


def capabilities():
    try:
        _runtime()
        return {PROFILE: {"state": "Ready",
                          "detail": "Native attested nikto web-server assessment; one pinned root URL, non-destructive tuning (no DoS/cmd-exec/injection/SQLi/upload), bounded -maxtime/deadline/output; real JSON parsed"}}
    except (NiktoError, OSError, subprocess.SubprocessError) as exc:
        detail = str(exc) if isinstance(exc, NiktoError) else "Native nikto runtime unavailable or verification failed"
        state = "Missing Dependency" if "Missing" in detail else "Unsupported"
        return {PROFILE: {"state": state, "detail": detail}}


def run_nikto(params):
    """Execute the reviewed native nikto scan. Returns a structured result whose ``execution_mode``
    (A/D/E/R) reports exactly what happened; mode A implies the native binary really ran."""
    started = time.monotonic()
    try:
        spec = _validate("nikto_scan", params)
    except NiktoError as exc:
        return {"success": False, "execution_mode": "R", "execution_mode_detail": "reviewed input rejected",
                "profile": PROFILE, "error": str(exc), "execution_time": time.monotonic() - started}
    try:
        if not _LOCK.acquire(blocking=False):
            raise NiktoError("Unsupported: reviewed nikto concurrency limit reached")
        try:
            executable = _runtime()
            before = _trusted(executable)
            with tempfile.TemporaryDirectory(prefix="redvector-nikto-") as name:
                directory = Path(name)
                outfile = directory / "nikto.json"
                command = _command(executable, spec, outfile)
                code, stdout, stderr = _execute(command, directory, timeout=_DEADLINE)
                if _trusted(executable) != before:
                    raise NiktoError("Unsupported: nikto runtime integrity changed")
                raw = outfile.read_text("utf-8", "replace") if outfile.is_file() else stdout
                if outfile.is_file() and outfile.stat().st_size > _LIMIT:
                    raise NiktoError("Reviewed nikto output limit exceeded")
                parsed = parse_json(raw)
                return {"success": True, "execution_mode": "A", "execution_mode_detail": "native binary executed",
                        "profile": PROFILE, "engine": "native nikto (reviewed non-destructive tuning)",
                        "runtime_sha256": before, "return_code": code,
                        "target": spec["host"] + ":" + spec["port"], "ssl": spec["ssl"],
                        "parsed": parsed, "findings_count": len(parsed.get("findings", [])),
                        "stderr": stderr[:4096], "execution_time": time.monotonic() - started}
        finally:
            _LOCK.release()
    except NiktoError as exc:
        detail = str(exc)
        mode = "D" if "Missing" in detail else "E"
        return {"success": False, "execution_mode": mode,
                "execution_mode_detail": {"D": "missing dependency", "E": "unsupported"}[mode],
                "profile": PROFILE, "error": detail, "execution_time": time.monotonic() - started}
    except (OSError, subprocess.SubprocessError):
        return {"success": False, "execution_mode": "E", "execution_mode_detail": "unsupported",
                "profile": PROFILE, "error": "Native nikto runtime unavailable or failed",
                "execution_time": time.monotonic() - started}

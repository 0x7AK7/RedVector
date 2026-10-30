"""Opt-in backend-owned reviewed native Searchsploit (local Exploit-DB) lookup.

Offline, read-only local exploit-database search. Non-destructive: no network access, no exploit
mirroring and no file writes outside a private temporary cwd. The native ``searchsploit`` binary
is invoked as a fixed argv vector (never a shell command string), bounded by a wall-clock deadline
and an output-size limit, with a private HOME/cwd. The execution mode is reported accurately:

  * ``A`` — native binary executed (real search ran),
  * ``D`` — missing dependency (native binary not installed),
  * ``E`` — unsupported (non-Linux host, runtime integrity or output not recognized),
  * ``R`` — reviewed input rejected (strict argument validation failed; nothing executed).

It NEVER reports mode ``A`` unless the native binary actually ran. The authenticated caller
supplies scope/authorization; this module does not replace API authentication. It mirrors the
established reviewed-profile pattern (fixed argv, private datadir, bounded subprocess, runtime
integrity check) and is self-contained so it can be attested by its own source hash.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time

SEARCHSPLOIT_MARKER = "--redvector-searchsploit-v1"
PROFILE = "searchsploit-v1"
_LOCK = threading.Lock()
_LIMIT = 1024 * 1024          # 1 MiB stdout/stderr cap
_DEADLINE = 30               # bounded wall-clock seconds
# Query/term grammar: no shell metacharacters, no option-leading tokens (handled in _validate).
_QUERY_RE = re.compile(r"[A-Za-z0-9 ._+/:\-]{1,200}")
_EXCLUDE_RE = re.compile(r"[A-Za-z0-9 ,._/\-]{1,200}")
_CVE_RE = re.compile(r"(?:CVE-)?[0-9]{4}-[0-9]{4,7}")


class SearchsploitError(ValueError):
    pass


def _digest(path):
    digest = hashlib.sha256()
    if path.stat().st_size > 32 * _LIMIT:
        raise SearchsploitError("Runtime file exceeds reviewed size")
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _trusted(path):
    path = Path(path)
    if path.is_symlink():
        raise SearchsploitError("Runtime symlinks are not supported")
    for parent in (path, *path.parents):
        info = parent.stat()
        if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise SearchsploitError("Searchsploit runtime must be administrator-owned and not writable by other users")
    if not path.is_file():
        raise SearchsploitError("Missing native searchsploit runtime")
    return _digest(path)


def _runtime():
    if not sys.platform.startswith("linux"):
        raise SearchsploitError("Unsupported: reviewed Searchsploit requires native Linux")
    executable = shutil.which("searchsploit")
    if not executable:
        raise SearchsploitError("Missing Dependency: native searchsploit binary unavailable")
    executable = Path(executable).resolve()
    _trusted(executable)
    return executable


def _validate(tool, params):
    if tool != "searchsploit_lookup" or not isinstance(params, dict):
        raise SearchsploitError("Unsupported reviewed tool")
    allowed = {"query", "cve", "exact", "title_only", "exclude", "json_output", "mirror", "additional_args"}
    if set(params) - allowed:
        raise SearchsploitError("Unexpected reviewed searchsploit arguments")
    if params.get("additional_args") != SEARCHSPLOIT_MARKER:
        raise SearchsploitError("Reviewed searchsploit profile marker required")
    # Mirroring (-m) writes exploit files to disk and fetches content: disabled (read-only).
    if params.get("mirror"):
        raise SearchsploitError("Reviewed searchsploit is read-only; mirroring (-m) is disabled")
    if params.get("json_output") not in (True, None):
        raise SearchsploitError("Reviewed searchsploit always returns structured JSON")
    for flag in ("exact", "title_only"):
        if params.get(flag) not in (True, False, None):
            raise SearchsploitError(flag + " must be a boolean")
    query = params.get("query", "") or ""
    cve = params.get("cve", "") or ""
    if not isinstance(query, str) or not isinstance(cve, str):
        raise SearchsploitError("Query and CVE must be strings")
    query = query.strip()
    cve = cve.strip()
    if not query and not cve:
        raise SearchsploitError("A search query or CVE is required")
    if query:
        if not _QUERY_RE.fullmatch(query):
            raise SearchsploitError("Query contains unsupported characters")
        if any(token.startswith("-") for token in query.split()):
            raise SearchsploitError("Query terms may not begin with '-'")
    if cve:
        if not _CVE_RE.fullmatch(cve):
            raise SearchsploitError("CVE must look like CVE-YYYY-NNNN")
        cve = cve.upper()
        if not cve.startswith("CVE-"):
            cve = "CVE-" + cve
    exclude = params.get("exclude", "") or ""
    if not isinstance(exclude, str):
        raise SearchsploitError("Exclude terms must be a string")
    exclude = exclude.strip()
    if exclude and not _EXCLUDE_RE.fullmatch(exclude):
        raise SearchsploitError("Exclude terms contain unsupported characters")
    return {"query": query, "cve": cve, "exact": bool(params.get("exact")),
            "title_only": bool(params.get("title_only")), "exclude": exclude}


def _command(executable, spec):
    # Fixed executable + argv vector; no shell. --json forces structured output; --disable-colour
    # keeps stdout machine-parseable. Query terms are appended as separate argv tokens (validated
    # not to start with '-'), so they can never be interpreted as options.
    command = [str(executable), "--json", "--disable-colour"]
    if spec["exact"]:
        command.append("--exact")
    if spec["title_only"]:
        command.append("--title")
    if spec["exclude"]:
        command.append("--exclude=" + spec["exclude"])
    if spec["cve"]:
        command += ["--cve", spec["cve"]]
    command += spec["query"].split()
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
                    raise SearchsploitError("Reviewed searchsploit deadline exceeded")
                for key, _ in selector.select(min(.1, remaining)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = output[key.data]
                    if len(buffer) + len(chunk) > _LIMIT:
                        raise SearchsploitError("Reviewed searchsploit output limit exceeded")
                    buffer.extend(chunk)
            code = process.wait(timeout=max(.01, deadline - time.monotonic()))
            return code, output["stdout"].decode("utf-8", "replace"), output["stderr"].decode("utf-8", "replace")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def _rows(obj, key):
    rows = []
    source = obj.get(key)
    for item in source if isinstance(source, list) else []:
        if not isinstance(item, dict):
            continue
        rows.append({"title": str(item.get("Title", ""))[:300],
                     "edb_id": str(item.get("EDB-ID", item.get("Codes", ""))),
                     "path": str(item.get("Path", ""))[:500],
                     "type": str(item.get("Type", "")),
                     "platform": str(item.get("Platform", "")),
                     "date": str(item.get("Date_Published", item.get("Date", "")))})
    return rows


def parse_json(stdout):
    """Parse ``searchsploit --json`` output into a bounded, structured result. Raises
    SearchsploitError (classified Unsupported) when the output is not recognizable JSON."""
    text = stdout.strip()
    if not text:
        return {"search": "", "results": [], "shellcode": [], "note": "Empty searchsploit output"}
    try:
        obj = json.loads(text)
    except ValueError:
        brace = text.find("{")
        if brace < 0:
            raise SearchsploitError("Unsupported: searchsploit JSON output was not recognized")
        try:
            obj = json.loads(text[brace:])
        except ValueError:
            raise SearchsploitError("Unsupported: searchsploit JSON output was not recognized") from None
    if not isinstance(obj, dict):
        raise SearchsploitError("Unsupported: searchsploit JSON output was not recognized")
    return {"search": str(obj.get("SEARCH", ""))[:200],
            "results": _rows(obj, "RESULTS_EXPLOIT"),
            "shellcode": _rows(obj, "RESULTS_SHELLCODE")}


def capabilities():
    try:
        _runtime()
        return {PROFILE: {"state": "Ready",
                          "detail": "Native attested searchsploit --json offline Exploit-DB lookup; read-only, no mirroring/network; fixed argv vector, bounded deadline/output"}}
    except (SearchsploitError, OSError, subprocess.SubprocessError) as exc:
        detail = str(exc) if isinstance(exc, SearchsploitError) else "Native searchsploit runtime unavailable or verification failed"
        state = "Missing Dependency" if "Missing" in detail else "Unsupported"
        return {PROFILE: {"state": state, "detail": detail}}


def run_searchsploit(params):
    """Execute the reviewed native searchsploit lookup. Returns a structured result whose
    ``execution_mode`` (A/D/E/R) reports exactly what happened; mode A implies the native binary
    really ran and produced the parsed results."""
    started = time.monotonic()
    try:
        spec = _validate("searchsploit_lookup", params)
    except SearchsploitError as exc:
        return {"success": False, "execution_mode": "R", "execution_mode_detail": "reviewed input rejected",
                "profile": PROFILE, "error": str(exc), "execution_time": time.monotonic() - started}
    try:
        if not _LOCK.acquire(blocking=False):
            raise SearchsploitError("Unsupported: reviewed searchsploit concurrency limit reached")
        try:
            executable = _runtime()
            before = _trusted(executable)
            with tempfile.TemporaryDirectory(prefix="redvector-searchsploit-") as name:
                directory = Path(name)
                command = _command(executable, spec)
                code, stdout, stderr = _execute(command, directory, timeout=_DEADLINE)
                if _trusted(executable) != before:
                    raise SearchsploitError("Unsupported: searchsploit runtime integrity changed")
                parsed = parse_json(stdout)
                return {"success": True, "execution_mode": "A", "execution_mode_detail": "native binary executed",
                        "profile": PROFILE, "engine": "native searchsploit --json (offline local Exploit-DB)",
                        "runtime_sha256": before, "binary": str(executable), "return_code": code,
                        "query": spec["cve"] or spec["query"],
                        "parsed": parsed, "results_count": len(parsed.get("results", [])),
                        "shellcode_count": len(parsed.get("shellcode", [])),
                        "stderr": stderr[:4096], "execution_time": time.monotonic() - started}
        finally:
            _LOCK.release()
    except SearchsploitError as exc:
        detail = str(exc)
        mode = "D" if "Missing" in detail else "E"
        return {"success": False, "execution_mode": mode,
                "execution_mode_detail": {"D": "missing dependency", "E": "unsupported"}[mode],
                "profile": PROFILE, "error": detail, "execution_time": time.monotonic() - started}
    except (OSError, subprocess.SubprocessError):
        return {"success": False, "execution_mode": "E", "execution_mode_detail": "unsupported",
                "profile": PROFILE, "error": "Native searchsploit runtime unavailable or failed",
                "execution_time": time.monotonic() - started}

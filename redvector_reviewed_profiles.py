"""Opt-in backend-owned, bounded Nmap service evidence profile.

The authenticated caller supplies scope authorization. This module accepts only a
numeric single host and never resolves names. It does not replace API auth.
Runtime trust assumes the native administrator and root-owned package installation
are trusted; profile data are copied into a private tree and hashed around use.
"""
import hashlib
import ipaddress
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
import xml.etree.ElementTree as ET

NMAP_PROFILE = "--redvector-profile=service-version-v1"
PROFILE = "service-version-v1"
_LOCK = threading.Lock()
_LIMIT = 1024 * 1024
_DEADLINE = 45
MAX_PORTS = 128
# No default/fallback probes, SSL upgrade, RPC match, proxy request or redirect.
_PROBES = r"""Exclude T:9100-9107
Probe TCP NULL q||
totalwaitms 800
tcpwrappedms 300
match ssh m|^SSH-2\.0-OpenSSH_([0-9][A-Za-z0-9.p_-]*)[^\r\n]*\r?\n| p/OpenSSH/ v/$1/
match ftp m|^220[^\r\n]*ProFTPD ([0-9][A-Za-z0-9.p_-]*)[^\r\n]*\r?\n| p/ProFTPD/ v/$1/
match smtp m|^220[^\r\n]*ESMTP Postfix[^\r\n]*\r?\n| p/Postfix/
match ftp m|^220 \(vsFTPd ([0-9][A-Za-z0-9.p_-]*)\)\r?\n| p/vsFTPd/ v/$1/
match smtp m|^220[^\r\n]*ESMTP Exim ([0-9][A-Za-z0-9.p_-]*)[^\r\n]*\r?\n| p/Exim/ v/$1/
match pop3 m|^\+OK Dovecot ready\.\r?\n| p/Dovecot/
match imap m|^\* OK [^\r\n]*Dovecot ready\.\r?\n| p/Dovecot/
match mysql m|^...\x00\x0a([0-9][A-Za-z0-9._-]*MariaDB[A-Za-z0-9._-]*)\x00|s p/MariaDB/ v/$1/
match mysql m|^...\x00\x0a([0-9][A-Za-z0-9._-]*)\x00|s p/MySQL/ v/$1/
Probe TCP RVHttp q|GET / HTTP/1.0\r\n\r\n|
rarity 1
totalwaitms 1000
match http m|^HTTP/1\.[01] [0-9]{3}[^\r\n]*\r\n(?:[^\r\n]+\r\n)*Server: ([A-Za-z][A-Za-z0-9_.-]*)/([0-9][A-Za-z0-9._-]*)[^\r\n]*\r\n| p/$1/ v/$2/
softmatch http m|^HTTP/1\.[01] [0-9]{3} |
"""
_NOOP = """description = "RedVector profile sentinel. Never runs."
author = "RedVector"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"version"}
portrule = function() return false end
action = function() return nil end
"""
_DB = 'Entry { filename = "rv-profile-sentinel.nse", categories = { "version" } }\n'

class ProfileError(ValueError):
    pass

def _digest(path):
    digest=hashlib.sha256()
    if path.stat().st_size > 32 * _LIMIT:
        raise ProfileError("Runtime file exceeds reviewed size")
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(65536),b""):
            digest.update(block)
    return digest.hexdigest()

def _trusted(path):
    path = Path(path)
    if path.is_symlink():
        raise ProfileError("Runtime symlinks are not supported")
    for parent in (path, *path.parents):
        info = parent.stat()
        if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ProfileError("Scanner runtime must be administrator-owned and not writable by other users")
    if not path.is_file():
        raise ProfileError("Missing native scanner runtime")
    return _digest(path)

def _elf(path):
    with path.open("rb") as stream:
        return stream.read(4)==b"\x7fELF"

def _runtime():
    if not sys.platform.startswith("linux"):
        raise ProfileError("Unsupported: reviewed service profile requires native Linux")
    executable = shutil.which("nmap")
    if not executable:
        raise ProfileError("Missing Dependency: native Nmap binary unavailable")
    executable = Path(executable).resolve()
    _trusted(executable)
    # Package metadata locates native data without user-configured paths.
    dpkg = shutil.which("dpkg-query")
    if not dpkg:
        raise ProfileError("Unsupported: native package runtime cannot be verified")
    _trusted(Path(dpkg).resolve())
    metadata = subprocess.run([dpkg, "-L", "nmap-common", "nmap"], capture_output=True,
                              text=True, timeout=5, env={"PATH":os.defpath,"LC_ALL":"C"})
    if metadata.returncode:
        raise ProfileError("Missing Dependency: nmap-common runtime package unavailable")
    mains = [Path(line) for line in metadata.stdout.splitlines()
             if line.endswith("/nse_main.lua") and Path(line).is_file()]
    if len(mains) != 1:
        raise ProfileError("Unsupported: ambiguous Nmap runtime data")
    binaries = [Path(line) for line in metadata.stdout.splitlines()
                if Path(line).name == "nmap" and Path(line).is_file()
                and _elf(Path(line))]
    if len(binaries) != 1:
        raise ProfileError("Unsupported: a unique native ELF scanner is required")
    executable = binaries[0]
    root = mains[0].parent
    files = [mains[0]]
    lib = root / "nselib"
    if not lib.is_dir():
        raise ProfileError("Missing Dependency: native NSE runtime libraries unavailable")
    # Copy runtime only, never installed scripts or installed probe databases.
    files.extend(sorted(x for x in lib.rglob("*") if x.is_file()))
    if len(files) > 2000 or sum(x.stat().st_size for x in files) > 32 * _LIMIT:
        raise ProfileError("Unsupported: scanner runtime exceeds reviewed size")
    snapshots = {path: _trusted(path) for path in [executable, *files]}
    return executable, root, files, snapshots

def capabilities():
    try:
        executable,root,files,snapshots=_runtime()
        with tempfile.TemporaryDirectory(prefix="redvector-profile-check-") as name:
            directory=Path(name)
            private=_stage(root,files,snapshots,directory)
            _verify_scripts(executable,directory)
            _check(snapshots)
            if any(_digest(p)!=digest for p,digest in private.items()):
                raise ProfileError("Private scanner profile integrity changed")
        return {PROFILE: {"state":"Ready", "detail":"Native reviewed TCP profile; at most 128 ports, intensity 0-2; SSH/HTTP/FTP/SMTP/POP3/IMAP/MySQL greeting evidence"}}
    except (ProfileError, OSError, subprocess.SubprocessError) as exc:
        detail = str(exc) if isinstance(exc,ProfileError) else "Native scanner runtime unavailable or verification failed"
        state = "Missing Dependency" if "Missing" in detail else "Unsupported"
        return {PROFILE: {"state":state, "detail":detail}}

def _validate(tool, params):
    if tool != "nmap_scan" or not isinstance(params, dict):
        raise ProfileError("Unsupported reviewed tool")
    if set(params) != {"target","ports","scan_type","additional_args","use_recovery"}:
        raise ProfileError("Reviewed profile requires exact arguments")
    if params["scan_type"] != NMAP_PROFILE or params["use_recovery"] is not False:
        raise ProfileError("Only the fixed profile with recovery disabled is permitted")
    target = params["target"]
    if not isinstance(target,str) or "%" in target:
        raise ProfileError("A numeric single host is required")
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        raise ProfileError("A numeric single host is required") from None
    if address.is_multicast or address.is_unspecified or str(address) != target:
        raise ProfileError("A canonical unicast numeric host is required")
    ports = params["ports"]
    if not isinstance(ports,str) or not ports or len(ports)>2048:
        raise ProfileError("Explicit bounded TCP ports are required")
    selected=set()
    for group in ports.split(","):
        if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", group):
            raise ProfileError("Only TCP port numbers and ascending ranges are permitted")
        values=[int(x) for x in group.split("-")]
        if min(values)<1 or max(values)>65535 or values[0]>values[-1]:
            raise ProfileError("Invalid TCP port bounds")
        if values[-1]-values[0]>=MAX_PORTS:
            raise ProfileError("Service profile permits at most 128 TCP ports")
        selected.update(range(values[0],values[-1]+1))
    if len(selected)>MAX_PORTS or selected.intersection(range(9100,9108)):
        raise ProfileError("At most 128 TCP ports; printer ports 9100-9107 are excluded")
    match=re.fullmatch(r"--version-intensity ([012])",params["additional_args"] if isinstance(params["additional_args"],str) else "")
    if not match:
        raise ProfileError("Only reviewed version intensity 0, 1 or 2 is permitted")
    return target,",".join(map(str,sorted(selected))),match.group(1),address.version

def parse_xml(raw):
    sanitized=re.sub(r"<!DOCTYPE\s+nmaprun\s*>","",raw,flags=re.I)
    if len(raw.encode("utf-8"))>_LIMIT or "<!ENTITY" in raw.upper() or "<!DOCTYPE" in sanitized.upper():
        raise ProfileError("Invalid or oversized scanner XML")
    try:
        root=ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ProfileError("Invalid scanner XML") from exc
    if root.tag!="nmaprun":
        raise ProfileError("Unexpected scanner output")
    result={"target":"","hosts":[],"open_ports":[],"services":[],"scan_summary":"",
            "profile":PROFILE,"fingerprint_coverage":"Reviewed SSH/FTP/SMTP/POP3/IMAP/MySQL greetings and HTTP Server header only"}
    for host in root.findall("host"):
        address=host.find("address")
        if address is not None:
            try: result["target"]=str(ipaddress.ip_address(address.get("addr","")))
            except ValueError: raise ProfileError("Scanner returned an invalid numeric destination") from None
            result["hosts"].append(result["target"])
        for port in host.findall("./ports/port"):
            state=port.find("state")
            if state is None or state.get("state")!="open":continue
            service=port.find("service")
            fields=service.attrib if service is not None else {}
            identified=fields.get("method")=="probed" and bool(fields.get("product"))
            entry={"port":port.get("portid"),"protocol":port.get("protocol"),"state":"open",
                   "service":fields.get("name","unknown"),
                   "product":fields.get("product","") if identified else "",
                   "version":fields.get("version","") if identified else "",
                   "confidence":"identified" if identified else "inconclusive",
                   "method":fields.get("method",""),"scanner_confidence":fields.get("conf","")}
            result["open_ports"].append(entry)
            result["services"].append(entry.copy())
    finished=root.find("./runstats/finished")
    result["scan_complete"]=(finished is not None and finished.get("exit")=="success"
                             and not any(h.get("timedout")=="true" for h in root.findall("host")))
    result["scan_summary"]=finished.get("summary","") if finished is not None else ""
    return result

def _write_private(directory):
    scripts=directory/"scripts";scripts.mkdir()
    (scripts/"script.db").write_text(_DB,encoding="ascii")
    (scripts/"rv-profile-sentinel.nse").write_text(_NOOP,encoding="ascii")
    (directory/"nmap-service-probes").write_text(_PROBES,encoding="ascii")
    (directory/"nmap-services").write_text("",encoding="ascii")
    (directory/"nmap-rpc").write_text("",encoding="ascii")
    return {p:_digest(p) for p in directory.rglob("*") if p.is_file()}

def _stage(root,files,snapshots,directory):
    for original in files:
        relative=original.relative_to(root);copy=directory/relative
        copy.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(original,copy)
        if _digest(copy)!=snapshots[original]:
            raise ProfileError("Scanner runtime changed during preparation")
    return _write_private(directory)

def _check(snapshots):
    if any(_trusted(p)!=digest for p,digest in snapshots.items()):
        raise ProfileError("Scanner runtime integrity changed")

def _execute(command, directory, timeout=_DEADLINE):
    # Fixed native executable, argv vector, no shell, private HOME and cwd.
    env={"PATH":os.defpath,"LC_ALL":"C","HOME":str(directory),
         "XDG_CONFIG_HOME":str(directory),"NMAPDIR":str(directory)}
    process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=directory,env=env,
                             stdin=subprocess.DEVNULL,start_new_session=True)
    deadline=time.monotonic()+timeout
    output={"stdout":bytearray(),"stderr":bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout,selectors.EVENT_READ,"stdout")
            selector.register(process.stderr,selectors.EVENT_READ,"stderr")
            while selector.get_map():
                remaining=deadline-time.monotonic()
                if remaining<=0:
                    raise ProfileError("Reviewed scan deadline exceeded")
                for key,_ in selector.select(min(.1,remaining)):
                    chunk=os.read(key.fileobj.fileno(),65536)
                    if not chunk:
                        selector.unregister(key.fileobj);continue
                    buffer=output[key.data]
                    if len(buffer)+len(chunk)>_LIMIT:
                        raise ProfileError("Reviewed scan output limit exceeded")
                    buffer.extend(chunk)
            code=process.wait(timeout=max(.01,deadline-time.monotonic()))
            return code,output["stdout"].decode("utf-8","replace"),output["stderr"].decode("utf-8","replace")
    finally:
        if process.poll() is None:
            process.kill();process.wait(timeout=5)
        process.stdout.close();process.stderr.close()

def _verify_scripts(executable,directory):
    code,out,err=_execute([str(executable),"--datadir",str(directory),"--script-help","version"],directory,timeout=5)
    tail="rv-profile-sentinel\nCategories: version\nhttps://nmap.org/nsedoc/scripts/rv-profile-sentinel.html\n  RedVector profile sentinel. Never runs."
    if code or err or out.strip().split("\n\n",1)[-1] != tail:
        raise ProfileError("Native version script selection differs from reviewed sentinel")

def run_profile(tool, params):
    started=time.monotonic()
    try:
        target,ports,intensity,version=_validate(tool,params)
        if not _LOCK.acquire(blocking=False):
            raise ProfileError("Reviewed scanner concurrency limit reached")
        try:
            executable,root,files,snapshots=_runtime()
            with tempfile.TemporaryDirectory(prefix="redvector-reviewed-") as name:
                directory=Path(name)
                private=_stage(root,files,snapshots,directory)
                _check(snapshots)
                _verify_scripts(executable,directory)
                command=[str(executable),"-sT","-sV","--unprivileged","-n","-Pn",
                         "--disable-arp-ping","--max-parallelism","1","--max-rate","10",
                         "--max-retries","1","--host-timeout","35s",
                         "--version-intensity",intensity,"--datadir",str(directory),
                         "--versiondb",str(directory/"nmap-service-probes"),
                         
                         "-p",ports,"-oX","-","--no-stylesheet"]
                if version==6:command.append("-6")
                command.append(target)
                code,stdout,stderr=_execute(command,directory)
                _check(snapshots)
                if any(_digest(p)!=digest for p,digest in private.items()):
                    raise ProfileError("Private scanner profile integrity changed")
                parsed=parse_xml(stdout)
                if code or not parsed["scan_complete"] or len(parsed["hosts"])!=1:
                    return {"success":False,"error":"Reviewed scan did not complete successfully",
                            "stdout":stdout,"stderr":stderr,"parsed":parsed,
                            "execution_time":time.monotonic()-started,"profile":PROFILE}
                if any(x!=target for x in parsed["hosts"]):
                    raise ProfileError("Scanner returned an unexpected destination")
                return {"success":True,"stdout":stdout,"stderr":stderr,"parsed":parsed,
                        "execution_time":time.monotonic()-started,"profile":PROFILE,
                        "reviewed_profile":{"ports":ports,"intensity":int(intensity),
                           "probes":["NULL","RVHttp"],"nse":"Sentinel only; portrule always false",
                           "runtime_sha256":snapshots[executable]}}
        finally:
            _LOCK.release()
    except (ProfileError,OSError,subprocess.SubprocessError) as exc:
        detail=str(exc) if isinstance(exc,ProfileError) else "Native scanner runtime unavailable or verification failed"
        return {"success":False,"error":detail,"profile":PROFILE,
                "execution_time":time.monotonic()-started}

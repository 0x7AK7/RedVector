"""Unified native-tool status layer and scanning implementations for RedVector AI.

Queries each reviewed native adapter's capabilities() function and normalises the result into
a single structured status dict with actionable installation guidance. Never installs tools,
executes binaries, modifies configuration, or bypasses integrity checks. Safe to call on any
platform: Missing Dependency is returned for tools that require native Linux when running on
Windows or macOS.

Usage::

    import redvector_tool_manager as tool_manager
    tool_status = tool_manager.discover_tools()
    reason = tool_manager.unavailability_reason("nikto-native-v1", tool_status)
"""

import base64
import concurrent.futures
import ctypes
import hashlib
import http.client
import ipaddress
import json
import os
import platform
import re
import selectors
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit

READY = "Ready"
MISSING = "Missing Dependency"
UNSUPPORTED = "Unsupported"
DISABLED = "Disabled"
RESTRICTED = "Restricted"


# ══════════════════════════════════════════════════════════════════════════════
# NSE REGISTRY — Dynamic Nmap NSE 'vuln' script discovery and risk classification
# ══════════════════════════════════════════════════════════════════════════════

_NSE_C_CATS = frozenset({"intrusive", "dos", "exploit", "brute", "fuzzer", "malware"})
_NSE_D_CATS = frozenset({"external"})
_NSE_NOT_A = _NSE_C_CATS | _NSE_D_CATS | frozenset({"auth", "broadcast"})
_NSE_FORCE_RISKY = frozenset()
_NSE_FORCE_EXTERNAL = frozenset({"vulners", "http-virustotal"})
_NSE_CATS_RE = re.compile(r"Categories:\s*(.+)", re.IGNORECASE)
_NSE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$", re.IGNORECASE)


def nse_classify(name, categories):
    cats = {str(c).strip().lower() for c in (categories or []) if str(c).strip()}
    name_l = str(name or "").strip().lower()
    if name_l in _NSE_FORCE_RISKY or (cats & _NSE_C_CATS):
        return "C", "intrusive/disruptive category or reviewed-risky name"
    if name_l in _NSE_FORCE_EXTERNAL or (cats & _NSE_D_CATS):
        return "D", "contacts external/third-party services"
    if "vuln" in cats and "safe" in cats and not (cats & _NSE_NOT_A):
        return "A", "vuln+safe with no sensitive category: read-only/low-impact detection"
    if "vuln" in cats:
        return "B", "vuln without safe: more extensive/sensitive probing"
    return "U", "not a recognized vuln-category script"


def nse_parse(text):
    lines = str(text or "").splitlines()
    records = []
    seen = set()
    for index, line in enumerate(lines):
        match = _NSE_CATS_RE.match(line.strip())
        if not match or index == 0:
            continue
        name = lines[index - 1].strip()
        if not name or not _NSE_NAME_RE.match(name) or name in seen:
            continue
        categories = sorted(c.strip().lower() for c in match.group(1).split() if c.strip())
        risk, reason = nse_classify(name, categories)
        records.append({"script": name, "categories": categories, "risk": risk, "reason": reason})
        seen.add(name)
    return records


def nse_eligible(records, limit=64):
    names = sorted({r["script"] for r in records if r.get("risk") == "A"})
    return names[:max(0, int(limit))]


def nse_summary(records):
    counts = {tier: 0 for tier in ("A", "B", "C", "D", "U")}
    for record in records:
        counts[record.get("risk", "U")] = counts.get(record.get("risk", "U"), 0) + 1
    return {"total": len(records), "counts": counts, "category_a": nse_eligible(records),
            "category_b": sorted(r["script"] for r in records if r.get("risk") == "B"),
            "category_c": sorted(r["script"] for r in records if r.get("risk") == "C"),
            "category_d": sorted(r["script"] for r in records if r.get("risk") == "D")}


# ══════════════════════════════════════════════════════════════════════════════
# PROFILES — Opt-in backend-owned, bounded Nmap service evidence profile
# ══════════════════════════════════════════════════════════════════════════════

NMAP_PROFILE = "--redvector-profile=service-version-v1"
NMAP_SVC_PROFILE = "service-version-v1"
DISCOVERY_PROFILE = "--redvector-profile=tcp-discovery-v1"
DISCOVERY = "tcp-discovery-v1"
NSE_VULN_PROFILE = "--redvector-profile=nse-vuln-v1"
NSE_VULN = "nse-vuln-v1"
_nmap_lock = threading.Lock()
_nmap_limit = 1024 * 1024
_NMAP_DEADLINE = 45
_DISCOVERY_DEADLINE = 300
_DISCOVERY_MAX_RATE = "2000"
_DISCOVERY_HOST_TIMEOUT = "280s"
_NSE_DEADLINE = 300
_NSE_HOST_TIMEOUT = "280s"
_NSE_MAX_RATE = "500"
MAX_PORTS = 128
MAX_DISCOVERY_PORTS = 65535
MAX_NSE_PORTS = 128
_NSE_DISCOVERY_CACHE = {}
_NSE_MAX_ELIGIBLE = 64
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
    if path.stat().st_size > 32 * _nmap_limit:
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

def _nmap_runtime():
    if not sys.platform.startswith("linux"):
        raise ProfileError("Unsupported: reviewed service profile requires native Linux")
    executable = shutil.which("nmap")
    if not executable:
        raise ProfileError("Missing Dependency: native Nmap binary unavailable")
    executable = Path(executable).resolve()
    _trusted(executable)
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
    files.extend(sorted(x for x in lib.rglob("*") if x.is_file()))
    if len(files) > 2000 or sum(x.stat().st_size for x in files) > 32 * _nmap_limit:
        raise ProfileError("Unsupported: scanner runtime exceeds reviewed size")
    snapshots = {path: _trusted(path) for path in [executable, *files]}
    return executable, root, files, snapshots

def _discovery_runtime():
    if not sys.platform.startswith("linux"):
        raise ProfileError("Unsupported: reviewed discovery profile requires native Linux")
    if not shutil.which("nmap"):
        raise ProfileError("Missing Dependency: native Nmap binary unavailable")
    dpkg=shutil.which("dpkg-query")
    if not dpkg:
        raise ProfileError("Unsupported: native package runtime cannot be verified")
    _trusted(Path(dpkg).resolve())
    metadata=subprocess.run([dpkg,"-L","nmap-common","nmap"],capture_output=True,text=True,timeout=5,
                            env={"PATH":os.defpath,"LC_ALL":"C"})
    if metadata.returncode:
        raise ProfileError("Missing Dependency: native Nmap runtime package unavailable")
    binaries=[Path(line) for line in metadata.stdout.splitlines()
              if Path(line).name=="nmap" and Path(line).is_file() and _elf(Path(line))]
    if len(binaries)!=1:
        raise ProfileError("Unsupported: a unique native ELF scanner is required")
    executable=binaries[0]
    _trusted(executable)
    return executable

def nmap_capabilities():
    states={}
    try:
        _discovery_runtime()
        states[DISCOVERY]={"state":"Ready","detail":"Native attested nmap -sT connect discovery; 1..65535 ports, bounded rate/host-timeout; no NSE/UDP/OS; XML parsed"}
    except (ProfileError, OSError, subprocess.SubprocessError) as exc:
        detail = str(exc) if isinstance(exc,ProfileError) else "Native scanner runtime unavailable or verification failed"
        states[DISCOVERY]={"state":"Missing Dependency" if "Missing" in detail else "Unsupported","detail":detail}
    try:
        executable,root,files,snapshots=_nmap_runtime()
        with tempfile.TemporaryDirectory(prefix="redvector-profile-check-") as name:
            directory=Path(name)
            private=_stage(root,files,snapshots,directory)
            _verify_scripts(executable,directory)
            _check(snapshots)
            if any(_digest(p)!=digest for p,digest in private.items()):
                raise ProfileError("Private scanner profile integrity changed")
        states[NMAP_SVC_PROFILE]={"state":"Ready", "detail":"Native reviewed TCP profile; at most 128 ports, intensity 0-2; SSH/HTTP/FTP/SMTP/POP3/IMAP/MySQL greeting evidence"}
    except (ProfileError, OSError, subprocess.SubprocessError) as exc:
        detail = str(exc) if isinstance(exc,ProfileError) else "Native scanner runtime unavailable or verification failed"
        state = "Missing Dependency" if "Missing" in detail else "Unsupported"
        states[NMAP_SVC_PROFILE]={"state":state, "detail":detail}
    try:
        executable,root,files,snapshots=_nmap_runtime()
        with tempfile.TemporaryDirectory(prefix="redvector-nse-cap-") as name:
            records=_discover_nse(executable,root,snapshots.get(executable),Path(name))
        summary=nse_summary(records)
        eligible=summary["category_a"]
        if eligible:
            states[NSE_VULN]={"state":"Ready","detail":("Native attested nmap -sV --script over "+str(len(eligible))
                +" dynamically discovered reviewed low-impact (Category A) vuln NSE script(s); "
                +str(summary["counts"]["B"])+" active, "+str(summary["counts"]["C"])+" intrusive and "
                +str(summary["counts"]["D"])+" external scripts discovered but NOT run by the default workflow; "
                "at most 128 ports; bounded; per-script integrity checked; XML parsed")}
        else:
            states[NSE_VULN]={"state":"Unsupported","detail":("No reviewed low-impact (Category A) NSE vuln script is "
                "available in the native inventory ("+str(summary["total"])+" vuln script(s) discovered: "
                +str(summary["counts"]["B"])+" active, "+str(summary["counts"]["C"])+" intrusive, "
                +str(summary["counts"]["D"])+" external); the default nse-vuln-v1 workflow has nothing safe to run")}
    except (ProfileError, OSError, subprocess.SubprocessError) as exc:
        detail = str(exc) if isinstance(exc,ProfileError) else "Native scanner runtime unavailable or verification failed"
        states[NSE_VULN]={"state":"Missing Dependency" if "Missing" in detail else "Unsupported","detail":detail}
    return states

def _nmap_validate(tool, params):
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
    if len(raw.encode("utf-8"))>_nmap_limit or "<!ENTITY" in raw.upper() or "<!DOCTYPE" in sanitized.upper():
        raise ProfileError("Invalid or oversized scanner XML")
    try:
        root=ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ProfileError("Invalid scanner XML") from exc
    if root.tag!="nmaprun":
        raise ProfileError("Unexpected scanner output")
    result={"target":"","hosts":[],"open_ports":[],"services":[],"scan_summary":"",
            "profile":NMAP_SVC_PROFILE,"fingerprint_coverage":"Reviewed SSH/FTP/SMTP/POP3/IMAP/MySQL greetings and HTTP Server header only"}
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
            cpe=[c.text for c in (service.findall("cpe") if service is not None else []) if c.text] if identified else []
            entry={"port":port.get("portid"),"protocol":port.get("protocol"),"state":"open",
                   "service":fields.get("name","unknown"),
                   "product":fields.get("product","") if identified else "",
                   "version":fields.get("version","") if identified else "",
                   "cpe":cpe,
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

def _nmap_execute(command, directory, timeout=_NMAP_DEADLINE):
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
                    if len(buffer)+len(chunk)>_nmap_limit:
                        raise ProfileError("Reviewed scan output limit exceeded")
                    buffer.extend(chunk)
            code=process.wait(timeout=max(.01,deadline-time.monotonic()))
            return code,output["stdout"].decode("utf-8","replace"),output["stderr"].decode("utf-8","replace")
    finally:
        if process.poll() is None:
            process.kill();process.wait(timeout=5)
        process.stdout.close();process.stderr.close()

def _observed_version(executable,directory):
    try:
        code,out,err=_nmap_execute([str(executable),"--version"],directory,timeout=10)
    except (ProfileError,OSError,subprocess.SubprocessError):
        return ""
    match=re.search(r"Nmap version ([0-9][0-9A-Za-z.\-]*)",out+err)
    return match.group(1) if match else ""

def _verify_scripts(executable,directory):
    code,out,err=_nmap_execute([str(executable),"--datadir",str(directory),"--script-help","version"],directory,timeout=5)
    tail="rv-profile-sentinel\nCategories: version\nhttps://nmap.org/nsedoc/scripts/rv-profile-sentinel.html\n  RedVector profile sentinel. Never runs."
    if code or err or out.strip().split("\n\n",1)[-1] != tail:
        raise ProfileError("Native version script selection differs from reviewed sentinel")

def _discover_nse(executable,root,sha,directory):
    if sha and sha in _NSE_DISCOVERY_CACHE:
        return _NSE_DISCOVERY_CACHE[sha]
    records=[]
    try:
        code,out,err=_nmap_execute([str(executable),"--script-help","vuln","--datadir",str(root)],directory,timeout=90)
        if not code:
            records=nse_parse(out)
    except (ProfileError,OSError,subprocess.SubprocessError):
        records=[]
    if sha:
        _NSE_DISCOVERY_CACHE[sha]=records
    return records


def nse_inventory():
    try:
        executable,root,files,snapshots=_nmap_runtime()
    except (ProfileError,OSError,subprocess.SubprocessError) as exc:
        detail=str(exc) if isinstance(exc,ProfileError) else "Native scanner runtime unavailable or verification failed"
        return {"state":"Missing Dependency" if "Missing" in detail else "Unsupported","detail":detail,"records":[],"summary":nse_summary([])}
    with tempfile.TemporaryDirectory(prefix="redvector-nse-inv-") as name:
        records=_discover_nse(executable,root,snapshots.get(executable),Path(name))
    return {"state":"ok","records":records,"summary":nse_summary(records)}


def nmap_run_profile(tool, params):
    started=time.monotonic()
    try:
        target,ports,intensity,version=_nmap_validate(tool,params)
        if not _nmap_lock.acquire(blocking=False):
            raise ProfileError("Reviewed scanner concurrency limit reached")
        try:
            executable,root,files,snapshots=_nmap_runtime()
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
                code,stdout,stderr=_nmap_execute(command,directory)
                _check(snapshots)
                if any(_digest(p)!=digest for p,digest in private.items()):
                    raise ProfileError("Private scanner profile integrity changed")
                parsed=parse_xml(stdout)
                if code or not parsed["scan_complete"] or len(parsed["hosts"])!=1:
                    return {"success":False,"error":"Reviewed scan did not complete successfully",
                            "stdout":stdout,"stderr":stderr,"parsed":parsed,
                            "execution_time":time.monotonic()-started,"profile":NMAP_SVC_PROFILE}
                if any(x!=target for x in parsed["hosts"]):
                    raise ProfileError("Scanner returned an unexpected destination")
                return {"success":True,"stdout":stdout,"stderr":stderr,"parsed":parsed,
                        "execution_time":time.monotonic()-started,"profile":NMAP_SVC_PROFILE,
                        "reviewed_profile":{"ports":ports,"intensity":int(intensity),
                           "probes":["NULL","RVHttp"],"nse":"Sentinel only; portrule always false",
                           "engine":"native nmap -sV reviewed service-version profile",
                           "binary":str(executable),"version":_observed_version(executable,directory),
                           "runtime_sha256":snapshots[executable]}}
        finally:
            _nmap_lock.release()
    except (ProfileError,OSError,subprocess.SubprocessError) as exc:
        detail=str(exc) if isinstance(exc,ProfileError) else "Native scanner runtime unavailable or verification failed"
        return {"success":False,"error":detail,"profile":NMAP_SVC_PROFILE,
                "execution_time":time.monotonic()-started}

def _validate_discovery(tool,params):
    if tool!="nmap_scan" or not isinstance(params,dict):
        raise ProfileError("Unsupported reviewed tool")
    if set(params)!={"target","ports","scan_type","additional_args","use_recovery"}:
        raise ProfileError("Reviewed profile requires exact arguments")
    if params["scan_type"]!=DISCOVERY_PROFILE or params["use_recovery"] is not False:
        raise ProfileError("Only the fixed discovery profile with recovery disabled is permitted")
    if params.get("additional_args","") not in ("",):
        raise ProfileError("The reviewed discovery profile accepts no free-form arguments")
    target=params["target"]
    if not isinstance(target,str) or "%" in target:
        raise ProfileError("A numeric single host is required")
    try:
        address=ipaddress.ip_address(target)
    except ValueError:
        raise ProfileError("A numeric single host is required") from None
    if address.is_multicast or address.is_unspecified or str(address)!=target:
        raise ProfileError("A canonical unicast numeric host is required")
    ports=params["ports"]
    if not isinstance(ports,str) or not ports or len(ports)>2048:
        raise ProfileError("Explicit bounded TCP ports are required")
    spec="1-65535" if ports.strip()=="-" else ports
    selected=set()
    for group in spec.split(","):
        if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?",group):
            raise ProfileError("Only TCP port numbers and ascending ranges are permitted")
        values=[int(x) for x in group.split("-")]
        if min(values)<1 or max(values)>65535 or values[0]>values[-1]:
            raise ProfileError("Invalid TCP port bounds")
        selected.update(range(values[0],values[-1]+1))
    if not selected or len(selected)>MAX_DISCOVERY_PORTS:
        raise ProfileError("Discovery permits 1..65535 TCP ports for one authorized host")
    return target,spec,len(selected),address.version

def parse_discovery_xml(raw):
    sanitized=re.sub(r"<!DOCTYPE\s+nmaprun\s*>","",raw,flags=re.I)
    if len(raw.encode("utf-8"))>_nmap_limit or "<!ENTITY" in raw.upper() or "<!DOCTYPE" in sanitized.upper():
        raise ProfileError("Invalid or oversized scanner XML")
    try:
        root=ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ProfileError("Invalid scanner XML") from exc
    if root.tag!="nmaprun":
        raise ProfileError("Unexpected scanner output")
    result={"target":"","hosts":[],"host_state":"","open_ports":[],"ports":[],
            "state_counts":{"open":0,"closed":0,"filtered":0},"profile":DISCOVERY,
            "note":"TCP connect discovery; service names are nmap's port guesses, not probed versions"}
    for host in root.findall("host"):
        status=host.find("status")
        result["host_state"]=status.get("state","up") if status is not None else "up"
        address=host.find("address")
        if address is not None:
            try: result["target"]=str(ipaddress.ip_address(address.get("addr","")))
            except ValueError: raise ProfileError("Scanner returned an invalid numeric destination") from None
            result["hosts"].append(result["target"])
        for port in host.findall("./ports/port"):
            state_el=port.find("state")
            state=state_el.get("state","unknown") if state_el is not None else "unknown"
            service=port.find("service")
            name=service.get("name","unknown") if service is not None else "unknown"
            entry={"port":port.get("portid"),"protocol":port.get("protocol","tcp"),"state":state,
                   "service_guess":name,"confidence":"port-name-guess; run service-version stage to verify"}
            result["ports"].append(entry)
            if state in result["state_counts"]:result["state_counts"][state]+=1
            if state=="open":result["open_ports"].append(entry)
    finished=root.find("./runstats/finished")
    result["scan_complete"]=(finished is not None and finished.get("exit")=="success"
                             and not any(h.get("timedout")=="true" for h in root.findall("host")))
    result["scan_summary"]=finished.get("summary","") if finished is not None else ""
    return result

def run_discovery(tool,params):
    started=time.monotonic()
    try:
        target,ports,count,version=_validate_discovery(tool,params)
        if not _nmap_lock.acquire(blocking=False):
            raise ProfileError("Reviewed scanner concurrency limit reached")
        try:
            executable=_discovery_runtime();before=_trusted(executable)
            with tempfile.TemporaryDirectory(prefix="redvector-discovery-") as name:
                directory=Path(name)
                private=_write_private(directory)
                command=[str(executable),"-sT","--unprivileged","-n","-Pn","--disable-arp-ping",
                         "--max-retries","1","--max-rate",_DISCOVERY_MAX_RATE,
                         "--host-timeout",_DISCOVERY_HOST_TIMEOUT,"--datadir",str(directory),
                         "-p",ports,"-oX","-","--no-stylesheet"]
                if version==6:command.append("-6")
                command.append(target)
                code,stdout,stderr=_nmap_execute(command,directory,timeout=_DISCOVERY_DEADLINE)
                if _trusted(executable)!=before:
                    raise ProfileError("Scanner runtime integrity changed")
                if any(_digest(p)!=digest for p,digest in private.items()):
                    raise ProfileError("Private scanner profile integrity changed")
                parsed=parse_discovery_xml(stdout)
                if code or not parsed["scan_complete"] or len(parsed["hosts"])!=1:
                    return {"success":False,"error":"Reviewed discovery did not complete successfully",
                            "stdout":stdout,"stderr":stderr,"parsed":parsed,
                            "execution_time":time.monotonic()-started,"profile":DISCOVERY}
                if any(x!=target for x in parsed["hosts"]):
                    raise ProfileError("Scanner returned an unexpected destination")
                return {"success":True,"stdout":stdout,"stderr":stderr,"parsed":parsed,
                        "execution_time":time.monotonic()-started,"profile":DISCOVERY,
                        "reviewed_profile":{"ports_requested":ports,"ports_count":count,
                           "engine":"native nmap -sT connect discovery","runtime_sha256":before,
                           "binary":str(executable),"version":_observed_version(executable,directory),
                           "coverage":{"requested":count,"completed":count,"scan_complete":True},
                           "note":"Bounded native Nmap TCP connect discovery; no version probes, NSE, UDP or OS detection in this stage"}}
        finally:
            _nmap_lock.release()
    except (ProfileError,OSError,subprocess.SubprocessError) as exc:
        detail=str(exc) if isinstance(exc,ProfileError) else "Native scanner runtime unavailable or verification failed"
        return {"success":False,"error":detail,"profile":DISCOVERY,
                "execution_time":time.monotonic()-started}

_NMAP_CVE_RE=re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}",re.I)

def parse_nse_xml(raw):
    sanitized=re.sub(r"<!DOCTYPE\s+nmaprun\s*>","",raw,flags=re.I)
    if len(raw.encode("utf-8"))>_nmap_limit or "<!ENTITY" in raw.upper() or "<!DOCTYPE" in sanitized.upper():
        raise ProfileError("Invalid or oversized scanner XML")
    try:
        root=ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ProfileError("Invalid scanner XML") from exc
    if root.tag!="nmaprun":
        raise ProfileError("Unexpected scanner output")
    result={"target":"","hosts":[],"scripts":[],"profile":NSE_VULN,
            "note":"NSE script evidence; a VULNERABLE state is the script's own assessment and requires validation"}
    def entry(script,port,proto):
        output=script.get("output","") or ""
        state=""
        for table in script.iter("table"):
            for elem in table.findall("elem"):
                if elem.get("key")=="state" and elem.text:
                    state=elem.text.strip();break
            if state:break
        if not state and re.search(r"(?i)\bVULNERABLE\b",output):
            state="VULNERABLE (reported in output)"
        table_keys=" ".join(t.get("key","") or "" for t in script.iter("table"))
        return {"port":port,"protocol":proto,"script_id":script.get("id",""),
                "output":output[:4000],"state":state,
                "cve_ids":sorted({m.upper() for m in _NMAP_CVE_RE.findall(output+" "+table_keys)})}
    for host in root.findall("host"):
        address=host.find("address")
        if address is not None:
            try:result["target"]=str(ipaddress.ip_address(address.get("addr","")))
            except ValueError:raise ProfileError("Scanner returned an invalid numeric destination") from None
            result["hosts"].append(result["target"])
        for script in host.findall("./hostscript/script"):
            result["scripts"].append(entry(script,"","host"))
        for port in host.findall("./ports/port"):
            proto=port.get("protocol","tcp");pid=port.get("portid","")
            for script in port.findall("script"):
                result["scripts"].append(entry(script,pid,proto))
    finished=root.find("./runstats/finished")
    result["scan_complete"]=(finished is not None and finished.get("exit")=="success"
                             and not any(h.get("timedout")=="true" for h in root.findall("host")))
    return result

def _validate_nse(tool,params):
    if tool!="nmap_scan" or not isinstance(params,dict):
        raise ProfileError("Unsupported reviewed tool")
    if set(params)!={"target","ports","scan_type","additional_args","use_recovery"}:
        raise ProfileError("Reviewed profile requires exact arguments")
    if params["scan_type"]!=NSE_VULN_PROFILE or params["use_recovery"] is not False:
        raise ProfileError("Only the fixed nse-vuln profile with recovery disabled is permitted")
    if params.get("additional_args","") not in ("",):
        raise ProfileError("The reviewed NSE vuln profile accepts no free-form arguments")
    target=params["target"]
    if not isinstance(target,str) or "%" in target:
        raise ProfileError("A numeric single host is required")
    try:
        address=ipaddress.ip_address(target)
    except ValueError:
        raise ProfileError("A numeric single host is required") from None
    if address.is_multicast or address.is_unspecified or str(address)!=target:
        raise ProfileError("A canonical unicast numeric host is required")
    ports=params["ports"]
    if not isinstance(ports,str) or not ports or len(ports)>2048:
        raise ProfileError("Explicit bounded TCP ports are required")
    selected=set()
    for group in ports.split(","):
        if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?",group):
            raise ProfileError("Only TCP port numbers and ascending ranges are permitted")
        values=[int(x) for x in group.split("-")]
        if min(values)<1 or max(values)>65535 or values[0]>values[-1]:
            raise ProfileError("Invalid TCP port bounds")
        selected.update(range(values[0],values[-1]+1))
    if not selected or len(selected)>MAX_NSE_PORTS:
        raise ProfileError("The NSE vuln profile permits at most 128 explicit TCP ports; discover ports first")
    return target,",".join(map(str,sorted(selected))),len(selected),address.version

def run_nse_vuln(tool,params):
    started=time.monotonic()
    try:
        target,ports,count,version=_validate_nse(tool,params)
    except ProfileError as exc:
        return {"success":False,"profile":NSE_VULN,"error":str(exc),"execution_time":time.monotonic()-started}
    try:
        if not _nmap_lock.acquire(blocking=False):
            raise ProfileError("Reviewed scanner concurrency limit reached")
        try:
            executable,root,files,snapshots=_nmap_runtime()
            before=_trusted(executable)
            with tempfile.TemporaryDirectory(prefix="redvector-nse-disc-") as discovery_dir:
                records=_discover_nse(executable,root,before,Path(discovery_dir))
            summary=nse_summary(records)
            scriptdir=root/"scripts"
            names=[]
            for script in nse_eligible(records,limit=_NSE_MAX_ELIGIBLE):
                path=scriptdir/(script+".nse")
                try:
                    _trusted(path)
                except ProfileError:
                    continue
                names.append(script)
            if not names:
                raise ProfileError("No reviewed low-impact (Category A) NSE vuln script is available to run; "
                                   "nse-vuln-v1 has nothing safe to execute")
            command=[str(executable),"-sV","-sT","--unprivileged","-n","-Pn","--disable-arp-ping",
                     "--max-retries","1","--max-rate",_NSE_MAX_RATE,"--host-timeout",_NSE_HOST_TIMEOUT,
                     "--script-timeout","60s","--datadir",str(root),"--script",",".join(names),
                     "-p",ports,"-oX","-","--no-stylesheet"]
            if version==6:command.append("-6")
            command.append(target)
            code,stdout,stderr=_nmap_execute(command,root,timeout=_NSE_DEADLINE)
            if _trusted(executable)!=before:
                raise ProfileError("Scanner runtime integrity changed")
            parsed=parse_nse_xml(stdout)
            if any(x!=target for x in parsed["hosts"]):
                raise ProfileError("Scanner returned an unexpected destination")
            return {"success":bool(parsed["scan_complete"]) and not code,"stdout":stdout,"stderr":stderr,
                    "parsed":parsed,"execution_time":time.monotonic()-started,"profile":NSE_VULN,
                    "reviewed_profile":{"ports":ports,"ports_count":count,"scripts":list(names),
                       "risk_classification":{"category_a":len(names),"category_b":summary["counts"]["B"],
                          "category_c":summary["counts"]["C"],"category_d":summary["counts"]["D"]},
                       "engine":"native nmap -sV --script (dynamically discovered reviewed low-impact vuln NSE)",
                       "runtime_sha256":before}}
        finally:
            _nmap_lock.release()
    except (ProfileError,OSError,subprocess.SubprocessError) as exc:
        detail=str(exc) if isinstance(exc,ProfileError) else "Native scanner runtime unavailable or verification failed"
        return {"success":False,"error":detail,"profile":NSE_VULN,"execution_time":time.monotonic()-started}


# ══════════════════════════════════════════════════════════════════════════════
# ASSESSMENT — Shared root-response capture and offline Nuclei assessment profiles
# ══════════════════════════════════════════════════════════════════════════════

HTTP_PROFILE="redvector-http-read-v1"
NUCLEI_PROFILE="--redvector-profile=http-headers-v1"
NUCLEI_BUILDS={
    "c49588140f357cbdddd5436dec11201953a4c5390faeec90777f9ee2cfd70251":{
        "version":"v3.11.1","platform":"linux/amd64",
        "capabilities":["offline-root-response-header-templates"],
        "template_requirements":"fixed reviewed root-response header templates; remote template download disabled",
        "evidence":"Installed and checksum-verified via tools/install_reviewed_nuclei.py; offline header profile exercised in the native sandbox regression."},
}
_ASSESSMENT_LIMIT=65536
_assessment_lock=threading.Lock()
_HTTP_SLOTS=threading.BoundedSemaphore(2)
class AssessmentError(ValueError):pass

def assessment_digest(path):
    value=hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda:stream.read(1048576),b""):value.update(block)
    return value.hexdigest()

def validate_url(value):
    if not isinstance(value,str) or len(value)>1024 or any(c.isspace() for c in value):
        raise AssessmentError("Use one canonical root HTTP(S) URL.")
    u=urlsplit(value)
    if u.scheme not in ("http","https") or u.username or u.password or u.query or u.fragment or u.path not in ("","/"):
        raise AssessmentError("Reviewed root-response profile permits HTTP(S) / only, without credentials/query/fragment.")
    try:
        ip=ipaddress.ip_address(u.hostname or "")
        port=u.port or (443 if u.scheme=="https" else 80)
    except ValueError:raise AssessmentError("Numeric pinned destination and valid port required.") from None
    if ip.is_unspecified or ip.is_multicast or "%" in str(ip) or not 1<=port<=65535:
        raise AssessmentError("Canonical unicast destination required.")
    return u,str(ip),port

def _fetch(url,method="GET",headers=None):
    u,host,port=validate_url(url)
    if method not in ("GET","HEAD"):raise AssessmentError("Only GET and HEAD are supported.")
    headers=headers or {}
    if set(headers)-{"Host"}:raise AssessmentError("Custom headers/cookies are not part of this profile.")
    authority=headers.get("Host",u.netloc)
    if not isinstance(authority,str) or not re.fullmatch(r"[A-Za-z0-9.:[\]-]{1,260}",authority):
        raise AssessmentError("Invalid Host authority.")
    conn=http.client.HTTPConnection(host,port,timeout=3)
    if u.scheme=="https":
        class PinnedTLS(http.client.HTTPSConnection):
            def connect(self):
                raw=socket.create_connection((host,port),timeout=self.timeout)
                name=authority
                if name.startswith("["):name=name[1:name.index("]")]
                elif name.count(":")==1:name=name.split(":")[0]
                try:self.sock=ssl.create_default_context().wrap_socket(raw,server_hostname=name)
                except BaseException:raw.close();raise
        conn=PinnedTLS(host,port,timeout=3)
    active=[None];expired=threading.Event()
    def expire():
        expired.set()
        sock=active[0] or conn.sock
        if sock:
            try:sock.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        conn.close()
    timer=threading.Timer(10,expire);timer.daemon=True;timer.start()
    started=time.monotonic()
    try:
        conn.request(method,"/",headers={"Host":authority,"User-Agent":"RedVector-Reviewed/8","Accept":"*/*","Connection":"close"})
        active[0]=conn.sock
        response=conn.getresponse()
        pairs=response.getheaders()
        if sum(len(k)+len(v) for k,v in pairs)>16384:raise AssessmentError("Response header limit exceeded.")
        chunks=[];total=0
        while method!="HEAD":
            if time.monotonic()-started>10:raise AssessmentError("Response deadline exceeded.")
            chunk=response.read1(min(4096,_ASSESSMENT_LIMIT+1-total))
            if expired.is_set():raise AssessmentError("Response deadline exceeded.")
            if not chunk:
                if response.length is not None and response.length>0:raise AssessmentError("Response ended before its declared content length.")
                break
            chunks.append(chunk);total+=len(chunk)
            if total>_ASSESSMENT_LIMIT:raise AssessmentError("Response exceeds 64 KiB; no partial assessment reported.")
        body=b"".join(chunks).decode("utf-8","replace")
        raw="HTTP/1.1 "+str(response.status)+" "+response.reason+"\r\n"+"".join(k+": "+v+"\r\n" for k,v in pairs)+"\r\n"+body
        return {"status_code":response.status,"headers":{k.lower():v for k,v in pairs},"body":body,
                "raw":raw,"redirect_followed":False}
    except (OSError,http.client.HTTPException):
        if expired.is_set():raise AssessmentError("Response deadline exceeded.") from None
        raise
    finally:timer.cancel();conn.close()

def fetch(url,method="GET",headers=None):
    if not _HTTP_SLOTS.acquire(blocking=False):
        raise AssessmentError("Root-response concurrency limit reached.")
    try:return _fetch(url,method,headers)
    finally:_HTTP_SLOTS.release()

def run_http(params):
    try:
        if set(params)-{"url","method","headers","cookies","data","action"} or params.get("action")!=HTTP_PROFILE:
            raise AssessmentError("Exact reviewed HTTP profile required.")
        if params.get("data") not in (None,{}) or params.get("cookies") not in (None,{}):
            raise AssessmentError("Request bodies and cookies are not supported by this profile.")
        value=fetch(params.get("url"),params.get("method","GET"),params.get("headers"))
        return {"success":True,"profile":HTTP_PROFILE,"target":params["url"],"result":value,
                "limitations":"One root response; no crawling, redirects, active payloads or inferred vulnerabilities."}
    except (AssessmentError,OSError,ValueError,http.client.HTTPException) as exc:
        return {"success":False,"profile":HTTP_PROFILE,"error":str(exc)[:300]}

def nuclei_version(output):
    text=output.decode("utf-8","replace") if isinstance(output,(bytes,bytearray)) else str(output)
    match=re.search(r"\bv?([0-9]+\.[0-9]+\.[0-9]+)\b",text)
    return ("v"+match.group(1)) if match else ""

def nuclei_binary():
    value=os.environ.get("REDVECTOR_NUCLEI_BIN") or shutil.which("nuclei")
    if not value:raise AssessmentError("Missing Dependency: configure REDVECTOR_NUCLEI_BIN or install Nuclei on the backend PATH.")
    path=Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise AssessmentError("Unsupported Nuclei runtime: an absolute, non-symlink regular-file path is required.")
    actual=assessment_digest(path)
    meta=NUCLEI_BUILDS.get(actual)
    if not meta:
        test_mode=os.environ.get("REDVECTOR_NUCLEI_ALLOW_CANDIDATE","") == "testing"
        candidate=os.environ.get("REDVECTOR_NUCLEI_CANDIDATE_SHA256","").lower().strip()
        if test_mode and candidate and actual==candidate:
            meta={"version":"","platform":"","capabilities":["offline-root-response-header-templates"],
                  "template_requirements":"candidate testing — not yet in production registry",
                  "evidence":"candidate","candidate":True}
        else:
            raise AssessmentError("Unsupported Nuclei runtime: unknown/unverified build (configured binary sha256 "+actual[:12]
                +"...). Only individually reviewed, checksum-verified Nuclei builds are accepted; install a reviewed build "
                "with tools/install_reviewed_nuclei.py and point REDVECTOR_NUCLEI_BIN at it. A different build stays "
                "unavailable until reviewed; attestation is not bypassed.")
    return path,dict(meta,sha256=actual)

def no_network():
    if not sys.platform.startswith("linux") or platform.machine() not in ("x86_64","amd64"):
        raise AssessmentError("Offline Nuclei sandbox requires Linux amd64.")
    class Filter(ctypes.Structure):
        _fields_=[("code",ctypes.c_ushort),("jt",ctypes.c_ubyte),("jf",ctypes.c_ubyte),("k",ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_=[("length",ctypes.c_ushort),("filter",ctypes.POINTER(Filter))]
    rules=[(0x20,0,0,4),(0x15,1,0,0xc000003e),(0x06,0,0,0x50001),(0x20,0,0,0),
           (0x35,0,1,0x40000000),(0x06,0,0,0x50001)]
    for number in (41,42,44,46,307):
        rules.extend([(0x15,0,1,number),(0x06,0,0,0x50001)])
    rules.append((0x06,0,0,0x7fff0000))
    array=(Filter*len(rules))(*(Filter(*r) for r in rules));program=Program(len(rules),array)
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(38,1,0,0,0) or libc.prctl(22,2,ctypes.byref(program),0,0):
        raise AssessmentError("Offline scanner network sandbox unavailable.")

def _env(directory):
    env={"PATH":os.defpath,"HOME":str(directory),"XDG_CONFIG_HOME":str(directory),
            "XDG_CACHE_HOME":str(directory),"LC_ALL":"C","DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD":"true",
            "DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD":"true","DISABLE_NUCLEI_TEMPLATES_GITLAB_DOWNLOAD":"true"}
    if os.environ.get("REDVECTOR_NUCLEI_ALLOW_CANDIDATE","") == "testing":
        candidate=os.environ.get("REDVECTOR_NUCLEI_CANDIDATE_SHA256","").lower().strip()
        if candidate:env["REDVECTOR_NUCLEI_CANDIDATE_SHA256"]=candidate
    return env

def _nuclei_command(binary,args,directory):
    return subprocess.run([sys.executable,str(Path(__file__).resolve()),"--offline-nuclei",str(binary),*args],
        cwd=directory,env=_env(directory),stdin=subprocess.DEVNULL,capture_output=True,timeout=30)

def assessment_capabilities():
    states={HTTP_PROFILE:{"state":"Ready","detail":"Pinned one-root GET/HEAD; redirects/proxies/credentials disabled."},
            SCAN_PROFILE:{"state":"Ready","detail":"Bounded TCP connect discovery; <=128 explicit ports, <=64 concurrent, 1s connect timeout, 20s deadline; native masscan/rustscan not executed."}}
    try:
        binary,meta=nuclei_binary()
        if meta.get("candidate"):
            raise AssessmentError(
                "Unsupported: unregistered candidate build detected. "
                "Add to NUCLEI_BUILDS with mode-A execution evidence before production use. "
                "Use the W6 acceptance test to validate the subprocess execution path.")
        if not sys.platform.startswith("linux") or platform.machine() not in ("x86_64","amd64"):
            raise AssessmentError("Unsupported native sandbox platform.")
        with tempfile.TemporaryDirectory(prefix="rv-nuclei-check-") as d:
            result=_nuclei_command(binary,["-version"],Path(d))
            detected=nuclei_version(result.stdout+result.stderr)
            if result.returncode:
                raise AssessmentError("Nuclei runtime or network sandbox preflight failed.")
            if meta.get("version") and detected!=meta["version"]:
                raise AssessmentError("Nuclei runtime or network sandbox preflight failed: detected "
                    +(detected or "unknown")+" does not match the reviewed build's version "+meta["version"]+".")
        states[NUCLEI_PROFILE]={"state":"Ready","detail":"Offline Nuclei "+meta["version"]+" (reviewed build "+meta["sha256"][:12]+"...); fixed root-response header templates; scanner sockets denied by seccomp."}
    except (AssessmentError,OSError,subprocess.SubprocessError) as exc:
        detail=str(exc)[:300];states[NUCLEI_PROFILE]={"state":"Missing Dependency" if "Missing Dependency" in detail else "Unsupported","detail":detail}
    return states

def template(ident,header):
    return ('id: '+ident+'\ninfo:\n  name: Missing '+header+' response header\n  author: redvector\n  severity: info\n'
            'http:\n  - method: GET\n    path:\n      - "{{BaseURL}}"\n    matchers:\n      - type: word\n'
            '        part: header\n        words:\n          - "'+header+':"\n        case-insensitive: true\n        negative: true\n')

def run_nuclei(params):
    started=time.monotonic()
    try:
        if set(params)-{"target","severity","tags","template","additional_args","use_recovery"}:
            raise AssessmentError("Unexpected Nuclei arguments.")
        if params.get("template")!=NUCLEI_PROFILE or params.get("use_recovery") is not False or any(params.get(k,"") for k in ("severity","tags")):
            raise AssessmentError("Fixed offline Nuclei profile with recovery disabled required.")
        binary,meta=nuclei_binary()
        if meta.get("candidate"):
            raise AssessmentError("Candidate builds are not available for production assessments; "
                "add to NUCLEI_BUILDS with mode-A evidence first.")
        if not _assessment_lock.acquire(blocking=False):raise AssessmentError("Assessment concurrency limit reached.")
        try:
            authority=params.get("additional_args","")
            headers=None
            if authority:
                if not isinstance(authority,str) or not authority.startswith("--redvector-authority="):
                    raise AssessmentError("Only the internal pinned authority marker is permitted.")
                value=authority.split("=",1)[1]
                if not re.fullmatch(r"[A-Za-z0-9.:[\]-]{1,260}",value):
                    raise AssessmentError("Invalid internal authority.")
                headers={"Host":value}
            captured=fetch(params.get("target"),headers=headers)
            with tempfile.TemporaryDirectory(prefix="rv-nuclei-evidence-") as d:
                directory=Path(d);responses=directory/"responses";responses.mkdir()
                header_input=captured["raw"].split("\r\n",1)[0]+"\r\n"
                for key,value in captured["headers"].items():
                    if key.lower() not in {"transfer-encoding","content-encoding","content-length","trailer","connection"}:
                        header_input+=key+": "+value+"\r\n"
                header_input+="Content-Length: 0\r\n\r\n"
                (responses/"response.txt").write_text(header_input,encoding="utf-8")
                templates=directory/"templates";templates.mkdir()
                for ident,header in [("rv-missing-nosniff","X-Content-Type-Options"),("rv-missing-frame-options","X-Frame-Options")]:
                    (templates/(ident+".yaml")).write_text(template(ident,header),encoding="utf-8")
                result=_nuclei_command(binary,["-passive","-u",str(responses),"-t",str(templates),"-ni","-duc","-dr","-nh","-no-stdin","-jsonl","-silent","-nc","-omit-raw","-c","1","-bs","1","-timeout","3","-retries","0"],directory)
                if result.returncode or len(result.stdout)+len(result.stderr)>1048576:
                    raise AssessmentError("Offline Nuclei failed or exceeded output budget.")
                rows=[]
                for line in result.stdout.decode("utf-8","strict").splitlines():
                    item=json.loads(line)
                    ident=item.get("template-id")
                    if ident not in ("rv-missing-nosniff","rv-missing-frame-options"):raise AssessmentError("Unexpected template result.")
                    rows.append({"id":ident,"title":item["info"]["name"],"severity":"info",
                                 "evidence":{"status_code":captured["status_code"],"response_headers":captured["headers"]},
                                 "validation":"Observed response configuration; exploitability not assessed"})
                expected={ident for ident,key in [("rv-missing-nosniff","x-content-type-options"),("rv-missing-frame-options","x-frame-options")] if key not in captured["headers"]}
                if {row["id"] for row in rows}!=expected or len(rows)!=len(expected):
                    raise AssessmentError("Nuclei header matches conflict with actual captured evidence; assessment is not clean.")
                return {"success":True,"input_representation":"Canonical header-only response; body/framing excluded from offline checks.","profile":NUCLEI_PROFILE,"target":params["target"],"findings":rows,
                        "stdout":result.stdout.decode(),"execution_time":time.monotonic()-started,
                        "limitations":"Two passive root-response header checks only; absence is not proof of exploitable vulnerability.",
                        "scanner":{"name":"nuclei","version":meta["version"],"sha256":meta["sha256"],"network":"seccomp denied sockets"}}
        finally:_assessment_lock.release()
    except (AssessmentError,OSError,ValueError,KeyError,subprocess.SubprocessError,http.client.HTTPException) as exc:
        return {"success":False,"profile":NUCLEI_PROFILE,"error":str(exc)[:300]}

HTTP_ASSESS_MARKER="--redvector-http-assess-v1"
ASSESS_TOOLS=frozenset({"httpx_probe","nikto_scan","wafw00f_scan","jaeles_vulnerability_scan"})
_SECURITY_HEADERS=[("strict-transport-security","HSTS"),("content-security-policy","Content-Security-Policy"),
    ("x-frame-options","X-Frame-Options"),("x-content-type-options","X-Content-Type-Options"),
    ("referrer-policy","Referrer-Policy"),("permissions-policy","Permissions-Policy")]
_WAF_SIGNATURES=[("Cloudflare","server","cloudflare"),("Cloudflare","cf-ray",""),("Sucuri","x-sucuri-id",""),
    ("Sucuri","server","sucuri"),("Akamai","server","akamaighost"),("Imperva Incapsula","x-iinfo",""),
    ("Imperva Incapsula","set-cookie","incap_ses"),("AWS CloudFront","server","cloudfront"),
    ("AWS CloudFront","x-amz-cf-id",""),("Fastly","x-served-by","cache"),("Fastly","server","fastly"),
    ("F5 BIG-IP","set-cookie","bigipserver"),("Barracuda","set-cookie","barra_counter_session"),
    ("Wallarm","server","wallarm"),("Fortinet FortiWeb","set-cookie","fortiwafsid")]
_TECH_SIGNATURES=[("nginx","server","nginx"),("Apache","server","apache"),("Microsoft-IIS","server","microsoft-iis"),
    ("PHP","x-powered-by","php"),("ASP.NET","x-powered-by","asp.net"),("ASP.NET","x-aspnet-version",""),
    ("Express","x-powered-by","express"),("OpenResty","server","openresty"),("LiteSpeed","server","litespeed"),
    ("Werkzeug","server","werkzeug")]
_JAELES_SIGNATURES=[("rv-info-powered-by","Technology disclosure via X-Powered-By","info","header","x-powered-by",None),
    ("rv-info-aspnet-version","ASP.NET version disclosure","low","header","x-aspnet-version",None),
    ("rv-info-server-version","Server banner version disclosure","info","header","server",r"\d"),
    ("rv-expo-status","Exposed server-status page","low","body",None,r"(?i)apache server status|/server-status"),
    ("rv-error-stacktrace","Verbose error/stack trace in response","low","body",None,r"(?i)traceback \(most recent call last\)|fatal error:|exception in thread"),
    ("rv-info-phpinfo","phpinfo output exposed","low","body",None,r"(?i)<title>phpinfo\(\)"),
    ("rv-default-page","Default/placeholder landing page","info","body",None,r"(?i)it works!|welcome to nginx!")]

def _title(body):
    match=re.search(r"<title[^>]*>(.*?)</title>",body or "",re.IGNORECASE|re.DOTALL)
    return re.sub(r"\s+"," ",match.group(1)).strip()[:200] if match else ""

def _technologies(headers):
    found=[]
    for name,key,needle in _TECH_SIGNATURES:
        value=headers.get(key,"")
        if value and (needle=="" or needle in value.lower()) and name not in found:found.append(name)
    return found

def _httpx_probe(captured):
    headers=captured["headers"]
    return {"probe":{"status_code":captured["status_code"],"title":_title(captured["body"]),
        "webserver":headers.get("server",""),"content_type":headers.get("content-type",""),
        "content_length":len(captured["body"].encode("utf-8","replace")),"powered_by":headers.get("x-powered-by",""),
        "technologies":_technologies(headers),"redirect_followed":False}}

def _wafw00f(captured):
    headers=captured["headers"];vendors=[];seen=set()
    for name,key,needle in _WAF_SIGNATURES:
        value=headers.get(key,"")
        if value and (needle=="" or needle in value.lower()) and name not in seen:
            seen.add(name);vendors.append({"name":name,"evidence":{key:value[:200]}})
    return {"waf":{"detected":bool(vendors),"vendors":vendors,"signatures_evaluated":len(_WAF_SIGNATURES)}}

def _nikto(captured):
    headers=captured["headers"];findings=[]
    if re.search(r"\d",headers.get("server","")):
        findings.append({"id":"rv-server-banner","title":"Server banner version disclosure","severity":"info","evidence":{"server":headers["server"][:200]}})
    if headers.get("x-powered-by"):
        findings.append({"id":"rv-powered-by","title":"X-Powered-By technology disclosure","severity":"info","evidence":{"x-powered-by":headers["x-powered-by"][:200]}})
    for key,label in _SECURITY_HEADERS:
        if key=="strict-transport-security" and not captured.get("scheme_https"):continue
        if key not in headers:
            findings.append({"id":"rv-missing-"+key,"title":"Missing "+label+" response header","severity":"info","evidence":{"header":label}})
    cookie=headers.get("set-cookie","")
    if cookie:
        lowered=cookie.lower()
        for flag in ("secure","httponly"):
            if flag not in lowered:
                findings.append({"id":"rv-cookie-"+flag,"title":"Root Set-Cookie without "+flag.capitalize()+" flag","severity":"low","evidence":{"set-cookie":cookie[:120]}})
    if re.search(r"(?i)<title>index of /|directory listing for",captured["body"] or ""):
        findings.append({"id":"rv-dir-listing","title":"Directory listing exposed on root","severity":"low","evidence":{"body":"index listing marker"}})
    for row in findings:row["validation"]="Observed response configuration; exploitability not assessed"
    return {"findings":findings}

def _jaeles(captured):
    headers=captured["headers"];body=captured["body"] or "";matches=[]
    for ident,name,severity,location,key,pattern in _JAELES_SIGNATURES:
        hit=None
        if location=="header":
            value=headers.get(key,"")
            if value and (pattern is None or re.search(pattern,value)):hit={key:value[:200]}
        else:
            found=re.search(pattern,body)
            if found:hit={"body":found.group(0)[:120]}
        if hit:matches.append({"id":ident,"name":name,"severity":severity,"location":location,"evidence":hit,
            "validation":"Passive signature match on one root response; not an active exploit test"})
    return {"matches":matches,"signatures_evaluated":len(_JAELES_SIGNATURES)}

_ASSESS_ANALYZERS={"httpx_probe":_httpx_probe,"wafw00f_scan":_wafw00f,"nikto_scan":_nikto,"jaeles_vulnerability_scan":_jaeles}
_ASSESS_LIMITS={
    "httpx_probe":"One confined TLS-verified root GET; status/title/server/technology are actual response observations. No port lists, crawling, file probing or external httpx binary.",
    "wafw00f_scan":"Passive WAF/CDN fingerprint from one root response's headers only; absence is not proof that no WAF is present; no active WAF-triggering payloads.",
    "nikto_scan":"Passive security-configuration review of one root response; a bounded subset of server/header/cookie checks, not a full Nikto scan and no external Nikto binary is run.",
    "jaeles_vulnerability_scan":"Fixed passive signature set matched against one root response; not Jaeles active signature testing and no external Jaeles binary is run."}

def run_http_assessment(tool,params):
    try:
        if tool not in ASSESS_TOOLS:raise AssessmentError("Unknown reviewed HTTP assessment tool.")
        allowed={"target","url","additional_args","probe","tech_detect","status_code","content_length","title","web_server","threads","signatures","config","timeout"}
        if not isinstance(params,dict) or set(params)-allowed:raise AssessmentError("Unexpected reviewed assessment arguments.")
        if params.get("additional_args")!=HTTP_ASSESS_MARKER:raise AssessmentError("Reviewed HTTP assessment profile marker required.")
        url=params.get("url") if tool=="jaeles_vulnerability_scan" else params.get("target")
        u,_host,_port=validate_url(url)
        captured=fetch(url,"GET")
        captured["scheme_https"]=(u.scheme=="https")
        result=_ASSESS_ANALYZERS[tool](captured)
        result.update(success=True,profile=HTTP_ASSESS_MARKER,tool=tool,target=url,status_code=captured["status_code"],
            engine="redvector-reviewed-passive-http",
            scanner={"name":tool.split("_")[0],"mode":"RedVector reviewed passive collector; no external scanner binary executed"},
            limitations=_ASSESS_LIMITS[tool])
        return result
    except (AssessmentError,OSError,ValueError,KeyError,http.client.HTTPException) as exc:
        return {"success":False,"profile":HTTP_ASSESS_MARKER,"tool":tool,"error":str(exc)[:300]}

SCAN_PROFILE="redvector-tcp-connect-v1"
SCAN_MARKER="--redvector-tcp-connect-v1"
SCAN_TOOLS=frozenset({"masscan_high_speed","rustscan_fast_scan"})
_SCAN_MAX_PORTS=128
_SCAN_WORKERS=64
_SCAN_SLOTS=threading.BoundedSemaphore(_SCAN_WORKERS)
_SCAN_CONNECT_TIMEOUT=1.0
_SCAN_DEADLINE=20.0

def _unicast_ip(value):
    ip=ipaddress.ip_address(value)
    if ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        raise AssessmentError("A canonical unicast numeric target is required.")
    return ip

def _scan_ports(spec):
    ports=[]
    for group in str(spec).split(","):
        if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?",group or ""):raise AssessmentError("Ports must be numbers or ascending ranges.")
        nums=[int(n) for n in group.split("-")]
        if not all(1<=n<=65535 for n in nums) or nums[0]>nums[-1]:raise AssessmentError("Ports must be within 1..65535 and ascending.")
        ports.extend(range(nums[0],nums[-1]+1))
    ports=sorted(set(ports))
    if not ports or len(ports)>_SCAN_MAX_PORTS:raise AssessmentError("Reviewed bounded TCP discovery permits 1..128 explicit ports.")
    return ports

def _connect(host,port,family,deadline):
    remaining=deadline-time.monotonic()
    if remaining<=0 or not _SCAN_SLOTS.acquire(blocking=True,timeout=remaining):return port,"filtered"
    try:
        remaining=deadline-time.monotonic()
        if remaining<=0:return port,"filtered"
        sock=socket.socket(family,socket.SOCK_STREAM);sock.settimeout(min(_SCAN_CONNECT_TIMEOUT,remaining))
        try:
            sock.connect((host,port));return port,"open"
        except (socket.timeout,TimeoutError):return port,"filtered"
        except ConnectionRefusedError:return port,"closed"
        except OSError as exc:return port,("closed" if exc.errno==111 else "filtered")
        finally:sock.close()
    finally:_SCAN_SLOTS.release()

def run_tcp_connect(tool,params):
    started=time.monotonic()
    try:
        if tool not in SCAN_TOOLS:raise AssessmentError("Unknown reviewed TCP discovery tool.")
        allowed={"target","ports","additional_args","rate","interface","router_mac","source_ip","banners","ulimit","batch_size","timeout","scripts"}
        if not isinstance(params,dict) or set(params)-allowed:raise AssessmentError("Unexpected reviewed scan arguments.")
        if params.get("additional_args")!=SCAN_MARKER:raise AssessmentError("Reviewed bounded TCP discovery marker required.")
        host=params.get("target")
        if not isinstance(host,str):raise AssessmentError("A single numeric target is required.")
        ip=_unicast_ip(host);ports=_scan_ports(params.get("ports",""))
        family=socket.AF_INET6 if ip.version==6 else socket.AF_INET
        deadline=started+_SCAN_DEADLINE;results=[]
        with concurrent.futures.ThreadPoolExecutor(max_workers=_SCAN_WORKERS) as pool:
            for port,state in pool.map(lambda p:_connect(str(ip),p,family,deadline),ports):
                results.append({"port":port,"state":state})
        results.sort(key=lambda row:row["port"])
        open_ports=[row["port"] for row in results if row["state"]=="open"]
        return {"success":True,"profile":SCAN_PROFILE,"requested_tool":tool,"engine":"redvector-reviewed-tcp-connect",
                "scanner":{"name":tool.split("_")[0],"mode":"RedVector reviewed bounded TCP connect engine; native masscan/rustscan not executed"},
                "target":str(ip),"ports_scanned":len(ports),"open_ports":open_ports,"results":results,
                "execution_time":time.monotonic()-started,
                "limitations":"Bounded TCP connect() discovery only: at most 128 explicit ports, <=64 concurrent connections, 1s per-connect timeout and a 20s overall deadline. Not native masscan/rustscan; no raw sockets, high-speed/internet-scale rates, banners, UDP or OS detection."}
    except (AssessmentError,OSError,ValueError) as exc:
        return {"success":False,"profile":SCAN_PROFILE,"requested_tool":tool,"error":str(exc)[:300]}


# ══════════════════════════════════════════════════════════════════════════════
# ARTIFACTS — Read-only operator-selected artifact profiles; private staging and native sandbox
# ══════════════════════════════════════════════════════════════════════════════

ARTIFACT_PREFIX="rv-artifact-v1:"
ARTIFACT_PROFILE="artifact-read-v1"
ARTIFACT_TOOLS=frozenset({"strings_extract","xxd_hexdump","objdump_analyze","checksec_analyze"})
ARTIFACT_ENGINES={"strings_extract":"strings","objdump_analyze":"objdump","checksec_analyze":"readelf"}
ARTIFACT_MAX_BYTES=4*1024*1024
ARTIFACT_OUTPUT_LIMIT=512*1024
class ArtifactError(ValueError):pass

class ArtifactStore:
    def __init__(self,directory=None):
        self._temp=tempfile.TemporaryDirectory(prefix="redvector-artifacts-") if directory is None else None
        self.base=Path(self._temp.name if self._temp else directory)
        self.base.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.records={};self.lock=threading.RLock()
    def _purge(self):
        now=time.monotonic()
        for key,row in list(self.records.items()):
            if now-row["created"]>900:
                row["path"].unlink(missing_ok=True);del self.records[key]
    def put(self,session,data,digest):
        if not re.fullmatch("[0-9a-f]{32}",session or "") or not isinstance(data,bytes) or not 0<len(data)<=ARTIFACT_MAX_BYTES:
            raise ArtifactError("Invalid artifact session or size (1 byte..4 MiB).")
        actual=hashlib.sha256(data).hexdigest()
        if digest!=actual:raise ArtifactError("Artifact digest mismatch.")
        with self.lock:
            self._purge()
            if len(self.records)>=16:raise ArtifactError("Artifact staging capacity reached; clear a previous selection.")
            ident=uuid.uuid4().hex;path=self.base/ident
            fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,"O_NOFOLLOW",0),0o600)
            with os.fdopen(fd,"wb") as out:out.write(data)
            self.records[ident]={"session":session,"sha256":actual,"path":path,"created":time.monotonic()}
            def expire():
                with self.lock:self._purge()
            timer=threading.Timer(901,expire);timer.daemon=True;timer.start()
            return ARTIFACT_PREFIX+session+":"+ident+":"+actual
    def _row(self,token):
        match=re.fullmatch(re.escape(ARTIFACT_PREFIX)+"([0-9a-f]{32}):([0-9a-f]{32}):([0-9a-f]{64})",token if isinstance(token,str) else "")
        if not match:raise ArtifactError("Invalid selected-artifact handle.")
        self._purge();row=self.records.get(match[2])
        if not row or row["session"]!=match[1] or row["sha256"]!=match[3]:raise ArtifactError("Artifact selection is unknown, expired or belongs to another session.")
        return row
    def path(self,token):
        with self.lock:return self._row(token)["path"]
    def read(self,token):
        with self.lock:
            row=self._row(token);path=row["path"]
            if path.is_symlink():raise ArtifactError("Staged artifact is not a regular snapshot.")
            fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
            with os.fdopen(fd,"rb") as src:
                before=os.fstat(src.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size>ARTIFACT_MAX_BYTES:raise ArtifactError("Invalid artifact snapshot.")
                data=src.read(ARTIFACT_MAX_BYTES+1);after=os.fstat(src.fileno())
            if (before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns) or hashlib.sha256(data).hexdigest()!=row["sha256"]:
                raise ArtifactError("Selected artifact changed; select it again.")
            return data
    def remove(self,token):
        with self.lock:
            row=self._row(token)
            for ident,value in list(self.records.items()):
                if value is row:row["path"].unlink(missing_ok=True);del self.records[ident];break

_STORE=None
_STORE_LOCK=threading.Lock()
_PARSER_SLOTS=threading.BoundedSemaphore(2)
def artifact_store():
    global _STORE
    with _STORE_LOCK:
        if _STORE is None:_STORE=ArtifactStore()
        return _STORE

def artifact_options(tool,params):
    if tool not in ARTIFACT_TOOLS:raise ArtifactError("Unknown artifact tool.")
    if params.get("additional_args",""):raise ArtifactError("Free-form artifact arguments are not supported.")
    if tool=="strings_extract":
        n=params.get("min_len",4)
        if type(n) is not int or not 4<=n<=64:raise ArtifactError("Minimum string length must be 4..64.")
        return ["-a","-n",str(n),"-t","x","/work/input"]
    if tool=="objdump_analyze":
        if type(params.get("disassemble",False)) is not bool:raise ArtifactError("Disassemble must be boolean.")
        return ["-w","-d" if params.get("disassemble",False) else "-x","/work/input"]
    if tool=="checksec_analyze":return ["-W","-h","-l","-d","/work/input"]
    for key,default,maximum in [("offset","0",ARTIFACT_MAX_BYTES),("length","4096",4096)]:
        value=params.get(key,default) or default
        if not isinstance(value,str) or not re.fullmatch(r"(?:[0-9]{1,10}|0x[0-9a-fA-F]{1,8})",value):
            raise ArtifactError("Hex offset/length must be bounded nonnegative decimal or hex.")
        n=int(value,16 if value.startswith("0x") else 10)
        if not 0<=n<=maximum or (key=="length" and n==0):raise ArtifactError("Hex offset/length exceeds profile bounds.")
    return []

def artifact_runtime(tool):
    if not sys.platform.startswith("linux"):raise ArtifactError("Unsupported: native artifact parsers require Linux.")
    executable=shutil.which(ARTIFACT_ENGINES[tool]);bubble=shutil.which("bwrap");ldd=shutil.which("ldd")
    if not all((executable,bubble,ldd)):raise ArtifactError("Missing Dependency: "+ARTIFACT_ENGINES[tool]+", Bubblewrap and ldd are required.")
    executable=Path(executable).resolve();bubble=Path(bubble).resolve();ldd=Path(ldd).resolve()
    snapshots={p:_trusted(p) for p in (executable,bubble,ldd)}
    listed=subprocess.run([str(ldd),str(executable)],capture_output=True,text=True,timeout=5,env={"PATH":os.defpath,"LC_ALL":"C"})
    if listed.returncode or len(listed.stdout)>32768:raise ArtifactError("Native library inventory could not be verified.")
    libraries=[]
    for raw in re.findall(r"(?<![A-Za-z0-9_])(/[^\s()]+)",listed.stdout):
        source=Path(raw).resolve()
        snapshots[source]=_trusted(source)
        if (source,raw) not in libraries:libraries.append((source,raw))
    if not libraries:raise ArtifactError("Native loader/library identity unavailable.")
    cache=Path("/etc/ld.so.cache")
    if cache.is_file():snapshots[cache]=_trusted(cache);libraries.append((cache,str(cache)))
    return executable,bubble,libraries,snapshots

def artifact_sandbox_command(tool,input_path,args):
    executable,bubble,libraries,snapshots=artifact_runtime(tool)
    cmd=[str(bubble),"--unshare-all","--die-with-parent","--new-session","--clearenv",
         "--setenv","LC_ALL","C","--setenv","HOME","/work","--setenv","PATH","/",
         "--proc","/proc","--dev","/dev","--tmpfs","/tmp","--dir","/work",
         "--ro-bind",str(executable),"/tool"]
    for source,dest in libraries:
        cmd+=["--ro-bind",str(source),dest]
    if input_path is not None:cmd+=["--ro-bind",str(input_path),"/work/input"]
    cmd+=["--chdir","/work","--","/tool",*args]
    return cmd,snapshots

def _artifact_capture(command,directory,timeout=12):
    process=subprocess.Popen(command,cwd=directory,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env={"PATH":os.defpath,"LC_ALL":"C"},start_new_session=True)
    result={"stdout":bytearray(),"stderr":bytearray()};deadline=time.monotonic()+timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout,selectors.EVENT_READ,"stdout");selector.register(process.stderr,selectors.EVENT_READ,"stderr")
            while selector.get_map():
                remaining=deadline-time.monotonic()
                if remaining<=0:raise ArtifactError("Artifact parser deadline exceeded.")
                for key,_ in selector.select(min(.1,remaining)):
                    chunk=os.read(key.fileobj.fileno(),65536)
                    if not chunk:selector.unregister(key.fileobj);continue
                    result[key.data].extend(chunk)
                    if sum(map(len,result.values()))>ARTIFACT_OUTPUT_LIMIT:raise ArtifactError("Artifact output exceeds 512 KiB; execution was not reported complete.")
            code=process.wait(timeout=max(.01,deadline-time.monotonic()))
            return code,bytes(result["stdout"]).decode("utf-8","replace"),bytes(result["stderr"]).decode("utf-8","replace")
    finally:
        if process.poll() is None:process.kill();process.wait(timeout=5)
        process.stdout.close();process.stderr.close()

def artifact_capabilities():
    result={ARTIFACT_PROFILE:{"state":"Ready","detail":"Operator-selected private regular-file snapshots only; max 4 MiB."}}
    for tool in ARTIFACT_TOOLS:
        key=ARTIFACT_PROFILE+":"+tool
        if tool=="xxd_hexdump":
            result[key]={"state":"Ready","detail":"Actual bytes formatted by bounded Python hex engine; no external xxd binary claimed."};continue
        try:
            cmd,snapshots=artifact_sandbox_command(tool,None,["--version"])
            checked=subprocess.run(cmd,capture_output=True,timeout=8,env={"PATH":os.defpath,"LC_ALL":"C"})
            if checked.returncode or b"GNU" not in checked.stdout:raise ArtifactError("Native filesystem/network sandbox preflight failed.")
            if any(_trusted(p)!=h for p,h in snapshots.items()):raise ArtifactError("Parser runtime changed during verification.")
            result[key]={"state":"Ready","detail":"Native "+ARTIFACT_ENGINES[tool]+" in minimal readonly filesystem and isolated network namespace."}
        except (ArtifactError,ProfileError,OSError,subprocess.SubprocessError) as exc:
            text=str(exc)[:300];result[key]={"state":"Missing Dependency" if "Missing Dependency" in text else "Unsupported","detail":text}
    return result

def elf_security(text):
    stack=next((line for line in text.splitlines() if line.lstrip().startswith("GNU_STACK")),None)
    flags="".join(stack.split()[6:-1]) if stack else ""
    nx="Unknown" if not re.fullmatch("[RWE]+",flags) else ("Disabled" if "E" in flags else "Enabled")
    relro="Full" if "GNU_RELRO" in text and ("BIND_NOW" in text or re.search(r"FLAGS(?:_1)?\).*\bNOW\b",text)) else "Partial" if "GNU_RELRO" in text else "Absent"
    match=re.search(r"^\s*Type:\s+(\S+)",text,re.M)
    return {"NX_stack":nx,"RELRO":relro,"ELF_type":match[1] if match else "Unknown",
            "stack_canary":"Not assessed","limitations":"Static readelf evidence; does not establish exploitability."}

def _artifact_run_profile(tool,params):
    started=time.monotonic()
    try:
        marker="binary" if tool in ("objdump_analyze","checksec_analyze") else "file_path"
        allowed={marker}|({"min_len","additional_args"} if tool=="strings_extract" else {"offset","length","additional_args"} if tool=="xxd_hexdump" else {"disassemble","additional_args"} if tool=="objdump_analyze" else set())
        if tool not in ARTIFACT_TOOLS or not isinstance(params,dict) or set(params)-allowed:raise ArtifactError("Unexpected artifact parameters.")
        token=params.get(marker);data=artifact_store().read(token);args=artifact_options(tool,params)
        digest=hashlib.sha256(data).hexdigest()
        if tool=="xxd_hexdump":
            offset=params.get("offset","0");offset=int(offset,16 if offset.startswith("0x") else 10)
            length=params.get("length","4096") or "4096";length=int(length,16 if length.startswith("0x") else 10)
            rows=[]
            for index in range(offset,min(len(data),offset+length),16):
                chunk=data[index:min(index+16,offset+length)];words=" ".join(chunk[i:i+2].hex() for i in range(0,len(chunk),2))
                rows.append(f"{index:08x}: {words:<39}  "+''.join(chr(b) if 32<=b<127 else "." for b in chunk))
            out="\n".join(rows);err="";code=0;engine="python-bounded-hex";facts={"offset":offset,"returned_bytes":len(data[offset:offset+length])}
        else:
            with tempfile.TemporaryDirectory(prefix="rv-artifact-call-") as name:
                directory=Path(name);snapshot=directory/"input";snapshot.write_bytes(data);snapshot.chmod(0o600)
                cmd,snapshots=artifact_sandbox_command(tool,snapshot,args)
                payload=json.dumps(cmd)
                launcher=[sys.executable,str(Path(__file__).resolve()),"--sandbox",payload]
                code,out,err=_artifact_capture(launcher,directory)
                if any(_trusted(p)!=h for p,h in snapshots.items()) or hashlib.sha256(snapshot.read_bytes()).hexdigest()!=digest:
                    raise ArtifactError("Artifact or parser runtime changed during execution.")
            engine=ARTIFACT_ENGINES[tool];facts=elf_security(out) if tool=="checksec_analyze" and code==0 else {}
        return {"success":code==0,"return_code":code,"stdout":out,"stderr":err,"engine":engine,
                "artifact_sha256":digest,"artifact_size":len(data),"facts":facts,"profile":ARTIFACT_PROFILE,"execution_time":time.monotonic()-started,
                "limitations":"Read-only selected artifact; uploaded code is never executed. Parser output is untrusted evidence."}
    except (ArtifactError,OSError,ValueError,subprocess.SubprocessError) as exc:
        return {"success":False,"error":str(exc)[:300],"profile":ARTIFACT_PROFILE,"execution_time":time.monotonic()-started}

def artifact_run_profile(tool,params):
    if not _PARSER_SLOTS.acquire(blocking=False):
        return {"success":False,"profile":ARTIFACT_PROFILE,"error":"Artifact parser concurrency limit reached."}
    try:return _artifact_run_profile(tool,params)
    finally:_PARSER_SLOTS.release()


# ══════════════════════════════════════════════════════════════════════════════
# SEARCHSPLOIT — Opt-in backend-owned reviewed native Searchsploit lookup
# ══════════════════════════════════════════════════════════════════════════════

SEARCHSPLOIT_MARKER = "--redvector-searchsploit-v1"
SEARCHSPLOIT_PROFILE = "searchsploit-v1"
_searchsploit_lock = threading.Lock()
_searchsploit_limit = 1024 * 1024
_SEARCHSPLOIT_DEADLINE = 30
_SEARCHSPLOIT_QUERY_RE = re.compile(r"[A-Za-z0-9 ._+/:\-]{1,200}")
_SEARCHSPLOIT_EXCLUDE_RE = re.compile(r"[A-Za-z0-9 ,._/\-]{1,200}")
_SEARCHSPLOIT_CVE_RE = re.compile(r"(?:CVE-)?[0-9]{4}-[0-9]{4,7}")


class SearchsploitError(ValueError):
    pass


def _searchsploit_digest(path):
    digest = hashlib.sha256()
    if path.stat().st_size > 32 * _searchsploit_limit:
        raise SearchsploitError("Runtime file exceeds reviewed size")
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _searchsploit_trusted(path):
    path = Path(path)
    if path.is_symlink():
        raise SearchsploitError("Runtime symlinks are not supported")
    for parent in (path, *path.parents):
        info = parent.stat()
        if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise SearchsploitError("Searchsploit runtime must be administrator-owned and not writable by other users")
    if not path.is_file():
        raise SearchsploitError("Missing native searchsploit runtime")
    return _searchsploit_digest(path)


def _searchsploit_runtime():
    if not sys.platform.startswith("linux"):
        raise SearchsploitError("Unsupported: reviewed Searchsploit requires native Linux")
    executable = shutil.which("searchsploit")
    if not executable:
        raise SearchsploitError("Missing Dependency: native searchsploit binary unavailable")
    executable = Path(executable).resolve()
    _searchsploit_trusted(executable)
    return executable


def _searchsploit_validate(tool, params):
    if tool != "searchsploit_lookup" or not isinstance(params, dict):
        raise SearchsploitError("Unsupported reviewed tool")
    allowed = {"query", "cve", "exact", "title_only", "exclude", "json_output", "mirror", "additional_args"}
    if set(params) - allowed:
        raise SearchsploitError("Unexpected reviewed searchsploit arguments")
    if params.get("additional_args") != SEARCHSPLOIT_MARKER:
        raise SearchsploitError("Reviewed searchsploit profile marker required")
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
        if not _SEARCHSPLOIT_QUERY_RE.fullmatch(query):
            raise SearchsploitError("Query contains unsupported characters")
        if any(token.startswith("-") for token in query.split()):
            raise SearchsploitError("Query terms may not begin with '-'")
    if cve:
        if not _SEARCHSPLOIT_CVE_RE.fullmatch(cve):
            raise SearchsploitError("CVE must look like CVE-YYYY-NNNN")
        cve = cve.upper()
        if not cve.startswith("CVE-"):
            cve = "CVE-" + cve
    exclude = params.get("exclude", "") or ""
    if not isinstance(exclude, str):
        raise SearchsploitError("Exclude terms must be a string")
    exclude = exclude.strip()
    if exclude and not _SEARCHSPLOIT_EXCLUDE_RE.fullmatch(exclude):
        raise SearchsploitError("Exclude terms contain unsupported characters")
    return {"query": query, "cve": cve, "exact": bool(params.get("exact")),
            "title_only": bool(params.get("title_only")), "exclude": exclude}


def _searchsploit_command(executable, spec):
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


def _searchsploit_execute(command, directory, timeout=_SEARCHSPLOIT_DEADLINE):
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
                    if len(buffer) + len(chunk) > _searchsploit_limit:
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


def _searchsploit_rows(obj, key):
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


def searchsploit_parse_json(stdout):
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
            "results": _searchsploit_rows(obj, "RESULTS_EXPLOIT"),
            "shellcode": _searchsploit_rows(obj, "RESULTS_SHELLCODE")}


def searchsploit_capabilities():
    try:
        _searchsploit_runtime()
        return {SEARCHSPLOIT_PROFILE: {"state": "Ready",
                          "detail": "Native attested searchsploit --json offline Exploit-DB lookup; read-only, no mirroring/network; fixed argv vector, bounded deadline/output"}}
    except (SearchsploitError, OSError, subprocess.SubprocessError) as exc:
        detail = str(exc) if isinstance(exc, SearchsploitError) else "Native searchsploit runtime unavailable or verification failed"
        state = "Missing Dependency" if "Missing" in detail else "Unsupported"
        return {SEARCHSPLOIT_PROFILE: {"state": state, "detail": detail}}


def run_searchsploit(params):
    started = time.monotonic()
    try:
        spec = _searchsploit_validate("searchsploit_lookup", params)
    except SearchsploitError as exc:
        return {"success": False, "execution_mode": "R", "execution_mode_detail": "reviewed input rejected",
                "profile": SEARCHSPLOIT_PROFILE, "error": str(exc), "execution_time": time.monotonic() - started}
    try:
        if not _searchsploit_lock.acquire(blocking=False):
            raise SearchsploitError("Unsupported: reviewed searchsploit concurrency limit reached")
        try:
            executable = _searchsploit_runtime()
            before = _searchsploit_trusted(executable)
            with tempfile.TemporaryDirectory(prefix="redvector-searchsploit-") as name:
                directory = Path(name)
                command = _searchsploit_command(executable, spec)
                code, stdout, stderr = _searchsploit_execute(command, directory, timeout=_SEARCHSPLOIT_DEADLINE)
                if _searchsploit_trusted(executable) != before:
                    raise SearchsploitError("Unsupported: searchsploit runtime integrity changed")
                parsed = searchsploit_parse_json(stdout)
                return {"success": True, "execution_mode": "A", "execution_mode_detail": "native binary executed",
                        "profile": SEARCHSPLOIT_PROFILE, "engine": "native searchsploit --json (offline local Exploit-DB)",
                        "runtime_sha256": before, "binary": str(executable), "return_code": code,
                        "query": spec["cve"] or spec["query"],
                        "parsed": parsed, "results_count": len(parsed.get("results", [])),
                        "shellcode_count": len(parsed.get("shellcode", [])),
                        "stderr": stderr[:4096], "execution_time": time.monotonic() - started}
        finally:
            _searchsploit_lock.release()
    except SearchsploitError as exc:
        detail = str(exc)
        mode = "D" if "Missing" in detail else "E"
        return {"success": False, "execution_mode": mode,
                "execution_mode_detail": {"D": "missing dependency", "E": "unsupported"}[mode],
                "profile": SEARCHSPLOIT_PROFILE, "error": detail, "execution_time": time.monotonic() - started}
    except (OSError, subprocess.SubprocessError):
        return {"success": False, "execution_mode": "E", "execution_mode_detail": "unsupported",
                "profile": SEARCHSPLOIT_PROFILE, "error": "Native searchsploit runtime unavailable or failed",
                "execution_time": time.monotonic() - started}


# ══════════════════════════════════════════════════════════════════════════════
# TOOL MANAGER — Unified discovery and status reporting
# ══════════════════════════════════════════════════════════════════════════════

_TOOLS = [
    {
        "name": "nmap",
        "display": "native Nmap",
        "execution_class": "detection",
        "profiles": ("tcp-discovery-v1", "service-version-v1", "nse-vuln-v1"),
        "adapter": "redvector_reviewed_profiles",
        "install_hint": "sudo apt-get install nmap",
    },
    {
        "name": "nuclei",
        "display": "native Nuclei (reviewed offline header profile)",
        "execution_class": "web-scan",
        "profiles": ("--redvector-profile=http-headers-v1",),
        "adapter": "redvector_reviewed_assessment",
        "install_hint": "python3 tools/install_reviewed_nuclei.py  (reviewed build required)",
    },
    {
        "name": "searchsploit",
        "display": "native Searchsploit (offline Exploit-DB, read-only)",
        "execution_class": "exploit-db",
        "profiles": ("searchsploit-v1",),
        "adapter": "redvector_reviewed_searchsploit",
        "install_hint": "sudo apt-get install exploitdb",
    },
]

_PROFILE_TO_SPEC = {pid: spec for spec in _TOOLS for pid in spec["profiles"]}

_CAPABILITIES_DISPATCH = {
    "redvector_reviewed_profiles": nmap_capabilities,
    "redvector_reviewed_assessment": assessment_capabilities,
    "redvector_reviewed_searchsploit": searchsploit_capabilities,
}


def discover_tools():
    """Query each reviewed adapter and return a unified status dict."""
    result = {}
    for spec in _TOOLS:
        cap = _capabilities_safe(spec["adapter"])
        profiles = {}
        for pid in spec["profiles"]:
            if pid in cap:
                profiles[pid] = cap[pid]
            elif "_error" in cap:
                profiles[pid] = cap["_error"]
            else:
                profiles[pid] = {"state": UNSUPPORTED, "detail": "Profile not registered on this platform"}
        result[spec["name"]] = {
            "display": spec["display"],
            "execution_class": spec["execution_class"],
            "install_hint": spec["install_hint"],
            "profiles": profiles,
        }
    return result


def unavailability_reason(profile_id, tool_status):
    spec = _PROFILE_TO_SPEC.get(profile_id)
    if spec is None:
        return "no approved adapter for profile {!r}".format(profile_id)

    info = tool_status.get(spec["name"], {}).get("profiles", {}).get(profile_id, {})
    state = info.get("state", "")
    detail = info.get("detail", "")
    detail_l = detail.lower()

    if state == READY:
        return "ready"
    if MISSING in state or "missing" in state.lower():
        return "not installed: {} — to install: {}".format(spec["display"], spec["install_hint"])
    if "linux" in detail_l:
        return "not enabled: native Linux required — {} runs on native Kali only".format(spec["display"])
    if "allowlist" in detail_l or ("empty" in detail_l and "nse" in profile_id.lower()):
        return ("not run: script allowlist not yet curated — "
                "run python3 tools/collect_kali_evidence.py on native Kali and review nse.vuln_and_safe")
    if "sha256" in detail_l or "attestation" in detail_l or ("build" in detail_l and "unsupported" in state.lower()):
        return "not enabled: attestation failed or unsupported build — {}".format(detail[:120])
    if "version" in detail_l and "unsupported" in state.lower():
        return "not enabled: unsupported version — {}".format(detail[:120])
    if DISABLED in state:
        return "disabled: {}".format(detail[:120])
    if RESTRICTED in state:
        return "restricted: {}".format(detail[:120])
    if state:
        return "not enabled: {} — {}".format(state, detail[:100])
    return "not enabled: status unknown for profile {!r}".format(profile_id)


def format_tool_report(tool_status):
    lines = []
    for name, entry in tool_status.items():
        for pid, info in entry.get("profiles", {}).items():
            state = info.get("state", "unknown")
            mark = "✓" if state == READY else "✗"
            lines.append("{} {} [{}]: {}".format(mark, entry["display"], state,
                                                  info.get("detail", "")[:80]))
    return lines


def _capabilities_safe(adapter_name):
    fn = _CAPABILITIES_DISPATCH.get(adapter_name)
    if fn is None:
        return {}
    try:
        return fn()
    except Exception as exc:
        return {"_error": {"state": UNSUPPORTED, "detail": str(exc)[:200]}}


# ══════════════════════════════════════════════════════════════════════════════
# SUBPROCESS ENTRY POINTS — Nuclei offline sandbox and artifact parser sandbox
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "--offline-nuclei":
        binary = Path(sys.argv[2])
        if binary.is_symlink() or not binary.is_file():
            raise SystemExit("Reviewed Nuclei build not recognized")
        actual = assessment_digest(binary)
        if actual not in NUCLEI_BUILDS:
            candidate = os.environ.get("REDVECTOR_NUCLEI_CANDIDATE_SHA256", "").lower().strip()
            if not candidate or actual != candidate:
                raise SystemExit("Reviewed Nuclei build not recognized")
        no_network()
        os.execv(str(binary), [str(binary), *sys.argv[3:]])
    elif len(sys.argv) == 3 and sys.argv[1] == "--sandbox":
        import resource
        if ctypes.CDLL(None).prctl(38, 1, 0, 0, 0):
            raise SystemExit("Cannot prevent parser privilege gain.")
        command = json.loads(sys.argv[2])
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024 * 1024, 2 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        os.execve(command[0], command, {"PATH": os.defpath, "LC_ALL": "C"})
    else:
        raise SystemExit(2)

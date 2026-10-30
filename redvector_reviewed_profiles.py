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
DISCOVERY_PROFILE = "--redvector-profile=tcp-discovery-v1"
DISCOVERY = "tcp-discovery-v1"
NSE_VULN_PROFILE = "--redvector-profile=nse-vuln-v1"
NSE_VULN = "nse-vuln-v1"
_LOCK = threading.Lock()
_LIMIT = 1024 * 1024
_DEADLINE = 45
_DISCOVERY_DEADLINE = 300
_DISCOVERY_MAX_RATE = "2000"  # bounded single-host connect rate; completes full-range within the client call budget
_DISCOVERY_HOST_TIMEOUT = "280s"
_NSE_DEADLINE = 300
_NSE_HOST_TIMEOUT = "280s"
_NSE_MAX_RATE = "500"
MAX_PORTS = 128
MAX_DISCOVERY_PORTS = 65535
MAX_NSE_PORTS = 128
# The set of SAFE, non-intrusive vuln-category NSE scripts MUST be curated from the live
# `nmap --script-help` output on the real Kali runtime and recorded here only after review
# (category must be 'vuln'/'safe'; never 'exploit', 'brute', 'dos' or 'intrusive'). It is
# intentionally EMPTY until that curation: an empty allowlist keeps nse-vuln-v1 DISABLED
# (capabilities() reports Unsupported and run_nse_vuln refuses), so no unverified or intrusive
# script can ever run in production. Do not invent or populate this without real-Kali verification.
_NSE_VULN_SCRIPTS = ()
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

def _discovery_runtime():
    # Locate the attested native ELF nmap via package metadata, not PATH: on some distros
    # /usr/bin/nmap is a wrapper script and only the dpkg-listed binary is the real ELF.
    # -sT -n discovery runs no NSE, so a minimal private datadir is sufficient (fast, no
    # nselib copy), which keeps a full 1..65535 scan within the client call budget.
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

def capabilities():
    states={}
    # Discovery (-sT) only needs the attested ELF binary; report it independently (fast) so a
    # missing service-version data package does not also disable plain TCP discovery.
    try:
        _discovery_runtime()
        states[DISCOVERY]={"state":"Ready","detail":"Native attested nmap -sT connect discovery; 1..65535 ports, bounded rate/host-timeout; no NSE/UDP/OS; XML parsed"}
    except (ProfileError, OSError, subprocess.SubprocessError) as exc:
        detail = str(exc) if isinstance(exc,ProfileError) else "Native scanner runtime unavailable or verification failed"
        states[DISCOVERY]={"state":"Missing Dependency" if "Missing" in detail else "Unsupported","detail":detail}
    try:
        executable,root,files,snapshots=_runtime()
        with tempfile.TemporaryDirectory(prefix="redvector-profile-check-") as name:
            directory=Path(name)
            private=_stage(root,files,snapshots,directory)
            _verify_scripts(executable,directory)
            _check(snapshots)
            if any(_digest(p)!=digest for p,digest in private.items()):
                raise ProfileError("Private scanner profile integrity changed")
        states[PROFILE]={"state":"Ready", "detail":"Native reviewed TCP profile; at most 128 ports, intensity 0-2; SSH/HTTP/FTP/SMTP/POP3/IMAP/MySQL greeting evidence"}
    except (ProfileError, OSError, subprocess.SubprocessError) as exc:
        detail = str(exc) if isinstance(exc,ProfileError) else "Native scanner runtime unavailable or verification failed"
        state = "Missing Dependency" if "Missing" in detail else "Unsupported"
        states[PROFILE]={"state":state, "detail":detail}
    # NSE vuln stage: disabled until its safe-script allowlist is curated from real Kali. While the
    # allowlist is empty it is reported Unsupported and never becomes Ready, so it cannot run.
    if not _NSE_VULN_SCRIPTS:
        states[NSE_VULN]={"state":"Unsupported","detail":"NSE vuln script allowlist not yet curated from live nmap --script-help; nse-vuln-v1 disabled"}
    else:
        try:
            _runtime()
            states[NSE_VULN]={"state":"Ready","detail":"Native attested nmap -sV --script over a reviewed safe vuln NSE allowlist; at most 128 ports; bounded; XML parsed"}
        except (ProfileError, OSError, subprocess.SubprocessError) as exc:
            detail = str(exc) if isinstance(exc,ProfileError) else "Native scanner runtime unavailable or verification failed"
            states[NSE_VULN]={"state":"Missing Dependency" if "Missing" in detail else "Unsupported","detail":detail}
    return states

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
            # CPE evidence (nmap emits <cpe> under <service> for -sV matches); carried only when the
            # service was actually probed, so it feeds accurate CPE-based CVE correlation, never a guess.
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

def _observed_version(executable,directory):
    """Actual version reported by the attested native binary (runtime observation, never a
    requirement). Returns '' when it cannot be read."""
    try:
        code,out,err=_execute([str(executable),"--version"],directory,timeout=10)
    except (ProfileError,OSError,subprocess.SubprocessError):
        return ""
    match=re.search(r"Nmap version ([0-9][0-9A-Za-z.\-]*)",out+err)
    return match.group(1) if match else ""

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
                           "engine":"native nmap -sV reviewed service-version profile",
                           "binary":str(executable),"version":_observed_version(executable,directory),
                           "runtime_sha256":snapshots[executable]}}
        finally:
            _LOCK.release()
    except (ProfileError,OSError,subprocess.SubprocessError) as exc:
        detail=str(exc) if isinstance(exc,ProfileError) else "Native scanner runtime unavailable or verification failed"
        return {"success":False,"error":detail,"profile":PROFILE,
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
    # Preserve the operator's exact range string for nmap; dedupe only for counting.
    return target,spec,len(selected),address.version

def parse_discovery_xml(raw):
    sanitized=re.sub(r"<!DOCTYPE\s+nmaprun\s*>","",raw,flags=re.I)
    if len(raw.encode("utf-8"))>_LIMIT or "<!ENTITY" in raw.upper() or "<!DOCTYPE" in sanitized.upper():
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
        # With -Pn the host is treated as up; never infer offline from no ping reply.
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
        if not _LOCK.acquire(blocking=False):
            raise ProfileError("Reviewed scanner concurrency limit reached")
        try:
            executable=_discovery_runtime();before=_trusted(executable)
            with tempfile.TemporaryDirectory(prefix="redvector-discovery-") as name:
                directory=Path(name)
                # Minimal private datadir (no nselib): -sT -n discovery runs no scripts, so a
                # full 1..65535 scan stays well within the client call budget.
                private=_write_private(directory)
                command=[str(executable),"-sT","--unprivileged","-n","-Pn","--disable-arp-ping",
                         "--max-retries","1","--max-rate",_DISCOVERY_MAX_RATE,
                         "--host-timeout",_DISCOVERY_HOST_TIMEOUT,"--datadir",str(directory),
                         "-p",ports,"-oX","-","--no-stylesheet"]
                if version==6:command.append("-6")
                command.append(target)
                code,stdout,stderr=_execute(command,directory,timeout=_DISCOVERY_DEADLINE)
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
            _LOCK.release()
    except (ProfileError,OSError,subprocess.SubprocessError) as exc:
        detail=str(exc) if isinstance(exc,ProfileError) else "Native scanner runtime unavailable or verification failed"
        return {"success":False,"error":detail,"profile":DISCOVERY,
                "execution_time":time.monotonic()-started}

_CVE_RE=re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}",re.I)

def parse_nse_xml(raw):
    """Parse native Nmap NSE script output (-oX) into structured vulnerability evidence. Each entry
    carries the script id, the host/port it ran against, the script's own output, its declared
    state (e.g. VULNERABLE) and any CVE ids it references. A VULNERABLE state is the SCRIPT's own
    assessment and is surfaced as evidence requiring validation, never as confirmed exploitability."""
    sanitized=re.sub(r"<!DOCTYPE\s+nmaprun\s*>","",raw,flags=re.I)
    if len(raw.encode("utf-8"))>_LIMIT or "<!ENTITY" in raw.upper() or "<!DOCTYPE" in sanitized.upper():
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
                "cve_ids":sorted({m.upper() for m in _CVE_RE.findall(output+" "+table_keys)})}
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
    """Reviewed native Nmap NSE vulnerability stage over a FIXED, reviewed allowlist of safe,
    non-intrusive vuln-category scripts. DISABLED until that allowlist is curated from real Kali
    (_NSE_VULN_SCRIPTS); while empty it refuses with an accurate Unsupported status and runs
    nothing, so no unverified or intrusive script can execute. When curated, it runs the native
    attested nmap ELF with only the allowlisted script names from the administrator-owned system
    datadir (each script file integrity-checked), bounded, and parses the real XML evidence."""
    started=time.monotonic()
    try:
        target,ports,count,version=_validate_nse(tool,params)
    except ProfileError as exc:
        return {"success":False,"profile":NSE_VULN,"error":str(exc),"execution_time":time.monotonic()-started}
    if not _NSE_VULN_SCRIPTS:
        return {"success":False,"profile":NSE_VULN,
                "error":"Unsupported: NSE vuln script allowlist is not yet curated from live nmap --script-help; the nse-vuln-v1 profile is disabled",
                "execution_time":time.monotonic()-started}
    try:
        if not _LOCK.acquire(blocking=False):
            raise ProfileError("Reviewed scanner concurrency limit reached")
        try:
            executable,root,files,snapshots=_runtime()   # nselib-backed runtime (shared helper)
            before=_trusted(executable)
            scriptdir=root/"scripts"
            names=[]
            for script in _NSE_VULN_SCRIPTS:
                path=scriptdir/(script+".nse")
                _trusted(path)                            # administrator-owned, unmodified script file
                names.append(script)
            command=[str(executable),"-sV","-sT","--unprivileged","-n","-Pn","--disable-arp-ping",
                     "--max-retries","1","--max-rate",_NSE_MAX_RATE,"--host-timeout",_NSE_HOST_TIMEOUT,
                     "--script-timeout","60s","--datadir",str(root),"--script",",".join(names),
                     "-p",ports,"-oX","-","--no-stylesheet"]
            if version==6:command.append("-6")
            command.append(target)
            code,stdout,stderr=_execute(command,root,timeout=_NSE_DEADLINE)
            if _trusted(executable)!=before:
                raise ProfileError("Scanner runtime integrity changed")
            parsed=parse_nse_xml(stdout)
            if any(x!=target for x in parsed["hosts"]):
                raise ProfileError("Scanner returned an unexpected destination")
            return {"success":bool(parsed["scan_complete"]) and not code,"stdout":stdout,"stderr":stderr,
                    "parsed":parsed,"execution_time":time.monotonic()-started,"profile":NSE_VULN,
                    "reviewed_profile":{"ports":ports,"ports_count":count,"scripts":list(names),
                       "engine":"native nmap -sV --script (reviewed safe vuln NSE allowlist)","runtime_sha256":before}}
        finally:
            _LOCK.release()
    except (ProfileError,OSError,subprocess.SubprocessError) as exc:
        detail=str(exc) if isinstance(exc,ProfileError) else "Native scanner runtime unavailable or verification failed"
        return {"success":False,"error":detail,"profile":NSE_VULN,"execution_time":time.monotonic()-started}

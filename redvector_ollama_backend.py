"""Conservative, read-only verification for Ollama backend reuse across checkouts."""
from dataclasses import dataclass
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import socket
import stat
import sys
import time
import psutil
from redvector_ollama_capacity import trusted_executable

class BackendReuseError(RuntimeError):
    pass

@dataclass(frozen=True)
class BackendProof:
    pid: int
    started: float
    executable: Path
    script: Path
    cwd: Path

def _listeners(host,port):
    target=ipaddress.ip_address(host)
    found=[]
    for item in psutil.net_connections(kind="tcp"):
        if item.status!=psutil.CONN_LISTEN or not item.laddr or item.laddr.port!=port:continue
        address=ipaddress.ip_address(item.laddr.ip)
        mapped=address.ipv4_mapped if address.version==6 else None
        if address==target or address.is_unspecified or mapped==target or (mapped is not None and mapped.is_unspecified):
            found.append(item)
    return found

def _source(path,started=None):
    with path.open("rb") as source:
        before=os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size>8_000_000:
            raise BackendReuseError("Backend source is not a bounded regular file.")
        if started is not None and max(before.st_mtime,before.st_ctime)>started:
            raise BackendReuseError("Backend source changed since process startup; running code cannot be verified.")
        data=source.read(8_000_001)
        after=os.fstat(source.fileno())
    if (before.st_ino,before.st_dev,before.st_mtime_ns,before.st_ctime_ns,before.st_size)!=(after.st_ino,after.st_dev,after.st_mtime_ns,after.st_ctime_ns,after.st_size):
        raise BackendReuseError("Backend source changed during verification.")
    return hashlib.sha256(data.replace(b"\r\n",b"\n")).digest()

def _script_path(path,started):
    # Retain the original pathname: resolving first would hide a retargeted link.
    for item in (*reversed(path.parents),path):
        metadata=os.lstat(item)
        if stat.S_ISLNK(metadata.st_mode):
            raise BackendReuseError("Backend script path contains a symlink; source provenance cannot be verified safely.")
    return path.resolve(strict=True)

def _source_start_limit(pid,fallback):
    # psutil/Linux btime is whole seconds. Derive the startup time window from
    # the monotonic boot clock and kernel start ticks, not truncated btime.
    try:
        fields=Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()
        ticks=int(fields[19])
        rate=os.sysconf("SC_CLK_TCK")
        wall=time.time()
        boot=time.clock_gettime(time.CLOCK_BOOTTIME)
        return wall-boot+(ticks+1)/rate
    except (OSError,AttributeError,ValueError,IndexError):
        return fallback

def _process_proof(project,pid):
    process=psutil.Process(pid)
    started=process.create_time()
    source_limit=_source_start_limit(pid,started)
    for name in ("ns/mnt","ns/net","root"):
        if os.readlink(f"/proc/{pid}/{name}")!=os.readlink(f"/proc/self/{name}"):
            raise BackendReuseError("Backend filesystem/network namespace differs or its root cannot be verified.")
    executable=Path(process.exe()).resolve(strict=True)
    if not re.fullmatch(r"python(?:[0-9]+(?:\.[0-9]+)*)?(?:\.exe)?",executable.name):
        raise BackendReuseError("Listener executable is not a verified Python interpreter.")
    if executable!=Path(sys.executable).resolve() and not trusted_executable(str(executable)):
        raise BackendReuseError("Backend interpreter trust cannot be verified.")
    argv=process.cmdline()
    if not argv:raise BackendReuseError("Backend script command line is unavailable.")
    invoked=Path(argv[0])
    if invoked.is_absolute() and invoked.resolve(strict=True)!=executable:
        raise BackendReuseError("Backend executable and command line disagree.")
    args=argv[1:]
    while args and args[0] in ("-u","-B","-E","-I","-s","-S","-O","-OO","-b","-bb"):
        args=args[1:]
    if not args or args[0].startswith("-"):
        raise BackendReuseError("Listener does not execute a verifiable backend script.")
    cwd=Path(process.cwd()).resolve(strict=True)
    script=Path(args[0])
    if not script.is_absolute():script=cwd/script
    script=_script_path(script,started)
    if script.parent!=cwd:
        raise BackendReuseError("Backend working directory differs from its script directory; script provenance cannot be verified safely.")
    if script.name!="redvector_server.py":
        raise BackendReuseError("Listener script is not redvector_server.py.")
    for name in ("redvector_server.py","redvector_banner.py"):
        if _source(_script_path(script.parent/name,source_limit),source_limit)!=_source(Path(project)/name):
            raise BackendReuseError("Backend source differs from this trusted version ("+name+"); compatibility is unverified.")
    # Verify the process itself owns the endpoint, not only a global PID hint.
    connections=process.net_connections(kind="tcp")
    return BackendProof(pid,started,executable,script,cwd),process,connections

def verify_api(host,port):
    import requests
    session=requests.Session()
    session.trust_env=False
    url=f"http://{host}:{port}"
    try:
        response=session.get(url+"/health",timeout=3,allow_redirects=False)
        if response.status_code!=200:
            raise BackendReuseError("Verified backend /health is unavailable.")
        health=response.json()
        if not isinstance(health,dict) or health.get("version")!="8.0.0":
            raise BackendReuseError("Incompatible RedVector API version; expected 8.0.0.")
        if health.get("status")!="healthy":
            raise BackendReuseError("Verified RedVector backend is not healthy.")
        denied=session.get(url+"/api/cache/stats",timeout=3,allow_redirects=False)
        if denied.status_code not in (401,403):
            raise BackendReuseError("Backend authentication is not enforced on the protected API.")
        token=os.environ.get("REDVECTOR_API_TOKEN","redvector-dev-token")
        allowed=session.get(url+"/api/cache/stats",headers={"Authorization":"Bearer "+token},
                            timeout=3,allow_redirects=False)
        if allowed.status_code!=200:
            raise BackendReuseError("Backend rejected the configured API token; supply its token explicitly. No configuration was changed.")
    except (requests.RequestException,ValueError) as exc:
        raise BackendReuseError("Verified backend API check failed or disappeared: "+type(exc).__name__) from exc
    finally:session.close()

def inspect_backend(project,host,port,health=True):
    """Return a pinned proof, None for a free port, or a specific safe failure."""
    if host!="127.0.0.1" or not isinstance(port,int) or not 1<=port<=65535:
        raise BackendReuseError("Backend reuse requires a concrete loopback endpoint and valid port.")
    try:
        listeners=_listeners(host,port)
        if not listeners:
            try:
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:probe.bind((host,port))
            except OSError as exc:
                raise BackendReuseError("Backend endpoint is occupied but its socket owner is unavailable.") from exc
            return None
        if any(item.laddr.ip!=host for item in listeners):
            raise BackendReuseError("Backend listener is not exclusively bound to loopback, or listener scope is ambiguous.")
        owners={item.pid for item in listeners}
        if None in owners or len(owners)!=1:
            raise BackendReuseError("Backend socket owner is unknown or multiple processes share the endpoint.")
        proof,process,connections=_process_proof(project,next(iter(owners)))
        if not any(item.status==psutil.CONN_LISTEN and item.laddr and item.laddr.ip==host and item.laddr.port==port for item in connections):
            raise BackendReuseError("Backend process no longer owns the configured listener.")
        if health:verify_api(host,port)
        after=_listeners(host,port)
        if {(item.pid,item.laddr.ip,item.laddr.port) for item in after}!={(item.pid,item.laddr.ip,item.laddr.port) for item in listeners}:
            raise BackendReuseError("Backend listener changed during verification; retry explicitly.")
        refreshed,_,_= _process_proof(project,proof.pid)
        if refreshed!=proof:
            raise BackendReuseError("Backend process changed during verification; retry explicitly.")
        return proof
    except BackendReuseError:raise
    except (OSError,psutil.Error,ValueError,RuntimeError) as exc:
        raise BackendReuseError("Backend process identity is unavailable ("+type(exc).__name__+"); inspect process permissions and retry. No process was stopped.") from exc

def verify_pin(proof,pin):
    if pin is None:return
    if proof is None:
        raise BackendReuseError("The existing backend disappeared before launch; no replacement was started.")
    if pin!=f"{proof.pid}:{proof.started!r}":
        raise BackendReuseError("The existing backend changed before launch; no replacement was started.")

if __name__=="__main__":
    try:
        proof=inspect_backend(Path(sys.argv[1]),sys.argv[2],int(sys.argv[3]))
        verify_pin(proof,os.environ.get("REDVECTOR_OLLAMA_BACKEND_PIN"))
        if proof is None:sys.exit(1)
        print(f"[RedVector] Verified backend PID {proof.pid} from {proof.script.parent}",file=sys.stderr)
        sys.exit(0)
    except (BackendReuseError,ValueError,IndexError) as exc:
        print("[RedVector] Backend reuse refused: "+str(exc),file=sys.stderr)
        sys.exit(2)

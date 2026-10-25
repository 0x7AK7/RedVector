"""Metadata-only filesystem capacity, independent of private model-file access."""
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import psutil

@dataclass(frozen=True)
class InstallerIdentity:
    uid: int | None
    name: str
    home: Path | None

def current_identity():
    uid=os.geteuid() if hasattr(os,"geteuid") else None
    name=f"UID {uid}" if uid is not None else "Current user"
    home=None
    try:
        import pwd
        entry=pwd.getpwuid(uid)
        name=entry.pw_name
        if entry.pw_dir:home=Path(entry.pw_dir)
    except (ImportError,KeyError,OSError,TypeError):pass
    if home is None:
        try:home=Path.home()
        except (RuntimeError,OSError):pass
    if home is not None and not home.is_absolute():home=None
    return InstallerIdentity(uid,name,home)

@dataclass(frozen=True)
class CapacitySnapshot:
    status: str
    available_bytes: int | None = None
    total_bytes: int | None = None
    checked_path: str | None = None
    device: str | None = None
    mount_id: str | None = None
    filesystem_type: str | None = None
    read_only: bool = False
    reason: str = ""
    source: str = "Metadata-only filesystem probe"
    measured_uid: int | None = None
    quota_status: str = "Unverified"

    @property
    def verified(self):return self.status=="verified"

@dataclass(frozen=True)
class CapacityAssessment:
    blobs: CapacitySnapshot
    manifests: CapacitySnapshot
    model_path: Path | None = None
    manifests_v2: CapacitySnapshot | None = None
    instance_verified: bool = False

    @property
    def complete(self):
        return self.blobs.verified and self.manifests.verified and (self.manifests_v2 is None or self.manifests_v2.verified)

# Fixed source is shared by normal tests and an isolated, optionally approved
# service-UID subprocess. No repository imports, model writes, shell or eval of input.
_PROBE_SOURCE=r'''
import ctypes
import json
import os
from pathlib import Path
import stat
import sys
import socket
import ipaddress

def unknown(reason,status="unverified"):
    return dict(status=status,available_bytes=None,total_bytes=None,checked_path=None,
                device=None,mount_id=None,filesystem_type=None,read_only=False,reason=reason,
                measured_uid=os.geteuid() if hasattr(os,"geteuid") else None)

def mount_id(fd):
    try:
        for line in Path(f"/proc/self/fdinfo/{fd}").read_text().splitlines():
            if line.startswith("mnt_id:"):return line.split()[1]
    except OSError:pass
    return None

def filesystem_type(fd):
    mid=mount_id(fd)
    try:
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            before,sep,after=line.partition(" - ")
            if sep and mid is not None and before.split()[0]==mid:
                return after.split()[0]
    except (OSError,IndexError):pass
    try:
        # Linux statfs begins with a native fsword_t f_type; the oversized
        # aligned buffer avoids architecture-specific trailing layouts.
        library=ctypes.CDLL(None,use_errno=True)
        buffer=(ctypes.c_long*128)()
        function=library.fstatfs
        function.argtypes=[ctypes.c_int,ctypes.c_void_p]
        function.restype=ctypes.c_int
        if function(fd,ctypes.byref(buffer))==0:
            magic=buffer[0] & 0xffffffff
            return "autofs" if magic==0x187 else hex(magic)
    except (AttributeError,OSError):pass
    return None

def resolve_missing(raw):
    path=Path(raw)
    if not path.is_absolute():raise ValueError("An absolute path is required.")
    resolved=Path(path.anchor)
    pending=list(path.parts[1:])
    links=0
    while pending:
        part=pending.pop(0)
        if part in ("","."):continue
        if part=="..":
            # Kernel traversal still requires search permission on this directory.
            os.lstat(resolved/"..")
            resolved=resolved.parent
            continue
        candidate=resolved/part
        try:metadata=os.lstat(candidate)
        except FileNotFoundError:
            if ".." in pending:
                raise FileNotFoundError("A missing component precedes unresolved parent traversal.")
            return candidate.joinpath(*pending)
        if stat.S_ISLNK(metadata.st_mode):
            links+=1
            if links>40:raise OSError("Too many symbolic links.")
            target=Path(os.readlink(candidate))
            if target.is_absolute():
                resolved=Path(target.anchor)
                pending=list(target.parts[1:])+pending
            else:pending=list(target.parts)+pending
        else:
            if pending and not stat.S_ISDIR(metadata.st_mode):
                raise NotADirectoryError(str(candidate))
            resolved=candidate
    return resolved

def measure_directory(raw):
    if not hasattr(os,"O_PATH") or not hasattr(os,"fstatvfs"):
        return unknown("Metadata-only Linux filesystem APIs are unavailable.")
    fd=None
    try:
        path=Path(raw)
        if not path.is_absolute() or any(ord(c)<32 for c in str(path)):
            return unknown("An absolute storage path without control characters is required.","error")
        # Resolve symlinks in kernel pathname order before climbing a proven
        # missing tail. Never climb on denied traversal, loops or non-directories.
        candidate=resolve_missing(raw)
        while True:
            try:
                fd=os.open(candidate,os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC)
                break
            except FileNotFoundError:
                if candidate==candidate.parent:raise
                candidate=candidate.parent
        metadata=os.fstat(fd)
        if not stat.S_ISDIR(metadata.st_mode):
            return unknown("The storage location is not a directory.","error")
        kind=filesystem_type(fd)
        if kind=="autofs":
            return unknown("An untriggered automount is not verified model storage.")
        if kind is None:
            return unknown("The pinned filesystem type could not be verified.")
        data=os.fstatvfs(fd)
        unit=data.f_frsize or data.f_bsize
        if unit<=0 or data.f_blocks<0:
            return unknown("The filesystem returned invalid capacity data.")
        checked=str(candidate)
        try:checked=os.readlink(f"/proc/self/fd/{fd}")
        except OSError:pass
        if checked.endswith(" (deleted)"):
            return unknown("Storage changed during capacity verification.","error")
        return dict(status="verified",available_bytes=max(0,data.f_bavail)*unit,
                    total_bytes=data.f_blocks*unit,checked_path=checked,
                    device=str(metadata.st_dev),mount_id=mount_id(fd),
                    filesystem_type=kind,read_only=bool(data.f_flag & getattr(os,"ST_RDONLY",1)),
                    reason="Filesystem availability is measured; account/project quotas and future usage are not guaranteed.",
                    measured_uid=os.geteuid() if hasattr(os,"geteuid") else None)
    except (OSError,RuntimeError) as exc:
        return unknown("Cannot resolve the actual storage filesystem without further access: "+str(exc))
    finally:
        if fd is not None:os.close(fd)

def verify_endpoint(pid,host,port):
    if host not in ("127.0.0.1","::1") or not 1<=port<=65535:
        raise PermissionError("A concrete local API endpoint is required for instance association.")
    if os.readlink(f"/proc/{pid}/ns/net")!=os.readlink("/proc/self/ns/net"):
        raise PermissionError("The candidate server uses a different network namespace.")
    names=os.listdir(f"/proc/{pid}/fd")
    if len(names)>16384:raise PermissionError("Too many server descriptors to verify safely.")
    owned=set()
    for name in names:
        try:
            target=os.readlink(f"/proc/{pid}/fd/{name}")
            if target.startswith("socket:[") and target.endswith("]"):
                owned.add(target[8:-1])
        except FileNotFoundError:continue
    possible=set();certain=set()
    for family,filename in ((socket.AF_INET,"tcp"),(socket.AF_INET6,"tcp6")):
        try:table=Path(f"/proc/{pid}/net/{filename}").read_text()
        except FileNotFoundError:continue
        if len(table)>8_000_000:raise PermissionError("The listener table is too large to verify safely.")
        for line in table.splitlines()[1:]:
            fields=line.split()
            if len(fields)<4 or fields[3]!="0A":continue
            if len(fields)<10:raise PermissionError("Listener metadata is incomplete.")
            address,hexport=fields[1].split(":")
            if int(hexport,16)!=port:continue
            packed=(int(address,16).to_bytes(4,sys.byteorder) if family==socket.AF_INET else
                    b"".join(int(address[i:i+8],16).to_bytes(4,sys.byteorder) for i in range(0,32,8)))
            decoded=socket.inet_ntop(family,packed)
            exact=(host=="127.0.0.1" and family==socket.AF_INET and decoded in (host,"0.0.0.0")
                   or host=="::1" and family==socket.AF_INET6 and decoded in (host,"::"))
            mapped=ipaddress.IPv6Address(decoded).ipv4_mapped if family==socket.AF_INET6 else None
            if host=="127.0.0.1" and mapped is not None and str(mapped)==host:exact=True
            ambiguous=(host=="127.0.0.1" and family==socket.AF_INET6 and
                       (decoded=="::" or (mapped is not None and mapped.is_unspecified)))
            if exact or ambiguous:
                inode=fields[9]
                if not inode.isdecimal() or inode=="0":
                    raise PermissionError("Some matching listener identities are hidden.")
                possible.add(inode)
                if exact:certain.add(inode)
    if not certain or not possible.issubset(owned):
        raise PermissionError("The API listener cannot be exclusively associated with this Ollama process.")

def server_root(hint,pid,token,executable):
    if not pid:return Path(hint)
    fields=Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()
    if len(fields)<20 or fields[19]!=token:
        raise RuntimeError("The Ollama instance changed; restart preflight.")
    actual_executable=os.readlink(f"/proc/{pid}/exe")
    if executable and actual_executable!=executable:
        raise RuntimeError("The Ollama executable changed; restart preflight.")
    if Path(actual_executable).name not in ("ollama","ollama.exe"):
        raise RuntimeError("The detected process is not the Ollama executable.")
    if (os.readlink(f"/proc/{pid}/ns/mnt")!=os.readlink("/proc/self/ns/mnt")
        or os.readlink(f"/proc/{pid}/root")!=os.readlink("/proc/self/root")):
        raise PermissionError("The server uses a different filesystem namespace; host capacity is not its storage capacity.")
    raw=Path(f"/proc/{pid}/environ").read_bytes()
    if len(raw)>2_000_000:raise PermissionError("Server environment is too large to verify safely.")
    env=dict(item.split("=",1) for item in raw.decode("utf8",errors="surrogateescape").split("\0") if "=" in item)
    model=env.get("OLLAMA_MODELS","").strip().strip("\"'")
    if not model:
        home=env.get("HOME")
        if not home:raise PermissionError("The running server's HOME/model override is unavailable.")
        model=str(Path(home)/".ollama"/"models")
    result=Path(model)
    if not result.is_absolute():result=Path(os.readlink(f"/proc/{pid}/cwd"))/result
    # Ollama uses filepath.Join for its store children, which applies Clean
    # before filesystem traversal. Match that runtime behavior, not shell cd.
    return Path(os.path.normpath(str(result)))

def run_request(hint,pid,token,executable,host="",port=0):
    try:
        root=server_root(hint,pid,token,executable)
        if pid:verify_endpoint(pid,host,port)
        return dict(model_path=str(root),instance_verified=bool(pid),blobs=measure_directory(str(root/"blobs")),
                    manifests=measure_directory(str(root/"manifests")),
                    manifests_v2=measure_directory(str(root/"manifests-v2")))
    except RuntimeError as exc:
        item=unknown(str(exc),"error")
    except (OSError,ValueError) as exc:
        item=unknown("The actual server filesystem context is unverified: "+str(exc))
    return dict(model_path=None,instance_verified=False,blobs=item,manifests=item,manifests_v2=item)

if __name__=="__main__":
    print(json.dumps(run_request(sys.argv[1],int(sys.argv[2]),sys.argv[3],sys.argv[4],sys.argv[5],int(sys.argv[6]))))
'''
_PROBE_NS={"__name__":"redvector_metadata_probe"}
exec(compile(_PROBE_SOURCE,"<fixed-read-only-capacity-probe>","exec"),_PROBE_NS)
measure_directory=_PROBE_NS["measure_directory"]

def unavailable(reason,status="unverified"):
    item=CapacitySnapshot(status,reason=reason)
    return CapacityAssessment(item,item,manifests_v2=item)

def _server_identity(info):
    if info.pid is None:return 0,"",""
    process=psutil.Process(info.pid)
    if info.started is None or process.create_time()!=info.started:
        raise ValueError("The Ollama instance changed; restart preflight.")
    args=process.cmdline()
    if len(args)<2 or Path(args[0]).name not in ("ollama","ollama.exe") or args[1]!="serve":
        raise ValueError("The verified listener is no longer the Ollama server.")
    if info.uid is not None and process.uids().effective!=info.uid:
        raise ValueError("The Ollama service UID changed; restart preflight.")
    try:executable=os.readlink(f"/proc/{info.pid}/exe")
    except PermissionError:executable=""
    except FileNotFoundError as exc:raise ValueError("The Ollama instance exited; restart preflight.") from exc
    fields=Path(f"/proc/{info.pid}/stat").read_text().rpartition(")")[2].split()
    if len(fields)<20:raise ValueError("Server identity metadata is incomplete.")
    return info.pid,fields[19],executable

def trusted_executable(raw):
    if not raw:return None
    try:
        path=Path(raw).resolve(strict=True)
        if not path.is_absolute() or not path.is_file():return None
        for item in (path,*path.parents):
            data=item.stat()
            if data.st_uid!=0 or data.st_mode & 0o022:return None
        if not os.access(path,os.X_OK):return None
        return str(path)
    except (OSError,RuntimeError):return None

def service_probe_command(info):
    if info.pid is None or not isinstance(info.uid,int) or isinstance(info.uid,bool) or info.uid<0:
        raise ValueError("A verified service UID and process are required.")
    if info.host not in ("127.0.0.1","::1") or not isinstance(info.port,int) or isinstance(info.port,bool) or not 1<=info.port<=65535:
        raise ValueError("A concrete local endpoint is required.")
    try:
        pid,token,executable=_server_identity(info)
    except (OSError,psutil.Error) as exc:
        raise ValueError("Service identity metadata is unavailable for a safe probe.") from exc
    sudo=trusted_executable(shutil.which("sudo"))
    python=trusted_executable(getattr(sys,"_base_executable",None) or sys.executable)
    if not sudo or not python:raise ValueError("Trusted read-only service-probe tooling is unavailable.")
    return [sudo,"-u",f"#{info.uid}","--",python,"-I","-S","-B","-c",_PROBE_SOURCE,
            str(info.path) if info.path is not None else "",str(pid),token,executable,info.host,str(info.port)]


def _snapshot(raw):
    if not isinstance(raw,dict) or raw.get("status") not in ("verified","unverified","error"):
        raise ValueError("Invalid probe status.")
    status=raw["status"]
    if status!="verified":
        return CapacitySnapshot(status,reason=str(raw.get("reason","Unverified"))[:1500])
    for key in ("available_bytes","total_bytes"):
        if not isinstance(raw.get(key),int) or isinstance(raw[key],bool) or raw[key]<0:
            raise ValueError("Invalid probe byte count.")
    if raw["available_bytes"]>raw["total_bytes"] or not isinstance(raw.get("read_only"),bool):
        raise ValueError("Invalid capacity accounting.")
    checked=raw.get("checked_path");device=raw.get("device");kind=raw.get("filesystem_type")
    if not isinstance(checked,str) or not Path(checked).is_absolute() or not isinstance(device,str) or not kind or kind=="autofs":
        raise ValueError("Incomplete filesystem identity.")
    uid=raw.get("measured_uid")
    if uid is not None and (not isinstance(uid,int) or isinstance(uid,bool) or uid<0):
        raise ValueError("Invalid measuring UID.")
    return CapacitySnapshot(status,raw["available_bytes"],raw["total_bytes"],checked,device,
                            raw.get("mount_id"),str(kind),raw["read_only"],str(raw.get("reason",""))[:1500],
                            measured_uid=uid)

def probe_storage(info,as_service=False):
    if info.path is None and info.pid is None:return unavailable(info.reason or "The model directory is unknown.")
    if not info.manual_allowed:return unavailable(info.reason or "This server is not a verified local instance.","error")
    try:
        identity=_server_identity(info)
        if info.pid is not None and (info.host not in ("127.0.0.1","::1") or not isinstance(info.port,int) or not 1<=info.port<=65535):
            return unavailable("The concrete API endpoint is not verified.")
        command=(service_probe_command(info) if as_service else
                 [sys.executable,"-I","-S","-B","-c",_PROBE_SOURCE,str(info.path) if info.path is not None else "",str(identity[0]),identity[1],identity[2],info.host or "",str(info.port or 0)])
        env={"PATH":os.defpath,"LC_ALL":"C","TERM":os.environ.get("TERM","dumb")}
        result=subprocess.run(command,capture_output=True,text=True,timeout=45 if as_service else 8,
                              check=False,env=env)
        if result.returncode:
            detail=(result.stderr or "").strip()[:500]
            return unavailable("The read-only capacity probe failed or was cancelled."+(" "+detail if detail else ""))
        if len(result.stdout)>65536:return unavailable("The read-only capacity response exceeded the safety limit.")
        if _server_identity(info)!=identity:
            return unavailable("The Ollama instance changed; restart preflight.","error")
        raw=json.loads(result.stdout)
        root=raw.get("model_path")
        if root is not None and (not isinstance(root,str) or not Path(root).is_absolute()):
            raise ValueError("Invalid runtime model directory.")
        blobs=_snapshot(raw.get("blobs"));manifests=_snapshot(raw.get("manifests"))
        manifests_v2=_snapshot(raw.get("manifests_v2"))
        if as_service and any(item.verified and item.measured_uid!=info.uid for item in (blobs,manifests,manifests_v2)):
            return unavailable("The read-only probe did not run as the approved service UID.","error")
        associated=raw.get("instance_verified")
        if not isinstance(associated,bool) or (info.pid is not None and not associated and any(item.verified for item in (blobs,manifests,manifests_v2))):
            return unavailable("Capacity data is not bound to the verified server instance.","error")
        return CapacityAssessment(blobs,manifests,Path(root) if root is not None else None,manifests_v2,associated)
    except (psutil.NoSuchProcess,ValueError) as exc:
        return unavailable(str(exc),"error")
    except (OSError,psutil.Error,subprocess.TimeoutExpired) as exc:
        return unavailable("Read-only capacity verification is unavailable: "+str(exc))

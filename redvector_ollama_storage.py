"""Read-only discovery of a LOCAL Ollama server's effective model filesystem."""
from dataclasses import dataclass
import os
import errno
import struct
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
from urllib.parse import urlsplit
import psutil

class StorageError(ValueError):
    pass

@dataclass(frozen=True)
class StorageInfo:
    path: Path | None
    source: str
    reason: str = ""
    uid: int | None = None
    gids: tuple = ()
    manual_allowed: bool = True

def value(raw):
    return str(raw).strip().strip("\"'")

def model_path(env, cwd=None, default_home=None):
    override=value(env.get("OLLAMA_MODELS",""))
    home=env.get("HOME",default_home)
    raw=override if override else str(Path(home)/".ollama"/"models") if home else None
    if not raw or any(ord(c)<32 for c in raw):
        raise StorageError("The server's model directory or HOME is unavailable.")
    path=Path(raw)
    if not path.is_absolute():
        if not cwd or not Path(cwd).is_absolute():
            raise StorageError("The server uses a relative model path but its working directory is unavailable.")
        path=Path(cwd)/path
    return path

def listener_pids(host,port):
    try:
        connections=psutil.net_connections(kind="tcp")
        return {c.pid for c in connections if c.status==psutil.CONN_LISTEN and c.laddr.port==port
                and c.laddr.ip in (host,"0.0.0.0","::","::1" if host=="::1" else "127.0.0.1") and c.pid}
    except (psutil.Error,OSError):return set()

def same_namespace(pid):
    try:
        return (os.readlink(f"/proc/{pid}/ns/mnt")==os.readlink("/proc/self/ns/mnt")
                and os.readlink(f"/proc/{pid}/root")==os.readlink("/proc/self/root"))
    except OSError:return None

def is_server(process):
    args=process.cmdline()
    return (len(args)>1 and Path(args[0]).name in ("ollama","ollama.exe")
            and Path(process.exe()).name in ("ollama","ollama.exe") and args[1]=="serve")

def ids(process):
    try:
        groups=process.gids()
        all_groups={groups.real,groups.effective,groups.saved}
        try:
            status=Path(f"/proc/{process.pid}/status").read_text(encoding="utf8")
            match=re.search(r"(?m)^Groups:\s*([0-9 \t]*)$",status)
            if match:all_groups.update(int(group) for group in match[1].split())
        except OSError:pass
        return process.uids().effective,tuple(all_groups)
    except (psutil.Error,AttributeError):return None,()

def account(user):
    import pwd
    return pwd.getpwuid(int(user)) if user.isdecimal() else pwd.getpwnam(user)

MAPPING_KEYS=("RootDirectory","RootImage","BindPaths","BindReadOnlyPaths","TemporaryFileSystem",
              "MountImages","ExtensionImages","ExtensionDirectories","ReadOnlyPaths","ReadWritePaths",
              "InaccessiblePaths","JoinsNamespaceOf")
NAMESPACE_FLAGS=("PrivateMounts","PrivateTmp","ProtectHome","ProtectSystem","PrivateDevices",
                 "PrivateUsers","RootEphemeral","MountAPIVFS","ProtectKernelTunables",
                 "ProtectKernelModules","ProtectKernelLogs","ProtectControlGroups")

def unit_properties():
    command=shutil.which("systemctl")
    if not command:return {}
    keys=("ActiveState","MainPID","User","Environment","EnvironmentFiles","PassEnvironment",
          "UnsetEnvironment","FragmentPath","DropInPaths","ExecStart","WorkingDirectory",
          "RootDirectory","RootImage","PrivateMounts","PrivateTmp","ProtectHome","ProtectSystem",
          "BindPaths","BindReadOnlyPaths","TemporaryFileSystem","SetLoginEnvironment")+MAPPING_KEYS+NAMESPACE_FLAGS
    try:
        result=subprocess.run([command,"show","ollama.service","--no-pager","--property="+",".join(keys)],
            capture_output=True,text=True,timeout=3,check=False,env=dict(os.environ,LC_ALL="C"))
        if result.returncode:return {}
        return dict(line.split("=",1) for line in result.stdout.splitlines() if "=" in line)
    except (OSError,subprocess.TimeoutExpired):return {}

def environment_files(raw):
    result=[];remaining=raw.strip()
    while remaining:
        match=re.match(r"(.*?)\s+\(ignore_errors=(yes|no)\)(?:\s+|$)",remaining)
        if not match:raise StorageError("Unsupported systemd EnvironmentFiles metadata.")
        name=match[1].strip()
        if name.startswith(('"',"'")):
            parts=shlex.split(name)
            if len(parts)!=1:raise StorageError("Ambiguous systemd environment-file path.")
            name=parts[0]
        name=re.sub(r"\\x([0-9a-fA-F]{2})",lambda m:chr(int(m[1],16)),name)
        result.append((Path(name),match[2]=="yes"))
        remaining=remaining[match.end():].strip()
    return result

def read_environment_file(path):
    env={}
    for line in path.read_text(encoding="utf8").splitlines():
        stripped=line.strip()
        if not stripped or stripped.startswith(("#",";")):continue
        key,sep,raw=stripped.partition("=")
        # Validate every assignment, including unrelated keys: a subsequent line
        # may otherwise be mistaken for a relevant assignment inside a multiline value.
        if not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*",key) or "\\" in raw:
            raise StorageError("Complex environment-file syntax requires manual verification.")
        if raw.startswith(('"',"'")):
            parsed=shlex.split(raw)
            if len(parsed)!=1:raise StorageError("Ambiguous environment-file value.")
            raw=parsed[0]
        elif '"' in raw or "'" in raw:
            raise StorageError("Complex environment-file quoting requires manual verification.")
        if key in ("OLLAMA_MODELS","HOME","OLLAMA_HOST"):env[key]=raw
    return env

def endpoint_matches(raw,host,port):
    raw=value(raw) or "127.0.0.1:11434"
    parsed=urlsplit(raw if "://" in raw else "http://"+raw)
    try:
        return (parsed.scheme=="http" and not parsed.username and not parsed.password
                and parsed.hostname in (host,"localhost","0.0.0.0","::")
                and (parsed.port or 11434)==port and parsed.path in ("","/"))
    except ValueError:return False

def systemd_storage(host,port,expected_pid=None):
    props=unit_properties()
    try:
        pid=int(props.get("MainPID","0"))
        if props.get("ActiveState")!="active" or pid<=0 or (expected_pid and expected_pid!=pid):
            raise StorageError("No matching active systemd Ollama service was verified.")
        process=psutil.Process(pid)
        if not is_server(process):raise StorageError("The systemd main process is not ollama serve.")
        user=props.get("User","")
        if not user:raise StorageError("The systemd service user is not explicit.")
        owner=account(user)
        uid,gids=ids(process)
        if uid is not None and uid!=owner.pw_uid:
            raise StorageError("The running service user differs from the loaded configuration.")
        # A different root/mount mapping cannot be measured as a host directory.
        for key in MAPPING_KEYS:
            if props.get(key):raise StorageError("The service has a private filesystem mapping.")
        for key in NAMESPACE_FLAGS:
            if props.get(key,"").lower() not in ("","no","false"):
                raise StorageError("The service filesystem namespace needs manual verification.")
        launch=re.search(r"(?:^|[ {])path=([^ ;]+)",props.get("ExecStart",""))
        if not launch or Path(launch[1]).name!="ollama":
            raise StorageError("A wrapped systemd launch may change its environment.")
        inherited=set(shlex.split(props.get("PassEnvironment","")))
        if inherited & {"HOME","OLLAMA_MODELS","OLLAMA_HOST"}:
            raise StorageError("The service inherits manager environment that cannot be verified.")
        env=dict(item.split("=",1) for item in shlex.split(props.get("Environment","")) if "=" in item)
        sources=shlex.split(props.get("DropInPaths",""))
        fragment=props.get("FragmentPath","")
        if not fragment:raise StorageError("The loaded unit file is unavailable.")
        sources.append(fragment)
        for path,optional in environment_files(props.get("EnvironmentFiles","")):
            try:env.update(read_environment_file(path));sources.append(str(path))
            except FileNotFoundError as exc:
                raise StorageError("An environment file is missing; the running environment cannot be reconstructed.") from exc
        # Don't confuse a newly edited/reloaded unit with a running process's old environment.
        for name in sources:
            if Path(name).stat().st_mtime>process.create_time():
                raise StorageError("Service configuration changed after this process started.")
        for item in shlex.split(props.get("UnsetEnvironment","")):
            key,sep,raw=item.partition("=")
            if not sep or env.get(key)==raw:env.pop(key,None)
            if key=="HOME" and not value(env.get("OLLAMA_MODELS","")):
                raise StorageError("The unit explicitly removes HOME.")
        if not endpoint_matches(env.get("OLLAMA_HOST",""),host,port):
            raise StorageError("The systemd service endpoint does not match this client.")
        home=env.get("HOME")
        if not home:
            if props.get("SetLoginEnvironment","").lower() in ("no","false"):
                raise StorageError("The service does not establish its user's HOME.")
            home=owner.pw_dir
        path=model_path(env,props.get("WorkingDirectory") or "/",home)
        return StorageInfo(path,"systemd effective configuration and service account",
                           uid=owner.pw_uid,gids=gids)
    except (StorageError,psutil.Error,OSError,ValueError,KeyError,ImportError) as exc:
        return StorageInfo(None,"systemd",str(exc))

def detect_storage(host,port):
    if host not in ("127.0.0.1","::1","localhost"):
        return StorageInfo(None,"remote","Remote Ollama storage cannot be measured on this computer.",manual_allowed=False)
    pids=listener_pids(host,port)
    if len(pids)>1:return StorageInfo(None,"process","Multiple local listeners make storage ownership ambiguous.")
    if not pids:return systemd_storage(host,port)
    pid=next(iter(pids))
    try:
        process=psutil.Process(pid)
        if not is_server(process):
            return StorageInfo(None,"forwarded or foreign endpoint",
                "The local listener is not ollama serve. A forwarded/remote server cannot use a local disk check.",
                manual_allowed=False)
        namespace=same_namespace(pid)
        if namespace is None:return systemd_storage(host,port,pid)
        if namespace is False:
            return StorageInfo(None,"process","The server's filesystem namespace cannot be mapped safely.")
        env=process.environ()
        try:
            path=model_path(env,process.cwd() if value(env.get("OLLAMA_MODELS","")) and not Path(value(env["OLLAMA_MODELS"])).is_absolute() else None)
        except StorageError as exc:return StorageInfo(None,"process",str(exc))
        uid,gids=ids(process)
        return StorageInfo(path,"running Ollama process environment",uid=uid,gids=gids)
    except (psutil.AccessDenied,psutil.NoSuchProcess,OSError):
        return systemd_storage(host,port,pid)

def directory_permissions(path,metadata,uid,gids):
    shift=6 if metadata.st_uid==uid else 3 if metadata.st_gid in gids else 0
    basic=(metadata.st_mode>>shift)&7
    if not hasattr(os,"getxattr"):return basic
    try:raw=os.getxattr(path,"system.posix_acl_access")
    except OSError as exc:
        if exc.errno in (errno.ENODATA,errno.ENOTSUP,getattr(errno,"EOPNOTSUPP",errno.ENOTSUP)):
            return basic
        raise StorageError("Cannot verify the model directory's ACL access.") from exc
    if len(raw)<4 or (len(raw)-4)%8 or struct.unpack_from("<I",raw)[0]!=2:
        raise StorageError("Cannot verify the model directory's ACL format.")
    entries=[struct.unpack_from("<HHI",raw,i) for i in range(4,len(raw),8)]
    mask=next((perm for tag,perm,_ in entries if tag==16),7)
    if metadata.st_uid==uid:return next((perm for tag,perm,_ in entries if tag==1),basic)
    for tag,perm,ident in entries:
        if tag==2 and ident==uid:return perm & mask
    matched=False
    for tag,perm,ident in entries:
        if (tag==4 and metadata.st_gid in gids) or (tag==8 and ident in gids):
            matched=True
            # A single matching group entry must satisfy combined access.
            # Do not invent rwx by OR-ing unrelated group entries.
            if (perm & mask)==7:return 7
    if matched:return 0
    return next((perm for tag,perm,_ in entries if tag==32),basic)

def filesystem_path(info):
    if info.path is None or not info.path.is_absolute():
        raise StorageError("Use an absolute local Ollama model directory.")
    path=info.path
    try:
        while True:
            try:metadata=path.stat();break
            except FileNotFoundError:
                if path==path.parent:raise
                path=path.parent
        if not stat.S_ISDIR(metadata.st_mode):
            raise StorageError("The model directory or its parent is not a directory.")
        if hasattr(os,"statvfs") and os.statvfs(path).f_flag & getattr(os,"ST_RDONLY",1):
            raise StorageError("The model filesystem is read-only. No installation changes were made.")
        if info.uid is not None and info.uid!=0:
            if directory_permissions(path,metadata,info.uid,info.gids)!=7:
                raise StorageError("Unable to verify required service-user directory access; check permissions/ACLs manually.")
        return path
    except OSError as exc:
        raise StorageError("Cannot access the model filesystem to verify available space; no permissions were changed.") from exc

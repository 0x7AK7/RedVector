"""Read-only operator-selected artifact profiles; private staging and native sandbox."""
import base64,hashlib,json,os,re,selectors,shutil,stat,subprocess,sys,tempfile,threading,time,uuid
from pathlib import Path
from redvector_reviewed_profiles import _trusted,ProfileError
PREFIX="rv-artifact-v1:"
PROFILE="artifact-read-v1"
TOOLS=frozenset({"strings_extract","xxd_hexdump","objdump_analyze","checksec_analyze"})
ENGINES={"strings_extract":"strings","objdump_analyze":"objdump","checksec_analyze":"readelf"}
MAX_BYTES=4*1024*1024
OUTPUT_LIMIT=512*1024
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
        if not re.fullmatch("[0-9a-f]{32}",session or "") or not isinstance(data,bytes) or not 0<len(data)<=MAX_BYTES:
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
            return PREFIX+session+":"+ident+":"+actual
    def _row(self,token):
        match=re.fullmatch(re.escape(PREFIX)+"([0-9a-f]{32}):([0-9a-f]{32}):([0-9a-f]{64})",token if isinstance(token,str) else "")
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
                if not stat.S_ISREG(before.st_mode) or before.st_size>MAX_BYTES:raise ArtifactError("Invalid artifact snapshot.")
                data=src.read(MAX_BYTES+1);after=os.fstat(src.fileno())
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
def store():
    global _STORE
    with _STORE_LOCK:
        if _STORE is None:_STORE=ArtifactStore()
        return _STORE

def options(tool,params):
    if tool not in TOOLS:raise ArtifactError("Unknown artifact tool.")
    if params.get("additional_args",""):raise ArtifactError("Free-form artifact arguments are not supported.")
    if tool=="strings_extract":
        n=params.get("min_len",4)
        if type(n) is not int or not 4<=n<=64:raise ArtifactError("Minimum string length must be 4..64.")
        return ["-a","-n",str(n),"-t","x","/work/input"]
    if tool=="objdump_analyze":
        if type(params.get("disassemble",False)) is not bool:raise ArtifactError("Disassemble must be boolean.")
        return ["-w","-d" if params.get("disassemble",False) else "-x","/work/input"]
    if tool=="checksec_analyze":return ["-W","-h","-l","-d","/work/input"]
    for key,default,maximum in [("offset","0",MAX_BYTES),("length","4096",4096)]:
        value=params.get(key,default) or default
        if not isinstance(value,str) or not re.fullmatch(r"(?:[0-9]{1,10}|0x[0-9a-fA-F]{1,8})",value):
            raise ArtifactError("Hex offset/length must be bounded nonnegative decimal or hex.")
        n=int(value,16 if value.startswith("0x") else 10)
        if not 0<=n<=maximum or (key=="length" and n==0):raise ArtifactError("Hex offset/length exceeds profile bounds.")
    return []

def runtime(tool):
    if not sys.platform.startswith("linux"):raise ArtifactError("Unsupported: native artifact parsers require Linux.")
    executable=shutil.which(ENGINES[tool]);bubble=shutil.which("bwrap");ldd=shutil.which("ldd")
    if not all((executable,bubble,ldd)):raise ArtifactError("Missing Dependency: "+ENGINES[tool]+", Bubblewrap and ldd are required.")
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

def sandbox_command(tool,input_path,args):
    executable,bubble,libraries,snapshots=runtime(tool)
    cmd=[str(bubble),"--unshare-all","--die-with-parent","--new-session","--clearenv",
         "--setenv","LC_ALL","C","--setenv","HOME","/work","--setenv","PATH","/",
         "--proc","/proc","--dev","/dev","--tmpfs","/tmp","--dir","/work",
         "--ro-bind",str(executable),"/tool"]
    for source,dest in libraries:
        cmd+=["--ro-bind",str(source),dest]
    if input_path is not None:cmd+=["--ro-bind",str(input_path),"/work/input"]
    cmd+=["--chdir","/work","--","/tool",*args]
    return cmd,snapshots

def _capture(command,directory,timeout=12):
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
                    if sum(map(len,result.values()))>OUTPUT_LIMIT:raise ArtifactError("Artifact output exceeds 512 KiB; execution was not reported complete.")
            code=process.wait(timeout=max(.01,deadline-time.monotonic()))
            return code,bytes(result["stdout"]).decode("utf-8","replace"),bytes(result["stderr"]).decode("utf-8","replace")
    finally:
        if process.poll() is None:process.kill();process.wait(timeout=5)
        process.stdout.close();process.stderr.close()

def capabilities():
    result={PROFILE:{"state":"Ready","detail":"Operator-selected private regular-file snapshots only; max 4 MiB."}}
    for tool in TOOLS:
        key=PROFILE+":"+tool
        if tool=="xxd_hexdump":
            result[key]={"state":"Ready","detail":"Actual bytes formatted by bounded Python hex engine; no external xxd binary claimed."};continue
        try:
            cmd,snapshots=sandbox_command(tool,None,["--version"])
            checked=subprocess.run(cmd,capture_output=True,timeout=8,env={"PATH":os.defpath,"LC_ALL":"C"})
            if checked.returncode or b"GNU" not in checked.stdout:raise ArtifactError("Native filesystem/network sandbox preflight failed.")
            if any(_trusted(p)!=h for p,h in snapshots.items()):raise ArtifactError("Parser runtime changed during verification.")
            result[key]={"state":"Ready","detail":"Native "+ENGINES[tool]+" in minimal readonly filesystem and isolated network namespace."}
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

def _run_profile(tool,params):
    started=time.monotonic()
    try:
        marker="binary" if tool in ("objdump_analyze","checksec_analyze") else "file_path"
        allowed={marker}|({"min_len","additional_args"} if tool=="strings_extract" else {"offset","length","additional_args"} if tool=="xxd_hexdump" else {"disassemble","additional_args"} if tool=="objdump_analyze" else set())
        if tool not in TOOLS or not isinstance(params,dict) or set(params)-allowed:raise ArtifactError("Unexpected artifact parameters.")
        token=params.get(marker);data=store().read(token);args=options(tool,params)
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
            # A private per-call input copy prevents session replacement racing parser IO.
            with tempfile.TemporaryDirectory(prefix="rv-artifact-call-") as name:
                directory=Path(name);snapshot=directory/"input";snapshot.write_bytes(data);snapshot.chmod(0o600)
                cmd,snapshots=sandbox_command(tool,snapshot,args)
                payload=json.dumps(cmd)
                launcher=[sys.executable,str(Path(__file__).resolve()),"--sandbox",payload]
                code,out,err=_capture(launcher,directory)
                if any(_trusted(p)!=h for p,h in snapshots.items()) or hashlib.sha256(snapshot.read_bytes()).hexdigest()!=digest:
                    raise ArtifactError("Artifact or parser runtime changed during execution.")
            engine=ENGINES[tool];facts=elf_security(out) if tool=="checksec_analyze" and code==0 else {}
        return {"success":code==0,"return_code":code,"stdout":out,"stderr":err,"engine":engine,
                "artifact_sha256":digest,"artifact_size":len(data),"facts":facts,"profile":PROFILE,"execution_time":time.monotonic()-started,
                "limitations":"Read-only selected artifact; uploaded code is never executed. Parser output is untrusted evidence."}
    except (ArtifactError,OSError,ValueError,subprocess.SubprocessError) as exc:
        return {"success":False,"error":str(exc)[:300],"profile":PROFILE,"execution_time":time.monotonic()-started}

def run_profile(tool,params):
    if not _PARSER_SLOTS.acquire(blocking=False):
        return {"success":False,"profile":PROFILE,"error":"Artifact parser concurrency limit reached."}
    try:return _run_profile(tool,params)
    finally:_PARSER_SLOTS.release()

if __name__=="__main__":
    if len(sys.argv)!=3 or sys.argv[1]!="--sandbox":raise SystemExit(2)
    import resource,ctypes
    if ctypes.CDLL(None).prctl(38,1,0,0,0):raise SystemExit("Cannot prevent parser privilege gain.")
    command=json.loads(sys.argv[2])
    resource.setrlimit(resource.RLIMIT_CPU,(5,5));resource.setrlimit(resource.RLIMIT_AS,(512*1024*1024,512*1024*1024))
    resource.setrlimit(resource.RLIMIT_FSIZE,(2*1024*1024,2*1024*1024));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
    os.execve(command[0],command,{"PATH":os.defpath,"LC_ALL":"C"})

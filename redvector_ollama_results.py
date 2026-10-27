"""Canonical scan facts and private original evidence; no network/tool execution."""
import copy
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid

MAX_EVIDENCE_BYTES=32*1024*1024

def payloads(data):
    values=[]
    structured=data.get("structuredContent")
    if isinstance(structured,dict):
        if set(structured)=={"result"} and isinstance(structured["result"],dict):structured=structured["result"]
        values.append(structured)
    for block in (data.get("content") if isinstance(data.get("content"),list) else []):
        if not isinstance(block,dict):continue
        try:value=json.loads(block.get("text",""))
        except (ValueError,TypeError):continue
        if isinstance(value,dict):values.append(value)
    return values

def findings(data,target,elapsed):
    values=payloads(data)
    payload=values[0] if values else {}
    warnings=[]
    conflict=False
    for other in values[1:]:
        for key in ("success","return_code","returncode","partial_results","parsed","stdout"):
            if key in payload and key in other and payload[key]!=other[key]:conflict=True
    if conflict:warnings.append("Conflicting MCP evidence; inspect raw results.")
    raw=payload.get("stdout","")
    if not isinstance(raw,str):raw=""
    parsed=payload.get("parsed",{})
    source=parsed.get("open_ports") if isinstance(parsed,dict) else None
    rows=[];seen=set()
    def add(row,version="Not verified"):
        if not isinstance(row,dict):
            warnings.append("Invalid structured port row retained in raw evidence.");return
        port=row.get("port");proto=row.get("protocol")
        if isinstance(port,bool) or not re.fullmatch(r"[0-9]{1,5}",str(port)) or not 1<=int(port)<=65535 or proto not in ("tcp","udp"):
            warnings.append("Invalid structured port row retained in raw evidence.");return
        state=row.get("state","unknown")
        if not isinstance(state,str) or not re.fullmatch(r"[a-z|_-]{1,32}",state):state="unknown"
        service=row.get("service","unknown")
        if not isinstance(service,str) or not service:service="unknown"
        explicit=row.get("version")
        if isinstance(explicit,str) and explicit.strip() and explicit.lower() not in ("unknown","not verified") and row.get("version_verified") is not False:
            product=row.get("product","")
            version=((product+" ") if isinstance(product,str) and product else "")+explicit
        record={"port":int(port),"protocol":proto,"state":state,"service":service,"version":version}
        key=json.dumps(record,sort_keys=True)
        if key not in seen:rows.append(record);seen.add(key)
    if isinstance(source,list):
        for row in source:add(row)
    if not rows:
        version_header=bool(re.search(r"(?m)^PORT\s+STATE\s+SERVICE\s+VERSION\s*$",raw))
        for match in re.finditer(r"(?m)^\s*([0-9]{1,5})/(tcp|udp)\s+([a-z|_-]+)\s+(\S+)(?:[ \t]+([^\r\n]*))?$",raw):
            port,proto,state,service,version=match.groups()
            add({"port":port,"protocol":proto,"state":state,"service":service},
                version.strip() if version_header and version and version.strip() else "Not verified")
    rows.sort(key=lambda row:(row["port"],row["protocol"],row["state"]))
    code=payload.get("return_code",payload.get("returncode"))
    failed=bool(data.get("isError") or payload.get("success") is False or payload.get("error") or
                (isinstance(code,int) and not isinstance(code,bool) and code!=0))
    timed_out=payload.get("timed_out") is True
    partial=payload.get("partial_results") is True or timed_out or bool(re.search(r"(?i)skipping host[^\n]*host timeout|scan timed out",raw))
    if data.get("execution_status") in ("unknown","cancelled") or conflict or warnings:status="UNKNOWN"
    elif partial:status="PARTIAL"
    elif failed:status="FAILED"
    elif payload.get("success") is True or (type(code) is int and code==0):status="COMPLETED"
    else:status="UNKNOWN"
    duration=payload.get("execution_time",elapsed)
    if type(duration) not in (int,float) or not math.isfinite(duration) or duration<0:duration=elapsed
    closed=sum(row["state"]=="closed" for row in rows)
    totals=[int(n) for n in re.findall(r"(?i)\b([0-9]+)\s+closed(?:\s+(?:tcp|udp))?\s+ports?\b",raw)]
    filtered=sum(row["state"]=="filtered" for row in rows)
    filtered_totals=[int(n) for n in re.findall(r"(?i)\b([0-9]+)\s+filtered(?:\s+(?:tcp|udp))?\s+ports?\b",raw)]
    host_status="Up (source reported)" if re.search(r"(?im)^Host is up\b",raw) else "Down (source reported)" if re.search(r"(?im)^Host seems down\b",raw) else "Not verified"
    reported=parsed.get("target") if isinstance(parsed,dict) else None
    if reported and reported!=target:warnings.append("Reported target differs from invocation; inspect raw evidence.");status="UNKNOWN"
    return {"target":target,"tool":"nmap_scan","status":status,"duration":duration,
            "duration_source":"backend" if "execution_time" in payload else "MCP elapsed",
            "ports":rows,"open_count":len({(r["port"],r["protocol"]) for r in rows if r["state"]=="open"}),
            "closed_count":closed+sum(totals) if closed or totals else None,
            "filtered_count":filtered+sum(filtered_totals) if filtered or filtered_totals else None,
            "host_status":host_status,
            "errors":"Tool reported a timeout" if timed_out else "Reported tool failure" if failed else "None reported",
            "warnings":list(dict.fromkeys(warnings))}

def _encoded(data):return json.dumps(data,ensure_ascii=True,separators=(",",":")).encode("utf8")

def analysis_page(value,page=1,budget=1800,max_ports=48):
    if type(page) is not int or page<1 or budget<512:raise ValueError("Invalid analysis page or byte budget.")
    ports=[str(row["port"])+"/"+row["protocol"] for row in value["ports"] if row["state"]=="open"]
    ports=list(dict.fromkeys(ports))
    base={"status":value["status"],"total_open":value["open_count"],"page":1,"pages":1,"open_ports":[]}
    # Reserve room for final counters. No service banners, stdout or duplicate wire data.
    pages=[];current=[]
    for port in ports:
        trial=dict(base,open_ports=current+[port],page=999999,pages=999999)
        if len(_encoded(trial))>budget or len(current)>=max_ports:
            if not current:raise ValueError("Analysis byte budget too small.")
            pages.append(current);current=[]
        current.append(port)
    pages.append(current)
    if page>len(pages):raise ValueError("Analysis page does not exist.")
    result=dict(base,page=page,pages=len(pages),open_ports=pages[page-1])
    if len(_encoded(result))>budget:raise ValueError("Analysis byte budget exceeded.")
    return result

class ResultsStore:
    def __init__(self,directory=None):
        if directory is None:
            from redvector_ollama_setup import config_path
            directory=os.environ.get("REDVECTOR_RESULTS_DIR") or config_path().parent/"results"
        self.directory=Path(directory);self.cache={};self.latest=None

    def ensure(self):
        path=self.directory
        if not path.is_absolute():raise ValueError("Result directory must be absolute.")
        created=False
        try:path.mkdir(parents=True,exist_ok=False,mode=0o700);created=True
        except FileExistsError:pass
        info=path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):raise ValueError("Result directory must be a real private directory.")
        if hasattr(os,"geteuid") and (info.st_uid!=os.geteuid() or info.st_mode & 0o077):
            raise ValueError("Existing result directory is not private and owned by this operator; no permissions were changed.")
        if os.name=="nt":
            from redvector_ollama_private import secure_new_directory,check_private
            if created:secure_new_directory(path)
            check_private(path)
        return path

    def _write(self,path,value):
        self.ensure()
        raw=_encoded(value)
        if len(raw)>MAX_EVIDENCE_BYTES:raise ValueError("Evidence exceeds the managed-file limit; retain in-session and export explicitly.")
        fd,name=tempfile.mkstemp(prefix=".evidence-",dir=self.directory)
        try:
            with os.fdopen(fd,"wb") as out:
                out.write(raw);out.flush();os.fsync(out.fileno())
            if path.is_symlink():raise ValueError("Refusing a symlink evidence file.")
            os.replace(name,path)
        finally:
            if os.path.exists(name):os.unlink(name)

    def save(self,tool,target,arguments,data,wire,elapsed,authorization=None):
        ident=uuid.uuid4().hex
        value={"schema":1,"id":ident,"created":datetime.now(timezone.utc).isoformat(),
               "tool":tool,"target":target,"arguments":copy.deepcopy(arguments),"mcp":copy.deepcopy(data),
               "wire":copy.deepcopy(wire),"findings":(findings(data,target,elapsed) if tool in ("nmap_scan","nmap_advanced_scan") else __import__("redvector_ollama_views").normalize(tool,target,arguments,data,elapsed)),"persisted":True}
        if authorization is not None:value["authorization"]=copy.deepcopy(authorization)
        if tool in ("nmap_scan","nmap_advanced_scan"):
            value["findings"]["scan_type"]=arguments.get("scan_type","Not supplied")
            value["findings"]["tool"]=tool
        self.cache[ident]=value;self.latest=ident
        try:self._write(self.directory/(ident+".json"),value)
        except (OSError,ValueError,TypeError):
            value["persisted"]=False
            value["storage_warning"]="Saving failed. Evidence is available only in this session; export before exit."
        return value

    def load(self,ident=None):
        ident=ident or self.latest
        if ident is None:
            ids=self.ids()
            if ids:ident=max(ids,key=lambda value:(self.directory/(value+".json")).lstat().st_mtime if (self.directory/(value+".json")).exists() else float("inf"))
        if not isinstance(ident,str) or not re.fullmatch(r"[0-9a-f]{32}",ident):raise ValueError("Use a result ID shown by /results.")
        if ident in self.cache:return copy.deepcopy(self.cache[ident])
        self.ensure();path=self.directory/(ident+".json")
        if path.is_symlink():raise ValueError("Refusing a symlink evidence file.")
        fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
        with os.fdopen(fd,"rb") as src:
            info=os.fstat(src.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size>MAX_EVIDENCE_BYTES:raise ValueError("Invalid evidence file.")
            if hasattr(os,"geteuid") and (info.st_uid!=os.geteuid() or info.st_mode & 0o077):raise ValueError("Evidence file is not private.")
            if os.name=="nt":
                from redvector_ollama_private import check_private
                check_private(path)
            value=json.load(src)
        if not isinstance(value,dict) or value.get("id")!=ident or value.get("schema")!=1:raise ValueError("Invalid evidence document.")
        return value

    def ids(self):
        self.ensure()
        return sorted({p.stem for p in self.directory.glob("*.json") if re.fullmatch(r"[0-9a-f]{32}",p.stem)}|set(self.cache))

    def export(self,ident=None):
        value=self.load(ident);self.ensure()
        path=self.directory/("export-"+value["id"]+"-"+uuid.uuid4().hex+".json")
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,"O_NOFOLLOW",0),0o600)
        with os.fdopen(fd,"wb") as out:out.write(_encoded(value));out.flush();os.fsync(out.fileno())
        return path

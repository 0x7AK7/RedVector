"""Trusted operator-only file selection and authenticated snapshot staging."""
import base64,hashlib,os,stat,uuid
from pathlib import Path
from redvector_ollama_backend import inspect_backend,BackendProof
from redvector_ollama_setup import ROOT,SetupError
from redvector_reviewed_artifacts import MAX_BYTES,PREFIX

def snapshot(value):
    path=Path(value).expanduser().absolute()
    for candidate in (path,*path.parents):
        if candidate.is_symlink() or (hasattr(candidate,"is_junction") and candidate.is_junction()):
            raise SetupError("Artifact selection refuses symlinks/junctions.")
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0<before.st_size<=MAX_BYTES:
        raise SetupError("Select a regular file between 1 byte and 4 MiB.")
    fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    with os.fdopen(fd,"rb") as source:
        opened=os.fstat(source.fileno());data=source.read(MAX_BYTES+1);after=os.fstat(source.fileno())
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns) or (opened.st_size,opened.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):
        raise SetupError("Artifact changed during selection; retry explicitly.")
    return {"name":path.name,"size":len(data),"sha256":hashlib.sha256(data).hexdigest()},data

def require_backend(session):
    proof=getattr(session,"_redvector_backend_proof",None)
    port=int(os.environ.get("REDVECTOR_PORT","8888"))
    if not isinstance(proof,BackendProof) or inspect_backend(ROOT,"127.0.0.1",port)!=proof:
        raise SetupError("Verified backend changed; reconnect before reviewed execution.")
    return proof,port

def control(session,payload,method="POST"):
    import requests
    proof,port=require_backend(session)
    client=requests.Session();client.trust_env=False
    try:
        response=client.request(method,f"http://127.0.0.1:{port}/api/ollama/artifacts",
            json=payload,headers={"Authorization":"Bearer "+os.environ.get("REDVECTOR_API_TOKEN","redvector-dev-token")},
            timeout=15,allow_redirects=False)
        if response.status_code!=200 or len(response.content)>4096:raise SetupError("Artifact staging refused; check backend capacity and capability.")
        result=response.json()
        if not isinstance(result,dict) or not result.get("success"):raise SetupError("Artifact staging failed; original file was not changed.")
        if inspect_backend(ROOT,"127.0.0.1",port)!=proof:raise SetupError("Backend changed during artifact staging; reconnect explicitly.")
        return result
    finally:client.close()

def select(session,value,session_id):
    metadata,data=snapshot(value)
    result=control(session,{"session":session_id,"sha256":metadata["sha256"],"data":base64.b64encode(data).decode("ascii")})
    token=result.get("token","")
    if token!=PREFIX+session_id+":"+result.get("id","")+":"+metadata["sha256"]:
        raise SetupError("Backend artifact handle does not match the selected snapshot.")
    return dict(metadata,token=token,source="operator-snapshot")

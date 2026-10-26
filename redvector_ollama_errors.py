"""Private bounded technical diagnostics without exception messages or credentials."""
import json
import os
from pathlib import Path
import stat
import traceback
from redvector_ollama_setup import config_path

def record_error(context,exc):
    try:
        directory=config_path().parent
        directory.mkdir(parents=True,exist_ok=True,mode=0o700)
        path=directory/"agent-errors.log"
        if path.is_symlink():return
        flags=os.O_CREAT|os.O_WRONLY|os.O_APPEND|getattr(os,"O_NOFOLLOW",0)
        fd=os.open(path,flags,0o600)
        try:
            data=os.fstat(fd)
            if not stat.S_ISREG(data.st_mode):return
            if hasattr(os,"geteuid") and data.st_uid!=os.geteuid():return
            frames=[{"file":Path(frame.filename).name,"line":frame.lineno,"function":frame.name}
                    for frame in traceback.extract_tb(exc.__traceback__)[-8:]]
            # No exception text, args, locals, headers, source lines or configuration.
            details={}
            category=getattr(exc,"category",None)
            if category in {"timeout","context-overflow","http-error","model-error","connection-error","invalid-response","response-limit"}:
                details["category"]=category
            for key in ("elapsed_seconds","prompt_bytes","context_limit","response_limit","timeout_seconds","http_status"):
                value=getattr(exc,key,None)
                if type(value) in (int,float):details[key]=value
            stage=getattr(exc,"timeout_stage",None)
            if stage in {"connect","read","write","pool","total-deadline"}:details["timeout_stage"]=stage
            causes=[];seen={id(exc)};cause=exc.__cause__ or exc.__context__
            while cause is not None and id(cause) not in seen and len(causes)<4:
                seen.add(id(cause))
                chain_frames=[{"file":Path(frame.filename).name,"line":frame.lineno,"function":frame.name}
                              for frame in traceback.extract_tb(cause.__traceback__)[-6:]]
                causes.append({"type":type(cause).__name__,"frames":chain_frames})
                cause=cause.__cause__ or cause.__context__
            payload=json.dumps({"context":context,"type":type(exc).__name__,"frames":frames,"details":details,"causes":causes})+"\n"
            os.write(fd,payload.encode("utf-8"))
        finally:os.close(fd)
    except (OSError,RuntimeError,ValueError):pass

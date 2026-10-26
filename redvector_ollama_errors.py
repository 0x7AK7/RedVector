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
            payload=json.dumps({"context":context,"type":type(exc).__name__,"frames":frames})+"\n"
            os.write(fd,payload.encode("utf-8"))
        finally:os.close(fd)
    except (OSError,RuntimeError,ValueError):pass

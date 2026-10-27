"""Read-only runtime facts from the existing backend registry and psutil."""
import math,re,shlex,time
from pathlib import Path
import psutil
PROFILE="runtime-read-v1"
TOOLS=frozenset({"list_active_processes","get_process_dashboard","get_live_dashboard","get_process_status","display_system_metrics"})
LIST_TOOLS=TOOLS-{"get_process_status","display_system_metrics"}

def number(value):
    if isinstance(value,(float,int)) and not isinstance(value,bool) and math.isfinite(value):return value
    return None

def snapshot(manager,pid=None):
    records=manager.list_active_processes()
    if not isinstance(records,dict):return {"success":False,"error":"Backend process registry is unavailable.","profile":PROFILE}
    rows=[]
    for key,info in list(records.items())[:256]:
        if not isinstance(info,dict) or type(key) is not int or key<1:continue
        try:
            label=Path(shlex.split(info.get("command",""))[0]).name
            if not re.fullmatch("[A-Za-z0-9_.+-]{1,64}",label):label="Unknown"
        except (IndexError,ValueError,TypeError):label="Unknown"
        rows.append({"pid":key,"tool":label,"recorded_status":info.get("status") if info.get("status") in {"running","paused","terminated","completed","timeout","failed"} else "Unknown",
                     "start_time":number(info.get("start_time")),"progress":number(info.get("progress")),
                     "bytes_processed":number(info.get("bytes_processed"))})
    if pid is not None:
        if type(pid) is not int or not 1<=pid<=2147483647:return {"success":False,"error":"Invalid managed process ID.","profile":PROFILE}
        found=next((row for row in rows if row["pid"]==pid),None)
        if found is None:return {"success":False,"error":"Managed process not found; rediscover current backend records.","profile":PROFILE}
        return {"success":True,"profile":PROFILE,"source":"existing backend ProcessManager","process":found}
    metrics={"cpu_percent":float(psutil.cpu_percent(interval=None)),"memory_percent":float(psutil.virtual_memory().percent),
             "disk_usage":float(psutil.disk_usage(str(Path.cwd())).percent),"system_uptime_seconds":max(0.0,time.time()-psutil.boot_time())}
    if any(number(value) is None for value in metrics.values()):return {"success":False,"error":"Actual runtime measurements unavailable.","profile":PROFILE}
    return {"success":True,"profile":PROFILE,"source":"existing backend ProcessManager and psutil","processes":rows,
            "total_processes":len(rows),"partial_results":len(records)>256,"metrics":metrics,
            "limitations":"Sanitized registered backend jobs only; no command arguments/output or arbitrary OS process inspection."}

def capabilities():
    return {PROFILE:{"state":"Ready","detail":"Read-only actual psutil measurements and sanitized registered backend jobs."}}

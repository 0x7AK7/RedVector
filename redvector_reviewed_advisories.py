"""Anonymous fixed-provider advisory sampling; never observed target vulnerabilities."""
from datetime import datetime,timedelta,timezone
import hashlib,http.client,ipaddress,json,queue,re,socket,ssl,threading,time
from urllib.parse import urlencode
PROFILE="nvd-advisory-v1"
TOOLS=frozenset({"monitor_cve_feeds","vulnerability_intelligence_dashboard"})
HOST="services.nvd.nist.gov"
PATH="/rest/json/cves/2.0"
_LIMIT=2*1024*1024
_LOCK=threading.Lock()
_DNS_SLOTS=threading.BoundedSemaphore(2)
_CACHE={};_LAST=float("-inf")
class AdvisoryError(ValueError):pass

def validate(params):
    if not isinstance(params,dict) or set(params)-{"hours","severity_filter","keywords"}:raise AdvisoryError("Unexpected advisory query fields.")
    hours=params.get("hours",24);severity=params.get("severity_filter","HIGH,CRITICAL");keywords=params.get("keywords","")
    if type(hours) is not int or not 1<=hours<=168:raise AdvisoryError("Advisory window must be 1..168 hours.")
    if not isinstance(severity,str) or not severity or len(severity)>50:raise AdvisoryError("Invalid severity selection.")
    values=set(severity.upper().split(","))
    if not values<={"LOW","MEDIUM","HIGH","CRITICAL","ALL"} or ("ALL" in values and len(values)>1):raise AdvisoryError("Use LOW,MEDIUM,HIGH,CRITICAL or ALL.")
    if not isinstance(keywords,str) or len(keywords)>80 or not re.fullmatch("[A-Za-z0-9 .,_+-]*",keywords):raise AdvisoryError("Use bounded plain advisory keywords, never URLs/credentials.")
    return hours,values,tuple(part.strip().lower() for part in keywords.split(",") if part.strip())

def _resolve():
    if not _DNS_SLOTS.acquire(blocking=False):raise AdvisoryError("Provider DNS capacity is busy.")
    result=queue.Queue(maxsize=1)
    def resolve():
        try:result.put(socket.getaddrinfo(HOST,443,type=socket.SOCK_STREAM))
        except OSError:result.put(None)
        finally:_DNS_SLOTS.release()
    threading.Thread(target=resolve,daemon=True).start()
    try:rows=result.get(timeout=5)
    except queue.Empty:raise AdvisoryError("Provider DNS timed out.") from None
    if not rows or len(rows)>32:raise AdvisoryError("Official provider DNS is unavailable.")
    addresses=set()
    for row in rows:
        value=ipaddress.ip_address(row[4][0])
        if not value.is_global or value.is_multicast or value.is_unspecified:raise AdvisoryError("Official provider DNS included a nonpublic destination.")
        addresses.add(str(value))
    return sorted(addresses,key=lambda x:(ipaddress.ip_address(x).version,x))[0]

def _request(hours):
    address=_resolve()
    class PinnedProvider(http.client.HTTPSConnection):
        def connect(self):
            raw=socket.create_connection((address,443),timeout=5)
            try:self.sock=ssl.create_default_context().wrap_socket(raw,server_hostname=HOST)
            except BaseException:raw.close();raise
    end=datetime.now(timezone.utc).replace(second=0,microsecond=0);start=end-timedelta(hours=hours)
    query=urlencode({"resultsPerPage":100,"pubStartDate":start.strftime("%Y-%m-%dT%H:%M:%S.000"),"pubEndDate":end.strftime("%Y-%m-%dT%H:%M:%S.000")})
    client=PinnedProvider(HOST,timeout=5);active=[None];expired=threading.Event();deadline=time.monotonic()+15
    def expire():
        expired.set()
        sock=active[0] or client.sock
        if sock:
            try:sock.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        client.close()
    timer=threading.Timer(15,expire);timer.daemon=True;timer.start()
    try:
        client.request("GET",PATH+"?"+query,headers={"Host":HOST,"User-Agent":"RedVector-Reviewed-Advisories/8","Accept":"application/json","Connection":"close"})
        active[0]=client.sock
        response=client.getresponse()
        if response.status!=200:raise AdvisoryError("Official NVD provider returned HTTP "+str(response.status)+"; no clean result was inferred.")
        body=bytearray()
        while True:
            if time.monotonic()>deadline:raise AdvisoryError("Official provider response deadline exceeded.")
            chunk=response.read1(min(65536,_LIMIT+1-len(body)))
            if expired.is_set():raise AdvisoryError("Official provider response deadline exceeded.")
            if not chunk:
                if response.length is not None and response.length>0:raise AdvisoryError("Official provider response was truncated.")
                break
            body.extend(chunk)
            if len(body)>_LIMIT:raise AdvisoryError("Provider response exceeds 2 MiB.")
        data=json.loads(bytes(body))
        rows,total=parse(data)
        return {"rows":rows,"total":total,"sha256":hashlib.sha256(body).hexdigest(),
                "retrieved_at":datetime.now(timezone.utc).isoformat(),"range_start":start.isoformat(),"range_end":end.isoformat()}
    except (OSError,http.client.HTTPException):
        if expired.is_set():raise AdvisoryError("Official provider response deadline exceeded.") from None
        raise
    finally:timer.cancel();client.close()

def parse(data):
    if not isinstance(data,dict) or type(data.get("totalResults")) is not int or data["totalResults"]<0 or not isinstance(data.get("vulnerabilities"),list):
        raise AdvisoryError("Malformed official advisory payload; no clean result inferred.")
    records=data["vulnerabilities"]
    if len(records)>100 or (data["totalResults"]>0 and not records):raise AdvisoryError("Incomplete provider payload.")
    rows=[]
    for item in records:
        cve=item.get("cve") if isinstance(item,dict) else None
        if not isinstance(cve,dict) or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}",cve.get("id","")):raise AdvisoryError("Invalid provider advisory identifier.")
        descriptions=cve.get("descriptions",[])
        description=next((value.get("value","") for value in descriptions if isinstance(value,dict) and value.get("lang")=="en"),"")
        metrics=cve.get("metrics",{});score=None;severity="UNKNOWN"
        for key in ("cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            values=metrics.get(key,[]) if isinstance(metrics,dict) else []
            if values and isinstance(values[0],dict):
                cvss=values[0].get("cvssData",{});score=cvss.get("baseScore");severity=cvss.get("baseSeverity") or values[0].get("baseSeverity","UNKNOWN");break
        rows.append({"id":cve["id"],"description":str(description)[:2000],"published":cve.get("published"),"modified":cve.get("lastModified"),
                     "provider_severity":severity,"provider_cvss_score":score,"applicability":"Not assessed",
                     "reference":"https://nvd.nist.gov/vuln/detail/"+cve["id"]})
    return rows,data["totalResults"]

def run(params,dashboard=False):
    global _LAST
    try:
        hours,severities,keywords=validate(params)
        with _LOCK:
            cached=_CACHE.get(hours);hit=bool(cached and time.monotonic()-cached["created"]<60)
            if hit:source=cached["data"]
            else:
                if time.monotonic()-_LAST<6.5:raise AdvisoryError("Official provider cooldown active; retry later rather than repeat requests.")
                _LAST=time.monotonic();source=_request(hours)
                if len(_CACHE)>=8:_CACHE.clear()
                _CACHE[hours]={"created":time.monotonic(),"data":source}
        rows=[row for row in source["rows"] if ("ALL" in severities or row["provider_severity"] in severities) and (not keywords or any(k in row["description"].lower() for k in keywords))]
        result={"success":True,"profile":PROFILE,"provider":"NVD","provider_endpoint":"https://"+HOST+PATH,
                "advisories":rows,"sampled_records":len(source["rows"]),"provider_total_results":source["total"],
                "partial_results":source["total"]>len(source["rows"]),"retrieved_at":source["retrieved_at"],
                "provider_payload_sha256":source["sha256"],"cache_hit":hit,"window_utc":{"start":source["range_start"],"end":source["range_end"]},
                "limitations":"At most 100 published advisories sampled; severity/keyword filters applied locally. Advisories do not establish target applicability or exploitability. No target or artifact data sent to provider."}
        if dashboard:
            counts={}
            for row in rows:counts[row["provider_severity"]]=counts.get(row["provider_severity"],0)+1
            result["dashboard"]={"sample_severity_counts":counts,"sample_count":len(rows),"scope":"This retrieved sample only; not global threat trends or exploit availability."}
        return result
    except (AdvisoryError,OSError,ValueError,KeyError,TypeError,http.client.HTTPException) as exc:
        return {"success":False,"profile":PROFILE,"error":str(exc)[:300],"provider":"NVD"}

def capabilities():
    return {PROFILE:{"state":"Ready","detail":"Anonymous fixed NVD public-provider query; exact approval, TLS/public-IP pinning, bounded sample. Live provider availability checked during execution."}}

"""Shared root-response capture and offline Nuclei assessment profiles."""
import concurrent.futures,ctypes,hashlib,http.client,ipaddress,json,os,platform,re,shutil,socket,ssl
from pathlib import Path
import subprocess,sys,tempfile,threading,time
from urllib.parse import urlsplit
HTTP_PROFILE="redvector-http-read-v1"
NUCLEI_PROFILE="--redvector-profile=http-headers-v1"
# Reviewed Nuclei builds keyed by verified binary SHA256. A build is usable only when its exact
# checksum is a key here (identity + integrity) AND its -version banner matches the recorded version
# (binds identity to the claimed version). Add a build ONLY after reviewing it and recording real
# verified-execution evidence on native Kali; never trust a whole version range and never bypass
# attestation. Unknown or unverified builds stay unavailable. Operators' installed versions are
# never global requirements: each legitimate build is reviewed and listed on its own merits.
NUCLEI_BUILDS={
    "c49588140f357cbdddd5436dec11201953a4c5390faeec90777f9ee2cfd70251":{
        "version":"v3.11.1","platform":"linux/amd64",
        "capabilities":["offline-root-response-header-templates"],
        "template_requirements":"fixed reviewed root-response header templates; remote template download disabled",
        "evidence":"Installed and checksum-verified via tools/install_reviewed_nuclei.py; offline header profile exercised in the native sandbox regression."},
}
_LIMIT=65536
_LOCK=threading.Lock()
_HTTP_SLOTS=threading.BoundedSemaphore(2)
class AssessmentError(ValueError):pass

def digest(path):
    value=hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda:stream.read(1048576),b""):value.update(block)
    return value.hexdigest()

def validate_url(value):
    if not isinstance(value,str) or len(value)>1024 or any(c.isspace() for c in value):
        raise AssessmentError("Use one canonical root HTTP(S) URL.")
    u=urlsplit(value)
    if u.scheme not in ("http","https") or u.username or u.password or u.query or u.fragment or u.path not in ("","/"):
        raise AssessmentError("Reviewed root-response profile permits HTTP(S) / only, without credentials/query/fragment.")
    try:
        ip=ipaddress.ip_address(u.hostname or "")
        port=u.port or (443 if u.scheme=="https" else 80)
    except ValueError:raise AssessmentError("Numeric pinned destination and valid port required.") from None
    if ip.is_unspecified or ip.is_multicast or "%" in str(ip) or not 1<=port<=65535:
        raise AssessmentError("Canonical unicast destination required.")
    return u,str(ip),port

def _fetch(url,method="GET",headers=None):
    u,host,port=validate_url(url)
    if method not in ("GET","HEAD"):raise AssessmentError("Only GET and HEAD are supported.")
    headers=headers or {}
    if set(headers)-{"Host"}:raise AssessmentError("Custom headers/cookies are not part of this profile.")
    authority=headers.get("Host",u.netloc)
    if not isinstance(authority,str) or not re.fullmatch(r"[A-Za-z0-9.:[\]-]{1,260}",authority):
        raise AssessmentError("Invalid Host authority.")
    # Connection destination is numeric; environment proxies and redirects are never used.
    conn=http.client.HTTPConnection(host,port,timeout=3)
    if u.scheme=="https":
        class PinnedTLS(http.client.HTTPSConnection):
            def connect(self):
                raw=socket.create_connection((host,port),timeout=self.timeout)
                name=authority
                if name.startswith("["):name=name[1:name.index("]")]
                elif name.count(":")==1:name=name.split(":")[0]
                try:self.sock=ssl.create_default_context().wrap_socket(raw,server_hostname=name)
                except BaseException:raw.close();raise
        conn=PinnedTLS(host,port,timeout=3)
    active=[None];expired=threading.Event()
    def expire():
        expired.set()
        sock=active[0] or conn.sock
        if sock:
            try:sock.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        conn.close()
    timer=threading.Timer(10,expire);timer.daemon=True;timer.start()
    started=time.monotonic()
    try:
        conn.request(method,"/",headers={"Host":authority,"User-Agent":"RedVector-Reviewed/8","Accept":"*/*","Connection":"close"})
        active[0]=conn.sock
        response=conn.getresponse()
        pairs=response.getheaders()
        if sum(len(k)+len(v) for k,v in pairs)>16384:raise AssessmentError("Response header limit exceeded.")
        chunks=[];total=0
        while method!="HEAD":
            if time.monotonic()-started>10:raise AssessmentError("Response deadline exceeded.")
            chunk=response.read1(min(4096,_LIMIT+1-total))
            if expired.is_set():raise AssessmentError("Response deadline exceeded.")
            if not chunk:
                if response.length is not None and response.length>0:raise AssessmentError("Response ended before its declared content length.")
                break
            chunks.append(chunk);total+=len(chunk)
            if total>_LIMIT:raise AssessmentError("Response exceeds 64 KiB; no partial assessment reported.")
        body=b"".join(chunks).decode("utf-8","replace")
        raw="HTTP/1.1 "+str(response.status)+" "+response.reason+"\r\n"+"".join(k+": "+v+"\r\n" for k,v in pairs)+"\r\n"+body
        return {"status_code":response.status,"headers":{k.lower():v for k,v in pairs},"body":body,
                "raw":raw,"redirect_followed":False}
    except (OSError,http.client.HTTPException):
        if expired.is_set():raise AssessmentError("Response deadline exceeded.") from None
        raise
    finally:timer.cancel();conn.close()

def fetch(url,method="GET",headers=None):
    if not _HTTP_SLOTS.acquire(blocking=False):
        raise AssessmentError("Root-response concurrency limit reached.")
    try:return _fetch(url,method,headers)
    finally:_HTTP_SLOTS.release()

def run_http(params):
    try:
        if set(params)-{"url","method","headers","cookies","data","action"} or params.get("action")!=HTTP_PROFILE:
            raise AssessmentError("Exact reviewed HTTP profile required.")
        if params.get("data") not in (None,{}) or params.get("cookies") not in (None,{}):
            raise AssessmentError("Request bodies and cookies are not supported by this profile.")
        value=fetch(params.get("url"),params.get("method","GET"),params.get("headers"))
        return {"success":True,"profile":HTTP_PROFILE,"target":params["url"],"result":value,
                "limitations":"One root response; no crawling, redirects, active payloads or inferred vulnerabilities."}
    except (AssessmentError,OSError,ValueError,http.client.HTTPException) as exc:
        return {"success":False,"profile":HTTP_PROFILE,"error":str(exc)[:300]}

def nuclei_version(output):
    """Parse a Nuclei -version banner (bytes or str) into a canonical 'vX.Y.Z' string, or '' when
    no version can be read. Tolerant of surrounding banner text and ANSI so it works across builds."""
    text=output.decode("utf-8","replace") if isinstance(output,(bytes,bytearray)) else str(output)
    match=re.search(r"\bv?([0-9]+\.[0-9]+\.[0-9]+)\b",text)
    return ("v"+match.group(1)) if match else ""

def nuclei_binary():
    """Resolve the configured Nuclei binary and match it against the reviewed-build registry.
    Returns (path, build_meta). Identity/integrity (the exact SHA256 must be a registry key) is kept
    separate from version compatibility (the registry metadata); an unknown/unverified build is
    reported Unsupported and never run, and attestation is never bypassed.

    Candidate-testing path: requires TWO env vars set simultaneously —
      REDVECTOR_NUCLEI_ALLOW_CANDIDATE=testing  (explicit test-mode gate; absent in production)
      REDVECTOR_NUCLEI_CANDIDATE_SHA256=<sha>   (operator-supplied expected SHA of the binary)
    Both must be present and the binary's actual SHA must match exactly.  Setting only the SHA env
    var in production has no effect; REDVECTOR_NUCLEI_ALLOW_CANDIDATE is the gate that must never
    be set in production deployments.  All execution restrictions still apply; no check is weakened."""
    value=os.environ.get("REDVECTOR_NUCLEI_BIN") or shutil.which("nuclei")
    if not value:raise AssessmentError("Missing Dependency: configure REDVECTOR_NUCLEI_BIN or install Nuclei on the backend PATH.")
    path=Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise AssessmentError("Unsupported Nuclei runtime: an absolute, non-symlink regular-file path is required.")
    actual=digest(path)
    meta=NUCLEI_BUILDS.get(actual)
    if not meta:
        # Candidate-testing path: both the test-mode gate AND the SHA must be set and match.
        # The gate (REDVECTOR_NUCLEI_ALLOW_CANDIDATE=testing) must never be set in production.
        # Setting only the SHA env var has no effect — both keys are required.
        test_mode=os.environ.get("REDVECTOR_NUCLEI_ALLOW_CANDIDATE","") == "testing"
        candidate=os.environ.get("REDVECTOR_NUCLEI_CANDIDATE_SHA256","").lower().strip()
        if test_mode and candidate and actual==candidate:
            meta={"version":"","platform":"","capabilities":["offline-root-response-header-templates"],
                  "template_requirements":"candidate testing — not yet in production registry",
                  "evidence":"candidate","candidate":True}
        else:
            raise AssessmentError("Unsupported Nuclei runtime: unknown/unverified build (configured binary sha256 "+actual[:12]
                +"...). Only individually reviewed, checksum-verified Nuclei builds are accepted; install a reviewed build "
                "with tools/install_reviewed_nuclei.py and point REDVECTOR_NUCLEI_BIN at it. A different build stays "
                "unavailable until reviewed; attestation is not bypassed.")
    return path,dict(meta,sha256=actual)

def no_network():
    """Linux amd64 seccomp: scanner cannot create or connect network sockets."""
    if not sys.platform.startswith("linux") or platform.machine() not in ("x86_64","amd64"):
        raise AssessmentError("Offline Nuclei sandbox requires Linux amd64.")
    class Filter(ctypes.Structure):
        _fields_=[("code",ctypes.c_ushort),("jt",ctypes.c_ubyte),("jf",ctypes.c_ubyte),("k",ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_=[("length",ctypes.c_ushort),("filter",ctypes.POINTER(Filter))]
    # Validate ABI; refuse x32 syscalls; deny socket/connect/sendto/sendmsg/sendmmsg.
    rules=[(0x20,0,0,4),(0x15,1,0,0xc000003e),(0x06,0,0,0x50001),(0x20,0,0,0),
           (0x35,0,1,0x40000000),(0x06,0,0,0x50001)]
    for number in (41,42,44,46,307):
        rules.extend([(0x15,0,1,number),(0x06,0,0,0x50001)])
    rules.append((0x06,0,0,0x7fff0000))
    array=(Filter*len(rules))(*(Filter(*r) for r in rules));program=Program(len(rules),array)
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(38,1,0,0,0) or libc.prctl(22,2,ctypes.byref(program),0,0):
        raise AssessmentError("Offline scanner network sandbox unavailable.")

def _env(directory):
    env={"PATH":os.defpath,"HOME":str(directory),"XDG_CONFIG_HOME":str(directory),
            "XDG_CACHE_HOME":str(directory),"LC_ALL":"C","DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD":"true",
            "DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD":"true","DISABLE_NUCLEI_TEMPLATES_GITLAB_DOWNLOAD":"true"}
    # Propagate candidate-testing SHA only when the test-mode gate is also set.
    # REDVECTOR_NUCLEI_ALLOW_CANDIDATE must never be present in production; its absence is the default-safe state.
    if os.environ.get("REDVECTOR_NUCLEI_ALLOW_CANDIDATE","") == "testing":
        candidate=os.environ.get("REDVECTOR_NUCLEI_CANDIDATE_SHA256","").lower().strip()
        if candidate:env["REDVECTOR_NUCLEI_CANDIDATE_SHA256"]=candidate
    return env

def _command(binary,args,directory):
    return subprocess.run([sys.executable,str(Path(__file__).resolve()),"--offline-nuclei",str(binary),*args],
        cwd=directory,env=_env(directory),stdin=subprocess.DEVNULL,capture_output=True,timeout=30)

def capabilities():
    states={HTTP_PROFILE:{"state":"Ready","detail":"Pinned one-root GET/HEAD; redirects/proxies/credentials disabled."},
            SCAN_PROFILE:{"state":"Ready","detail":"Bounded TCP connect discovery; <=128 explicit ports, <=64 concurrent, 1s connect timeout, 20s deadline; native masscan/rustscan not executed."}}
    try:
        binary,meta=nuclei_binary()
        # Candidate builds are never usable in production capabilities or assessments.
        # Test the subprocess execution path via the W6 acceptance test instead.
        if meta.get("candidate"):
            raise AssessmentError(
                "Unsupported: unregistered candidate build detected. "
                "Add to NUCLEI_BUILDS with mode-A execution evidence before production use. "
                "Use the W6 acceptance test to validate the subprocess execution path.")
        if not sys.platform.startswith("linux") or platform.machine() not in ("x86_64","amd64"):
            raise AssessmentError("Unsupported native sandbox platform.")
        with tempfile.TemporaryDirectory(prefix="rv-nuclei-check-") as d:
            result=_command(binary,["-version"],Path(d))
            detected=nuclei_version(result.stdout+result.stderr)
            if result.returncode:
                raise AssessmentError("Nuclei runtime or network sandbox preflight failed.")
            if meta.get("version") and detected!=meta["version"]:
                raise AssessmentError("Nuclei runtime or network sandbox preflight failed: detected "
                    +(detected or "unknown")+" does not match the reviewed build's version "+meta["version"]+".")
        states[NUCLEI_PROFILE]={"state":"Ready","detail":"Offline Nuclei "+meta["version"]+" (reviewed build "+meta["sha256"][:12]+"...); fixed root-response header templates; scanner sockets denied by seccomp."}
    except (AssessmentError,OSError,subprocess.SubprocessError) as exc:
        detail=str(exc)[:300];states[NUCLEI_PROFILE]={"state":"Missing Dependency" if "Missing Dependency" in detail else "Unsupported","detail":detail}
    return states

def template(ident,header):
    return ('id: '+ident+'\ninfo:\n  name: Missing '+header+' response header\n  author: redvector\n  severity: info\n'
            'http:\n  - method: GET\n    path:\n      - "{{BaseURL}}"\n    matchers:\n      - type: word\n'
            '        part: header\n        words:\n          - "'+header+':"\n        case-insensitive: true\n        negative: true\n')

def run_nuclei(params):
    started=time.monotonic()
    try:
        if set(params)-{"target","severity","tags","template","additional_args","use_recovery"}:
            raise AssessmentError("Unexpected Nuclei arguments.")
        if params.get("template")!=NUCLEI_PROFILE or params.get("use_recovery") is not False or any(params.get(k,"") for k in ("severity","tags")):
            raise AssessmentError("Fixed offline Nuclei profile with recovery disabled required.")
        binary,meta=nuclei_binary()
        if meta.get("candidate"):
            raise AssessmentError("Candidate builds are not available for production assessments; "
                "add to NUCLEI_BUILDS with mode-A evidence first.")
        if not _LOCK.acquire(blocking=False):raise AssessmentError("Assessment concurrency limit reached.")
        try:
            authority=params.get("additional_args","")
            headers=None
            if authority:
                if not isinstance(authority,str) or not authority.startswith("--redvector-authority="):
                    raise AssessmentError("Only the internal pinned authority marker is permitted.")
                value=authority.split("=",1)[1]
                if not re.fullmatch(r"[A-Za-z0-9.:[\]-]{1,260}",value):
                    raise AssessmentError("Invalid internal authority.")
                headers={"Host":value}
            captured=fetch(params.get("target"),headers=headers)
            with tempfile.TemporaryDirectory(prefix="rv-nuclei-evidence-") as d:
                directory=Path(d);responses=directory/"responses";responses.mkdir()
                # Only headers are checked. http.client already decoded chunked bodies;
                # retain original evidence, but do not feed inconsistent framing to Nuclei.
                header_input=captured["raw"].split("\r\n",1)[0]+"\r\n"
                for key,value in captured["headers"].items():
                    if key.lower() not in {"transfer-encoding","content-encoding","content-length","trailer","connection"}:
                        header_input+=key+": "+value+"\r\n"
                header_input+="Content-Length: 0\r\n\r\n"
                (responses/"response.txt").write_text(header_input,encoding="utf-8")
                templates=directory/"templates";templates.mkdir()
                for ident,header in [("rv-missing-nosniff","X-Content-Type-Options"),("rv-missing-frame-options","X-Frame-Options")]:
                    (templates/(ident+".yaml")).write_text(template(ident,header),encoding="utf-8")
                result=_command(binary,["-passive","-u",str(responses),"-t",str(templates),"-ni","-duc","-dr","-nh","-no-stdin","-jsonl","-silent","-nc","-omit-raw","-c","1","-bs","1","-timeout","3","-retries","0"],directory)
                if result.returncode or len(result.stdout)+len(result.stderr)>1048576:
                    raise AssessmentError("Offline Nuclei failed or exceeded output budget.")
                rows=[]
                for line in result.stdout.decode("utf-8","strict").splitlines():
                    item=json.loads(line)
                    ident=item.get("template-id")
                    if ident not in ("rv-missing-nosniff","rv-missing-frame-options"):raise AssessmentError("Unexpected template result.")
                    rows.append({"id":ident,"title":item["info"]["name"],"severity":"info",
                                 "evidence":{"status_code":captured["status_code"],"response_headers":captured["headers"]},
                                 "validation":"Observed response configuration; exploitability not assessed"})
                expected={ident for ident,key in [("rv-missing-nosniff","x-content-type-options"),("rv-missing-frame-options","x-frame-options")] if key not in captured["headers"]}
                if {row["id"] for row in rows}!=expected or len(rows)!=len(expected):
                    raise AssessmentError("Nuclei header matches conflict with actual captured evidence; assessment is not clean.")
                return {"success":True,"input_representation":"Canonical header-only response; body/framing excluded from offline checks.","profile":NUCLEI_PROFILE,"target":params["target"],"findings":rows,
                        "stdout":result.stdout.decode(),"execution_time":time.monotonic()-started,
                        "limitations":"Two passive root-response header checks only; absence is not proof of exploitable vulnerability.",
                        "scanner":{"name":"nuclei","version":meta["version"],"sha256":meta["sha256"],"network":"seccomp denied sockets"}}
        finally:_LOCK.release()
    except (AssessmentError,OSError,ValueError,KeyError,subprocess.SubprocessError,http.client.HTTPException) as exc:
        return {"success":False,"profile":NUCLEI_PROFILE,"error":str(exc)[:300]}

HTTP_ASSESS_MARKER="--redvector-http-assess-v1"
ASSESS_TOOLS=frozenset({"httpx_probe","nikto_scan","wafw00f_scan","jaeles_vulnerability_scan"})
_SECURITY_HEADERS=[("strict-transport-security","HSTS"),("content-security-policy","Content-Security-Policy"),
    ("x-frame-options","X-Frame-Options"),("x-content-type-options","X-Content-Type-Options"),
    ("referrer-policy","Referrer-Policy"),("permissions-policy","Permissions-Policy")]
_WAF_SIGNATURES=[("Cloudflare","server","cloudflare"),("Cloudflare","cf-ray",""),("Sucuri","x-sucuri-id",""),
    ("Sucuri","server","sucuri"),("Akamai","server","akamaighost"),("Imperva Incapsula","x-iinfo",""),
    ("Imperva Incapsula","set-cookie","incap_ses"),("AWS CloudFront","server","cloudfront"),
    ("AWS CloudFront","x-amz-cf-id",""),("Fastly","x-served-by","cache"),("Fastly","server","fastly"),
    ("F5 BIG-IP","set-cookie","bigipserver"),("Barracuda","set-cookie","barra_counter_session"),
    ("Wallarm","server","wallarm"),("Fortinet FortiWeb","set-cookie","fortiwafsid")]
_TECH_SIGNATURES=[("nginx","server","nginx"),("Apache","server","apache"),("Microsoft-IIS","server","microsoft-iis"),
    ("PHP","x-powered-by","php"),("ASP.NET","x-powered-by","asp.net"),("ASP.NET","x-aspnet-version",""),
    ("Express","x-powered-by","express"),("OpenResty","server","openresty"),("LiteSpeed","server","litespeed"),
    ("Werkzeug","server","werkzeug")]
_JAELES_SIGNATURES=[("rv-info-powered-by","Technology disclosure via X-Powered-By","info","header","x-powered-by",None),
    ("rv-info-aspnet-version","ASP.NET version disclosure","low","header","x-aspnet-version",None),
    ("rv-info-server-version","Server banner version disclosure","info","header","server",r"\d"),
    ("rv-expo-status","Exposed server-status page","low","body",None,r"(?i)apache server status|/server-status"),
    ("rv-error-stacktrace","Verbose error/stack trace in response","low","body",None,r"(?i)traceback \(most recent call last\)|fatal error:|exception in thread"),
    ("rv-info-phpinfo","phpinfo output exposed","low","body",None,r"(?i)<title>phpinfo\(\)"),
    ("rv-default-page","Default/placeholder landing page","info","body",None,r"(?i)it works!|welcome to nginx!")]

def _title(body):
    match=re.search(r"<title[^>]*>(.*?)</title>",body or "",re.IGNORECASE|re.DOTALL)
    return re.sub(r"\s+"," ",match.group(1)).strip()[:200] if match else ""

def _technologies(headers):
    found=[]
    for name,key,needle in _TECH_SIGNATURES:
        value=headers.get(key,"")
        if value and (needle=="" or needle in value.lower()) and name not in found:found.append(name)
    return found

def _httpx_probe(captured):
    headers=captured["headers"]
    return {"probe":{"status_code":captured["status_code"],"title":_title(captured["body"]),
        "webserver":headers.get("server",""),"content_type":headers.get("content-type",""),
        "content_length":len(captured["body"].encode("utf-8","replace")),"powered_by":headers.get("x-powered-by",""),
        "technologies":_technologies(headers),"redirect_followed":False}}

def _wafw00f(captured):
    headers=captured["headers"];vendors=[];seen=set()
    for name,key,needle in _WAF_SIGNATURES:
        value=headers.get(key,"")
        if value and (needle=="" or needle in value.lower()) and name not in seen:
            seen.add(name);vendors.append({"name":name,"evidence":{key:value[:200]}})
    return {"waf":{"detected":bool(vendors),"vendors":vendors,"signatures_evaluated":len(_WAF_SIGNATURES)}}

def _nikto(captured):
    headers=captured["headers"];findings=[]
    if re.search(r"\d",headers.get("server","")):
        findings.append({"id":"rv-server-banner","title":"Server banner version disclosure","severity":"info","evidence":{"server":headers["server"][:200]}})
    if headers.get("x-powered-by"):
        findings.append({"id":"rv-powered-by","title":"X-Powered-By technology disclosure","severity":"info","evidence":{"x-powered-by":headers["x-powered-by"][:200]}})
    for key,label in _SECURITY_HEADERS:
        if key=="strict-transport-security" and not captured.get("scheme_https"):continue
        if key not in headers:
            findings.append({"id":"rv-missing-"+key,"title":"Missing "+label+" response header","severity":"info","evidence":{"header":label}})
    cookie=headers.get("set-cookie","")
    if cookie:
        lowered=cookie.lower()
        for flag in ("secure","httponly"):
            if flag not in lowered:
                findings.append({"id":"rv-cookie-"+flag,"title":"Root Set-Cookie without "+flag.capitalize()+" flag","severity":"low","evidence":{"set-cookie":cookie[:120]}})
    if re.search(r"(?i)<title>index of /|directory listing for",captured["body"] or ""):
        findings.append({"id":"rv-dir-listing","title":"Directory listing exposed on root","severity":"low","evidence":{"body":"index listing marker"}})
    for row in findings:row["validation"]="Observed response configuration; exploitability not assessed"
    return {"findings":findings}

def _jaeles(captured):
    headers=captured["headers"];body=captured["body"] or "";matches=[]
    for ident,name,severity,location,key,pattern in _JAELES_SIGNATURES:
        hit=None
        if location=="header":
            value=headers.get(key,"")
            if value and (pattern is None or re.search(pattern,value)):hit={key:value[:200]}
        else:
            found=re.search(pattern,body)
            if found:hit={"body":found.group(0)[:120]}
        if hit:matches.append({"id":ident,"name":name,"severity":severity,"location":location,"evidence":hit,
            "validation":"Passive signature match on one root response; not an active exploit test"})
    return {"matches":matches,"signatures_evaluated":len(_JAELES_SIGNATURES)}

_ASSESS_ANALYZERS={"httpx_probe":_httpx_probe,"wafw00f_scan":_wafw00f,"nikto_scan":_nikto,"jaeles_vulnerability_scan":_jaeles}
_ASSESS_LIMITS={
    "httpx_probe":"One confined TLS-verified root GET; status/title/server/technology are actual response observations. No port lists, crawling, file probing or external httpx binary.",
    "wafw00f_scan":"Passive WAF/CDN fingerprint from one root response's headers only; absence is not proof that no WAF is present; no active WAF-triggering payloads.",
    "nikto_scan":"Passive security-configuration review of one root response; a bounded subset of server/header/cookie checks, not a full Nikto scan and no external Nikto binary is run.",
    "jaeles_vulnerability_scan":"Fixed passive signature set matched against one root response; not Jaeles active signature testing and no external Jaeles binary is run."}

def run_http_assessment(tool,params):
    try:
        if tool not in ASSESS_TOOLS:raise AssessmentError("Unknown reviewed HTTP assessment tool.")
        allowed={"target","url","additional_args","probe","tech_detect","status_code","content_length","title","web_server","threads","signatures","config","timeout"}
        if not isinstance(params,dict) or set(params)-allowed:raise AssessmentError("Unexpected reviewed assessment arguments.")
        if params.get("additional_args")!=HTTP_ASSESS_MARKER:raise AssessmentError("Reviewed HTTP assessment profile marker required.")
        url=params.get("url") if tool=="jaeles_vulnerability_scan" else params.get("target")
        u,_host,_port=validate_url(url)
        captured=fetch(url,"GET")
        captured["scheme_https"]=(u.scheme=="https")
        result=_ASSESS_ANALYZERS[tool](captured)
        result.update(success=True,profile=HTTP_ASSESS_MARKER,tool=tool,target=url,status_code=captured["status_code"],
            engine="redvector-reviewed-passive-http",
            scanner={"name":tool.split("_")[0],"mode":"RedVector reviewed passive collector; no external scanner binary executed"},
            limitations=_ASSESS_LIMITS[tool])
        return result
    except (AssessmentError,OSError,ValueError,KeyError,http.client.HTTPException) as exc:
        return {"success":False,"profile":HTTP_ASSESS_MARKER,"tool":tool,"error":str(exc)[:300]}

SCAN_PROFILE="redvector-tcp-connect-v1"
SCAN_MARKER="--redvector-tcp-connect-v1"
SCAN_TOOLS=frozenset({"masscan_high_speed","rustscan_fast_scan"})
_SCAN_MAX_PORTS=128
_SCAN_WORKERS=64
_SCAN_SLOTS=threading.BoundedSemaphore(_SCAN_WORKERS)
_SCAN_CONNECT_TIMEOUT=1.0
_SCAN_DEADLINE=20.0

def _unicast_ip(value):
    ip=ipaddress.ip_address(value)
    if ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        raise AssessmentError("A canonical unicast numeric target is required.")
    return ip

def _scan_ports(spec):
    ports=[]
    for group in str(spec).split(","):
        if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?",group or ""):raise AssessmentError("Ports must be numbers or ascending ranges.")
        nums=[int(n) for n in group.split("-")]
        if not all(1<=n<=65535 for n in nums) or nums[0]>nums[-1]:raise AssessmentError("Ports must be within 1..65535 and ascending.")
        ports.extend(range(nums[0],nums[-1]+1))
    ports=sorted(set(ports))
    if not ports or len(ports)>_SCAN_MAX_PORTS:raise AssessmentError("Reviewed bounded TCP discovery permits 1..128 explicit ports.")
    return ports

def _connect(host,port,family,deadline):
    remaining=deadline-time.monotonic()
    if remaining<=0 or not _SCAN_SLOTS.acquire(blocking=True,timeout=remaining):return port,"filtered"
    try:
        remaining=deadline-time.monotonic()
        if remaining<=0:return port,"filtered"
        sock=socket.socket(family,socket.SOCK_STREAM);sock.settimeout(min(_SCAN_CONNECT_TIMEOUT,remaining))
        try:
            sock.connect((host,port));return port,"open"
        except (socket.timeout,TimeoutError):return port,"filtered"
        except ConnectionRefusedError:return port,"closed"
        except OSError as exc:return port,("closed" if exc.errno==111 else "filtered")
        finally:sock.close()
    finally:_SCAN_SLOTS.release()

def run_tcp_connect(tool,params):
    started=time.monotonic()
    try:
        if tool not in SCAN_TOOLS:raise AssessmentError("Unknown reviewed TCP discovery tool.")
        allowed={"target","ports","additional_args","rate","interface","router_mac","source_ip","banners","ulimit","batch_size","timeout","scripts"}
        if not isinstance(params,dict) or set(params)-allowed:raise AssessmentError("Unexpected reviewed scan arguments.")
        if params.get("additional_args")!=SCAN_MARKER:raise AssessmentError("Reviewed bounded TCP discovery marker required.")
        host=params.get("target")
        if not isinstance(host,str):raise AssessmentError("A single numeric target is required.")
        ip=_unicast_ip(host);ports=_scan_ports(params.get("ports",""))
        family=socket.AF_INET6 if ip.version==6 else socket.AF_INET
        deadline=started+_SCAN_DEADLINE;results=[]
        with concurrent.futures.ThreadPoolExecutor(max_workers=_SCAN_WORKERS) as pool:
            for port,state in pool.map(lambda p:_connect(str(ip),p,family,deadline),ports):
                results.append({"port":port,"state":state})
        results.sort(key=lambda row:row["port"])
        open_ports=[row["port"] for row in results if row["state"]=="open"]
        return {"success":True,"profile":SCAN_PROFILE,"requested_tool":tool,"engine":"redvector-reviewed-tcp-connect",
                "scanner":{"name":tool.split("_")[0],"mode":"RedVector reviewed bounded TCP connect engine; native masscan/rustscan not executed"},
                "target":str(ip),"ports_scanned":len(ports),"open_ports":open_ports,"results":results,
                "execution_time":time.monotonic()-started,
                "limitations":"Bounded TCP connect() discovery only: at most 128 explicit ports, <=64 concurrent connections, 1s per-connect timeout and a 20s overall deadline. Not native masscan/rustscan; no raw sockets, high-speed/internet-scale rates, banners, UDP or OS detection."}
    except (AssessmentError,OSError,ValueError) as exc:
        return {"success":False,"profile":SCAN_PROFILE,"requested_tool":tool,"error":str(exc)[:300]}

if __name__=="__main__":
    if len(sys.argv)<4 or sys.argv[1]!="--offline-nuclei":raise SystemExit(2)
    binary=Path(sys.argv[2])
    if binary.is_symlink() or not binary.is_file():raise SystemExit("Reviewed Nuclei build not recognized")
    actual=digest(binary)
    if actual not in NUCLEI_BUILDS:
        # Candidate-testing path: accept the binary only when its actual SHA256 exactly matches
        # REDVECTOR_NUCLEI_CANDIDATE_SHA256.  All other execution restrictions still apply.
        candidate=os.environ.get("REDVECTOR_NUCLEI_CANDIDATE_SHA256","").lower().strip()
        if not candidate or actual!=candidate:
            raise SystemExit("Reviewed Nuclei build not recognized")
    no_network()
    os.execv(str(binary),[str(binary),*sys.argv[3:]])

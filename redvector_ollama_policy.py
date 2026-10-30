"""Fail-closed execution policy for the Ollama client; MCP registrations are unchanged."""
import copy
import ipaddress
import re
import socket
import queue
import threading
import time

class PolicyError(ValueError):
    pass

from redvector_ollama_reporting import OFFLINE_TOOLS

DIAGNOSTICS = frozenset({"server_health", "get_cache_stats","get_telemetry","error_handling_statistics"})
from redvector_reviewed_artifacts import TOOLS as ARTIFACT_TOOLS
from redvector_reviewed_runtime import TOOLS as RUNTIME_TOOLS
from redvector_reviewed_advisories import TOOLS as ADVISORY_TOOLS

HTTP_READ_TOOLS=frozenset({"http_framework_test","http_repeater","nuclei_scan"})
HTTP_ASSESS_TOOLS=frozenset({"httpx_probe","nikto_scan","wafw00f_scan","jaeles_vulnerability_scan"})
TCP_SCAN_TOOLS=frozenset({"masscan_high_speed","rustscan_fast_scan"})
NMAP_TOOLS=frozenset({"nmap_scan","nmap_advanced_scan"})
ASSESSMENT_TOOLS=frozenset({"ai_vulnerability_assessment"})
SEARCHSPLOIT_TOOLS=frozenset({"searchsploit_lookup"})
REVIEWED = DIAGNOSTICS | OFFLINE_TOOLS | HTTP_READ_TOOLS | HTTP_ASSESS_TOOLS | TCP_SCAN_TOOLS | ARTIFACT_TOOLS | RUNTIME_TOOLS | ADVISORY_TOOLS | NMAP_TOOLS | ASSESSMENT_TOOLS | SEARCHSPLOIT_TOOLS | {"clear_cache"}
DISABLED_REASONS = {"whois_lookup": "WHOIS registry and referral destinations cannot be confined by the existing backend."}
FIXED_NMAP_ARGS = "-n -Pn --unprivileged --max-retries 1 --host-timeout 60s"
AUTO_NMAP_ARGS = FIXED_NMAP_ARGS + " --max-rate 50 --scan-delay 20ms --max-parallelism 8"

def validate_arguments(schema, arguments):
    from jsonschema import Draft202012Validator, exceptions
    if not isinstance(arguments, dict):
        raise PolicyError("Tool arguments must be a JSON object.")
    try:
        checked = copy.deepcopy(schema)
        # The existing SDK schemas allow extras by default; this client does not.
        checked["additionalProperties"] = False
        Draft202012Validator.check_schema(checked)
        Draft202012Validator(checked).validate(arguments)
    except (exceptions.SchemaError, exceptions.ValidationError, TypeError, ValueError) as exc:
        raise PolicyError("Arguments do not match the discovered tool schema.") from exc
    return arguments

def hostname(value):
    if not isinstance(value, str) or len(value)>253 or not re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value
    ):
        raise PolicyError("Use a single plain hostname or IP, without URLs, options or shell syntax.")
    labels = value.split(".")
    if any(len(x)>63 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?",x) for x in labels):
        raise PolicyError("Invalid hostname.")
    # Reject ambiguous alternate numeric IP representations.
    if all(re.fullmatch(r"(?:0x[0-9a-fA-F]+|[0-9]+)",x) for x in labels):
        raise PolicyError("Use a canonical IP address.")
    return value.lower()

def target(value):
    if not isinstance(value,str):
        raise PolicyError("Target must be text.")
    try:
        address=ipaddress.ip_address(value)
        # Backend shell commands interpolate target, so IPv6 zone identifiers are refused.
        if "%" in value:
            raise PolicyError("Scoped IPv6 addresses are unsupported.")
        return str(_unicast(address))
    except ValueError:
        return hostname(value)

def _unicast(address):
    if address.is_unspecified or address.is_multicast:
        raise PolicyError("Assessment destinations must be unicast addresses.")
    if address.version == 4 and int(address) >= int(ipaddress.IPv4Address("240.0.0.0")):
        raise PolicyError("Reserved and broadcast destinations are unsupported.")
    if address.version == 6 and address.ipv4_mapped:
        _unicast(address.ipv4_mapped)
    return address


# Stalled OS lookups cannot be cancelled safely. Daemon workers keep shutdown
# unblocked, while slots remain occupied until the actual lookup finishes.
DNS_LOOKUP_TIMEOUT = 5.0
_DNS_WORKER_SLOTS = threading.BoundedSemaphore(4)


def _system_resolver(name):
    slots = _DNS_WORKER_SLOTS
    if not slots.acquire(blocking=False):
        raise PolicyError("DNS lookup capacity is busy; try again later.")
    result = queue.Queue(maxsize=1)

    def lookup():
        payload = (False, ())
        try:
            answers = []
            for index, row in enumerate(socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)):
                if index >= 256:
                    raise PolicyError("DNS answer set exceeds the reviewed limit.")
                answers.append(row[4][0])
            payload = (True, tuple(answers))
        except Exception:
            # Do not retain or forward OS exception text or traceback secrets.
            pass
        finally:
            slots.release()
            result.put_nowait(payload)

    try:
        threading.Thread(target=lookup, name="redvector-dns", daemon=True).start()
    except Exception:
        slots.release()
        raise PolicyError("Could not start a bounded DNS lookup.") from None
    try:
        success, answers = result.get(timeout=DNS_LOOKUP_TIMEOUT)
    except queue.Empty:
        raise PolicyError("DNS lookup timed out; authorized scope is unchanged.") from None
    if not success:
        raise PolicyError("Could not resolve the authorized hostname safely.") from None
    return answers


class Policy:
    def __init__(self, scope=(), resolver=None, auto_discovery=True, clock=None):
        self.auto_discovery=auto_discovery is True
        self.clock=clock or time.monotonic
        self.auto_count=0;self.last_auto=float("-inf");self.last_automatic=False
        self.task=None;self.last_task_id=None
        self.profile_status={};self.version_intensity=1;self.report_provider=None;self.artifact_provider=None;self.observed_processes={}
        self._resolver = resolver if resolver is not None else _system_resolver
        self._state = ((), {}, 0)
        self.replace_scope(scope)

    @property
    def scope(self):
        return self._state[0]

    @property
    def revision(self):
        return self._state[2]

    def snapshot(self):
        return tuple(str(value) for value in self.scope)

    def dns_snapshot(self):
        return dict(self._state[1])

    def _resolve(self, name):
        try:
            answers = set()
            for index, value in enumerate(self._resolver(name)):
                if index >= 256 or not isinstance(value, str) or "%" in value:
                    raise PolicyError("DNS answer set is invalid or exceeds the reviewed limit.")
                answers.add(str(_unicast(ipaddress.ip_address(value))))
                if len(answers) > 64:
                    raise PolicyError("DNS answer set exceeds the reviewed limit.")
            if not answers:
                raise PolicyError("Authorized hostname has no usable DNS destinations.")
            return tuple(sorted(answers, key=lambda value: (ipaddress.ip_address(value).version,
                                                           int(ipaddress.ip_address(value)))))
        except PolicyError:
            raise
        except Exception as exc:
            raise PolicyError("Could not resolve the authorized hostname safely.") from exc

    def replace_scope(self, values):
        if isinstance(values, (str, bytes, dict)):
            raise PolicyError("Scope must be a sequence of explicit targets.")
        allowed, pins = [], {}
        try:
            for value in values:
                if not isinstance(value, str) or "%" in value:
                    raise PolicyError("Invalid authorized target scope.")
                if "/" in value:
                    entry = ipaddress.ip_network(value, strict=False)
                    if entry.network_address.is_multicast or entry.prefixlen == entry.max_prefixlen:
                        _unicast(entry.network_address)
                else:
                    entry = target(value)
                    try:
                        _unicast(ipaddress.ip_address(entry))
                    except ValueError:
                        if entry not in pins:
                            pins[entry] = self._resolve(entry)
                if entry not in allowed:
                    allowed.append(entry)
        except (ValueError, TypeError) as exc:
            raise PolicyError("Invalid authorized target scope.") from exc
        # Publish only after every entry and DNS answer has validated.
        self._state = (tuple(allowed), pins, self.revision + 1)

    def _destination(self, value):
        canonical = target(value)
        state = self._state
        try:
            address = _unicast(ipaddress.ip_address(canonical))
        except ValueError:
            pinned = state[1].get(canonical)
            if pinned is None:
                raise PolicyError("Hostname is outside the operator-authorized scope.")
            if self._resolve(canonical) != pinned:
                raise PolicyError("DNS destinations changed; explicitly replace scope to authorize new pins.")
            return pinned[0]
        for allowed in state[0]:
            if isinstance(allowed, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                if address.version == allowed.version and address in allowed:
                    return str(address)
                continue
            if allowed == canonical:
                return str(address)
        for name, addresses in state[1].items():
            if canonical in addresses:
                if self._resolve(name) != addresses:
                    raise PolicyError("DNS destinations changed; explicitly replace scope to authorize new pins.")
                return str(address)
        raise PolicyError("Target is outside the operator-authorized scope.")

    def destination(self, value):
        """Resolve only an explicitly authorized, pinned single-host destination."""
        return self._destination(value)

    def contains(self, value):
        try:
            self._destination(value)
            return True
        except PolicyError:
            return False

    def _prepare(self, name, args):
        if name not in REVIEWED:
            raise PolicyError(DISABLED_REASONS.get(name, "Tool is discoverable but has no reviewed execution policy."))
        if not isinstance(args, dict):
            raise PolicyError("Arguments must be an object.")
        if name in ADVISORY_TOOLS:
            from redvector_reviewed_advisories import validate
            capability=self.profile_status.get("nvd-advisory-v1",{})
            if capability.get("state")!="Ready":raise PolicyError("Advisory profile unavailable. "+str(capability.get("detail","Updated verified backend required.")))
            if name=="vulnerability_intelligence_dashboard":
                if args:raise PolicyError("Advisory dashboard accepts no arguments.")
                return {}
            try:validate(args)
            except ValueError as exc:raise PolicyError(str(exc)) from exc
            return dict(args)
        if name in RUNTIME_TOOLS:
            capability=self.profile_status.get("runtime-read-v1",{})
            if capability.get("state")!="Ready":raise PolicyError("Runtime profile unavailable. "+str(capability.get("detail","Updated verified backend required.")))
            if name=="get_process_status":
                if set(args)!={"pid"} or type(args.get("pid")) is not int or args["pid"] not in self.observed_processes:
                    raise PolicyError("Rediscover managed backend jobs with list_active_processes before requesting that PID.")
                return dict(args)
            if args:raise PolicyError("This runtime diagnostic accepts no arguments.")
            return {}
        if name in DIAGNOSTICS or name == "clear_cache":
            if args:
                raise PolicyError("This tool accepts no arguments.")
            return {}
        if name in OFFLINE_TOOLS:
            if self.report_provider is None:raise PolicyError("Saved evidence provider is required for offline reporting.")
            marker={"create_vulnerability_report":"vulnerabilities","create_scan_summary":"target","format_tool_output_visual":"output"}[name]
            if args.get(marker)!="saved":raise PolicyError("Offline reports must use the saved-evidence marker, never model-invented findings.")
            try:payload=self.report_provider(name)
            except (OSError,ValueError,KeyError,TypeError) as exc:raise PolicyError("Saved evidence is unavailable or exceeds the formatter limit; use /results or /export.") from exc
            if set(args)-set(payload):raise PolicyError("Unexpected offline-report arguments.")
            for key,value in args.items():
                if key==marker or value=="saved":continue
                if value not in ("", "comprehensive") and value!=payload.get(key):
                    raise PolicyError("Report arguments differ from saved source evidence.")
            return payload
        if name in ARTIFACT_TOOLS:
            from redvector_reviewed_artifacts import options
            marker="binary" if name in ("objdump_analyze","checksec_analyze") else "file_path"
            if args.get(marker)!="selected" or self.artifact_provider is None:raise PolicyError("Select an artifact with /artifact PATH; model-selected paths are refused.")
            selected=self.artifact_provider()
            if not selected or selected.get("source")!="operator-snapshot":raise PolicyError("No operator-selected artifact snapshot is available.")
            capability=self.profile_status.get("artifact-read-v1:"+name,{})
            if capability.get("state")!="Ready":raise PolicyError("Artifact profile unavailable. "+str(capability.get("detail","Refresh verified backend capabilities.")))
            allowed={marker}|({"min_len","additional_args"} if name=="strings_extract" else {"offset","length","additional_args"} if name=="xxd_hexdump" else {"disassemble","additional_args"} if name=="objdump_analyze" else set())
            if set(args)-allowed:raise PolicyError("Unexpected artifact arguments.")
            try:options(name,args)
            except ValueError as exc:raise PolicyError(str(exc)) from exc
            prepared=dict(args,**{marker:selected["token"]})
            if name=="objdump_analyze":prepared.setdefault("disassemble",False)
            return prepared
        if name in HTTP_READ_TOOLS:
            from urllib.parse import urlsplit,urlunsplit
            from redvector_reviewed_assessment import HTTP_PROFILE,NUCLEI_PROFILE
            supplied=args.get("request_spec") if name=="http_repeater" else args
            if not isinstance(supplied,dict):raise PolicyError("HTTP request must be an object.")
            url=supplied.get("target") if name=="nuclei_scan" else supplied.get("url")
            if not isinstance(url,str):raise PolicyError("One explicit authorized root URL is required.")
            u=urlsplit(url)
            try:port=u.port
            except ValueError:raise PolicyError("Invalid URL port.") from None
            if u.scheme not in ("http","https") or u.username or u.password or u.query or u.fragment or u.path not in ("","/"):
                raise PolicyError("Reviewed HTTP assessment permits one root HTTP(S) URL, without credentials, queries or fragments.")
            destination=self._destination(u.hostname or "")
            ip=ipaddress.ip_address(destination)
            authority=("["+destination+"]" if ip.version==6 else destination)+((":"+str(port)) if port else "")
            pinned=urlunsplit((u.scheme,authority,"/","",""))
            required=NUCLEI_PROFILE if name=="nuclei_scan" else HTTP_PROFILE
            capability=self.profile_status.get(required,{})
            if capability.get("state")!="Ready":raise PolicyError("Reviewed assessment unavailable. "+str(capability.get("detail","Refresh backend capabilities with /tools.")))
            if name=="nuclei_scan":
                if set(supplied)-{"target","severity","tags","template","additional_args"} or any(supplied.get(k,"") for k in ("severity","tags","additional_args")) or supplied.get("template","") not in ("",NUCLEI_PROFILE):
                    raise PolicyError("Only the fixed root-response Nuclei profile is currently reviewed.")
                return {"target":pinned,"severity":"","tags":"","template":NUCLEI_PROFILE,"additional_args":"--redvector-authority="+u.netloc}
            if set(supplied)-{"url","method","data","headers","cookies","action"} or supplied.get("data") not in (None,{}) or supplied.get("cookies") not in (None,{}) or supplied.get("headers") not in (None,{}):
                raise PolicyError("Reviewed HTTP reads do not accept bodies, cookies or custom headers.")
            if supplied.get("method","GET") not in ("GET","HEAD") or supplied.get("action","request") not in ("request",HTTP_PROFILE):
                raise PolicyError("Only the reviewed GET/HEAD root response is supported.")
            payload={"url":pinned,"method":supplied.get("method","GET"),"headers":{"Host":u.netloc},"data":None,"cookies":None,"action":HTTP_PROFILE}
            return {"request_spec":payload} if name=="http_repeater" else payload
        if name in HTTP_ASSESS_TOOLS:
            from urllib.parse import urlsplit,urlunsplit
            from redvector_reviewed_assessment import HTTP_PROFILE,HTTP_ASSESS_MARKER
            key="url" if name=="jaeles_vulnerability_scan" else "target"
            url=args.get(key)
            if not isinstance(url,str):raise PolicyError("One explicit authorized root URL is required.")
            u=urlsplit(url)
            try:port=u.port
            except ValueError:raise PolicyError("Invalid URL port.") from None
            if u.scheme not in ("http","https") or u.username or u.password or u.query or u.fragment or u.path not in ("","/"):
                raise PolicyError("Reviewed HTTP assessment permits one root HTTP(S) URL, without credentials, queries or fragments.")
            # The reviewed passive profile ignores any model-supplied scanner flags rather than
            # failing the workflow; it always runs the fixed confined root-response assessment.
            capability=self.profile_status.get(HTTP_PROFILE,{})
            if capability.get("state")!="Ready":raise PolicyError("Reviewed assessment unavailable. "+str(capability.get("detail","Refresh backend capabilities with /tools.")))
            destination=self._destination(u.hostname or "")
            ip=ipaddress.ip_address(destination)
            authority=("["+destination+"]" if ip.version==6 else destination)+((":"+str(port)) if port else "")
            pinned=urlunsplit((u.scheme,authority,"/","",""))
            return {key:pinned,"additional_args":HTTP_ASSESS_MARKER}
        if name in SEARCHSPLOIT_TOOLS:
            # Offline, read-only local Exploit-DB lookup (no network target). The backend adapter
            # re-validates strictly and runs a fixed argv vector; here we constrain the arguments,
            # require the attested profile, force read-only JSON output and inject the marker.
            from redvector_reviewed_searchsploit import SEARCHSPLOIT_MARKER,PROFILE as SEARCHSPLOIT_PROFILE
            if set(args)-{"query","cve","exact","title_only","exclude","json_output","mirror","additional_args"}:
                raise PolicyError("Unexpected reviewed searchsploit arguments.")
            capability=self.profile_status.get(SEARCHSPLOIT_PROFILE,{})
            if capability.get("state")!="Ready":
                raise PolicyError("Reviewed searchsploit unavailable. "+str(capability.get("detail","Refresh backend capabilities with /tools.")))
            query=args.get("query","") or "";cve=args.get("cve","") or ""
            if not isinstance(query,str) or not isinstance(cve,str):raise PolicyError("Searchsploit query and CVE must be text.")
            if not query.strip() and not cve.strip():raise PolicyError("A searchsploit query or CVE is required.")
            if args.get("mirror"):raise PolicyError("Reviewed searchsploit is read-only; mirroring is disabled.")
            for flag in ("exact","title_only"):
                if args.get(flag) not in (True,False,None):raise PolicyError("Searchsploit "+flag+" must be boolean.")
            exclude=args.get("exclude","") or ""
            if not isinstance(exclude,str):raise PolicyError("Searchsploit exclude terms must be text.")
            return {"query":query,"cve":cve,"exact":bool(args.get("exact")),"title_only":bool(args.get("title_only")),
                    "exclude":exclude,"json_output":True,"mirror":"","additional_args":SEARCHSPLOIT_MARKER}
        if name in ASSESSMENT_TOOLS:
            if "target" not in args or set(args)-{"target","focus_areas"}:
                raise PolicyError("The staged assessment requires one authorized target and an optional focus area.")
            value=self._destination(args["target"])
            focus=args.get("focus_areas","all")
            if not isinstance(focus,str) or focus not in ("all","web","network","api","http"):
                focus="all"
            capability=self.profile_status.get("tcp-discovery-v1",{})
            if capability.get("state")!="Ready":
                raise PolicyError("Reviewed staged assessment unavailable: discovery profile not ready. "+str(capability.get("detail","Refresh backend capabilities with /tools.")))
            return {"target":value,"focus_areas":focus}
        if name in TCP_SCAN_TOOLS:
            from redvector_reviewed_assessment import SCAN_PROFILE,SCAN_MARKER
            if "target" not in args:raise PolicyError("One explicit authorized target is required.")
            value=self._destination(args["target"])
            if args.get("additional_args",""):raise PolicyError("Reviewed bounded TCP discovery uses a fixed profile; no extra arguments.")
            capability=self.profile_status.get(SCAN_PROFILE,{})
            if capability.get("state")!="Ready":raise PolicyError("Reviewed bounded TCP discovery unavailable. "+str(capability.get("detail","Refresh backend capabilities with /tools.")))
            ports=args.get("ports","")
            if not isinstance(ports,str) or len(ports)>2048:raise PolicyError("Invalid port selection.")
            if not ports or ports.strip() in ("1-65535","0-65535","-"):
                raise PolicyError("Reviewed bounded TCP discovery requires 1..128 explicit ports; unbounded full-range or high-speed scanning is disabled.")
            seen=set()
            for group in ports.split(","):
                if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?",group):raise PolicyError("Ports must be numbers or ascending ranges.")
                numbers=[int(number) for number in group.split("-")]
                if not all(1<=number<=65535 for number in numbers) or numbers[0]>numbers[-1]:raise PolicyError("Ports must be within 1..65535 and ascending.")
                seen.update(range(numbers[0],numbers[-1]+1))
            if len(seen)>128:raise PolicyError("Reviewed bounded TCP discovery permits at most 128 ports per call.")
            return {"target":value,"ports":ports,"additional_args":SCAN_MARKER}
        if name=="nmap_advanced_scan":
            if args.get("version_detection") is False:raise PolicyError("Explicit no-version request cannot use the active service-version profile.")
            if set(args)-{"target","ports","scan_type","timing","nse_scripts","os_detection","version_detection","aggressive","stealth","additional_args"} or any(args.get(k,False) for k in ("os_detection","aggressive","stealth")) or args.get("nse_scripts","") or args.get("additional_args","") or args.get("scan_type","-sT") not in ("-sT","-sV","-sT -sV"):
                raise PolicyError("Advanced scanner currently supports only the reviewed TCP service profile.")
            narrowed=self._prepare("nmap_scan",{"target":args.get("target"),"ports":args.get("ports",""),"scan_type":"-sT -sV"})
            return {"target":narrowed["target"],"ports":narrowed["ports"],"scan_type":narrowed["scan_type"],
                    "timing":"T2","nse_scripts":"","os_detection":False,"version_detection":True,"aggressive":False,"stealth":False,"additional_args":narrowed["additional_args"]}
        allowed = {"target", "ports", "scan_type", "additional_args", "use_recovery"}
        if set(args) - allowed or "target" not in args:
            raise PolicyError("Unexpected or missing assessment arguments.")
        value = self._destination(args["target"])
        if args.get("additional_args", "") not in ("", FIXED_NMAP_ARGS):
            raise PolicyError("Free-form command arguments are disabled.")
        if args.get("use_recovery", False) is not False:
            raise PolicyError("Automatic recovery is disabled for confined assessment calls.")
        scan = args.get("scan_type", "-sT")
        version = ipaddress.ip_address(value).version
        if version == 6 and isinstance(scan, str) and scan.startswith("-6 "):
            scan = scan[3:]
        # An explicit request for the reviewed discovery profile (used by the staged detection task)
        # is validated as plain TCP-connect discovery over its exact, operator-derived range.
        discovery_requested = scan == "--redvector-profile=tcp-discovery-v1"
        if discovery_requested:
            scan = "-sT"
        version_profile=scan in ("-sV","-sT -sV")
        if scan!="-sT" and not version_profile:
            raise PolicyError("Restricted Nmap operation: only reviewed TCP discovery/service profiles are supported; OS, UDP and arbitrary NSE remain restricted.")
        if version_profile:
            capability=self.profile_status.get("service-version-v1",{})
            if capability.get("state")!="Ready":
                raise PolicyError("Reviewed service-version profile unavailable. "+str(capability.get("detail","Updated verified backend and native runtime required.")))
            if type(self.version_intensity) is not int or not 0<=self.version_intensity<=2:
                raise PolicyError("Reviewed version intensity must be 0, 1 or 2.")
        ports = args.get("ports", "")
        if not isinstance(ports, str) or len(ports) > 2048:
            raise PolicyError("Invalid port selection.")
        if not version_profile and ports.strip() == "-":
            ports = "1-65535"  # explicit full-range discovery shorthand
        if ports:
            for group in ports.split(","):
                if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", group):
                    raise PolicyError("Ports must be numbers or ascending ranges.")
                numbers = [int(number) for number in group.split("-")]
                if not all(1 <= number <= 65535 for number in numbers) or numbers[0] > numbers[-1]:
                    raise PolicyError("Ports must be within 1..65535 and ascending.")
        if version_profile:
            count=len({port for group in ports.split(",") if group for port in range(int(group.split("-")[0]),int(group.split("-")[-1])+1)})
            if not ports or count>128:raise PolicyError("Reviewed service-version profile requires 1..128 explicit TCP ports; discover ports first.")
            from redvector_reviewed_profiles import NMAP_PROFILE
            return {"target":value,"additional_args":"--version-intensity "+str(self.version_intensity),
                    "scan_type":NMAP_PROFILE,"ports":ports,"use_recovery":False}
        if ports=="1-65535" or discovery_requested:
            # Full-range discovery, or an explicit staged-discovery request over a validated range, uses
            # the attested reviewed discovery profile (real native nmap -sT, XML parsed) — never a silent
            # fallback to the 128-port service profile. Other plain scans keep their existing bounded path.
            from redvector_reviewed_profiles import DISCOVERY_PROFILE
            if not ports:raise PolicyError("Discovery requires an explicit TCP port range.")
            capability=self.profile_status.get("tcp-discovery-v1",{})
            if capability.get("state")!="Ready":
                raise PolicyError("Reviewed TCP discovery profile unavailable. "+str(capability.get("detail","Updated verified backend and native runtime required.")))
            return {"target":value,"additional_args":"","scan_type":DISCOVERY_PROFILE,"ports":ports,"use_recovery":False}
        return {"target":value, "additional_args":FIXED_NMAP_ARGS, "scan_type":("-6 " if version == 6 else "") + scan,
                "ports":ports, "use_recovery":False}

    # ---- task-scoped authorization ---------------------------------------------------------------
    # A validated scope alone does NOT authorize operations. An explicit natural-language detection
    # task creates ONE authorization record bound to its target, operation class (detection), the
    # stages it contains, its port bound and an expiry; its constituent bounded stages reuse it
    # without repeated prompts. Tasks above the bounded range (full-range discovery) or using the
    # public advisory provider require one plain-English task confirmation. A record never covers a
    # different target, never outlives its task and is never elevated to exploitation.
    TASK_BOUNDED_PORTS = 10000
    TASK_TTL = 3600

    def begin_task(self, target, ports_requested, stages, approve, description):
        canonical = self.destination(target)              # scope-validated; raises outside scope
        stages = frozenset(stages)
        if not stages <= {"discovery", "service-version", "advisory", "web-detection", "offline-correlation"}:
            raise PolicyError("A detection task may contain only detection stages.")
        confirm = int(ports_requested) > self.TASK_BOUNDED_PORTS or "advisory" in stages
        if confirm and not approve({"tool": "detection task", "target": canonical, "reason": description}):
            raise PolicyError("Operator declined this task. No scan was executed.")
        import uuid
        self.task = {"id": uuid.uuid4().hex[:12], "target": canonical, "class": "detection", "stages": stages,
                     "max_ports": int(ports_requested), "expires": self.clock() + self.TASK_TTL,
                     "revision": self.revision, "confirmed": bool(confirm)}
        return dict(self.task)

    def end_task(self):
        self.task = None

    def _task_covers(self, stage, target=None, ports=0):
        task = getattr(self, "task", None)
        if not task or task["revision"] != self.revision or self.clock() > task["expires"]:
            return False
        if stage not in task["stages"]:
            return False
        if target is not None and target != task["target"]:
            return False
        return int(ports) <= task["max_ports"]

    def authorize(self, name, args, approve, allow_automatic=True):
        revision = self.revision
        original = copy.deepcopy(args)
        result = self._prepare(name, original)
        self.last_automatic=False
        self.last_task_id=None
        if name in ADVISORY_TOOLS:
            if self._task_covers("advisory"):
                # covered by the operator's confirmed assessment task (provider queries listed there)
                self.last_automatic=True;self.last_task_id=self.task["id"]
            elif not approve({"tool":name,"arguments":copy.deepcopy(result),"provider":"NVD","query":({"hours":24,"severity_filter":"CRITICAL","keywords":""} if name=="vulnerability_intelligence_dashboard" else {"hours":result.get("hours",24),"severity_filter":result.get("severity_filter","HIGH,CRITICAL"),"keywords":result.get("keywords","")}),"reason":"Explicit public-provider query approval required. Anonymous NVD publication window only; keywords are filtered locally. Data does not establish target applicability."}):
                raise PolicyError("Operator declined the public advisory query.")
            if self.revision!=revision or self._prepare(name,original)!=result:
                raise PolicyError("Authorization state changed during advisory approval.")
        # Scope-gated low-impact reviewed reads (diagnostics, saved-evidence, passive HTTP read and
        # assessment, bounded TCP connect, artifact, runtime, advisory) do not prompt per call;
        # high-impact operations below still require an explicit approval each time.
        if name not in DIAGNOSTICS | OFFLINE_TOOLS | HTTP_READ_TOOLS | HTTP_ASSESS_TOOLS | TCP_SCAN_TOOLS | ARTIFACT_TOOLS | RUNTIME_TOOLS | ADVISORY_TOOLS | SEARCHSPLOIT_TOOLS:
            count=1000
            if name in NMAP_TOOLS and result["ports"]:
                ports=set()
                for group in result["ports"].split(","):
                    bounds=[int(n) for n in group.split("-")]
                    ports.update(range(bounds[0],bounds[-1]+1))
                count=len(ports)
            version_profile=name in NMAP_TOOLS and result.get("scan_type","")=="--redvector-profile=service-version-v1"
            discovery_profile=name in NMAP_TOOLS and result.get("scan_type","")=="--redvector-profile=tcp-discovery-v1"
            automatic=(allow_automatic is True and name=="nmap_scan" and not version_profile and not discovery_profile and self.auto_discovery and count<=1000
                       and self.auto_count<5 and self.clock()-self.last_auto>=30)
            # Reviewed detection stages (native TCP-connect discovery and the <=128-port service-version
            # profile, both validated in _prepare) run without a repeated prompt ONLY when the active
            # task authorization covers this exact stage, target and port bound. Scope alone is not
            # enough; higher-impact operations (plain scans over 1,000 ports, state-changing tools, the
            # backend orchestrator, anything exploitation-class) still require explicit approval.
            stage="discovery" if discovery_profile else "service-version" if version_profile else None
            pre_authorized=(stage is not None and self._task_covers(stage,result.get("target"),count))
            if not automatic and not pre_authorized:
                reasons=[]
                if name in ASSESSMENT_TOOLS:reasons.append("Staged reviewed assessment (chains multiple reviewed scanners against the authorized target) requires one operator approval")
                elif name not in NMAP_TOOLS:reasons.append("State-changing operation requires explicit approval")
                else:
                    if version_profile:reasons.append("Reviewed service-version detection requires operator authorization")
                    if discovery_profile:reasons.append("Native TCP connect discovery requires operator authorization")
                    if count>1000:reasons.append("Port count exceeds the unattended 1,000-port bound")
                    if not allow_automatic:reasons.append("No explicit low-impact discovery instruction selected")
                    if not self.snapshot():reasons.append("No authorized target scope is set")
                    if not self.auto_discovery:reasons.append("Unattended discovery is disabled")
                    if self.auto_count>=5:reasons.append("Unattended discovery session limit reached")
                    if self.clock()-self.last_auto<30:reasons.append("Unattended discovery cooldown has not elapsed")
                if not approve({"tool":name, "arguments":copy.deepcopy(result),"reason":"; ".join(reasons)}):
                    raise PolicyError("Operator declined this operation.")
            if self.revision != revision:
                raise PolicyError("Authorized scope changed during approval; request a new operation.")
            if self._prepare(name, original) != result or self.revision != revision:
                raise PolicyError("Assessment destinations changed during approval.")
            if automatic:
                result["additional_args"]=AUTO_NMAP_ARGS
                self.auto_count+=1;self.last_auto=self.clock();self.last_automatic=True
            elif pre_authorized:
                # Covered by the operator's task authorization; profile marker and bounds unchanged,
                # and the task id is recorded for the audit trail.
                self.last_automatic=True;self.last_task_id=self.task["id"]
        return result

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

DIAGNOSTICS = frozenset({"server_health", "get_cache_stats"})
REVIEWED = DIAGNOSTICS | {"nmap_scan", "clear_cache"}
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
        if name in DIAGNOSTICS or name == "clear_cache":
            if args:
                raise PolicyError("This tool accepts no arguments.")
            return {}
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
        if scan != "-sT":
            raise PolicyError("Only reviewed TCP connect scans are enabled; active version detection and scripts are disabled.")
        ports = args.get("ports", "")
        if not isinstance(ports, str) or len(ports) > 128:
            raise PolicyError("Invalid port selection.")
        if ports:
            for group in ports.split(","):
                if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", group):
                    raise PolicyError("Ports must be numbers or ascending ranges.")
                numbers = [int(number) for number in group.split("-")]
                if not all(1 <= number <= 65535 for number in numbers) or numbers[0] > numbers[-1]:
                    raise PolicyError("Ports must be within 1..65535 and ascending.")
        return {"target":value, "additional_args":FIXED_NMAP_ARGS, "scan_type":("-6 " if version == 6 else "") + scan,
                "ports":ports, "use_recovery":False}

    def authorize(self, name, args, approve, allow_automatic=True):
        revision = self.revision
        original = copy.deepcopy(args)
        result = self._prepare(name, original)
        self.last_automatic=False
        if name not in DIAGNOSTICS:
            count=1000
            if name=="nmap_scan" and result["ports"]:
                ports=set()
                for group in result["ports"].split(","):
                    bounds=[int(n) for n in group.split("-")]
                    ports.update(range(bounds[0],bounds[-1]+1))
                count=len(ports)
            automatic=(allow_automatic is True and name=="nmap_scan" and self.auto_discovery and count<=1000
                       and self.auto_count<5 and self.clock()-self.last_auto>=30)
            if not automatic:
                reason=("Intensive or unattended-limit scan; explicit approval required."
                        if name=="nmap_scan" else "State-changing operation; explicit approval required.")
                if not approve({"tool":name,"arguments":copy.deepcopy(result)}):
                    raise PolicyError("Operator declined this operation.")
            if self.revision != revision:
                raise PolicyError("Authorized scope changed during approval; request a new operation.")
            if self._prepare(name, original) != result or self.revision != revision:
                raise PolicyError("Assessment destinations changed during approval.")
            if automatic:
                result["additional_args"]=AUTO_NMAP_ARGS
                self.auto_count+=1;self.last_auto=self.clock();self.last_automatic=True
        return result

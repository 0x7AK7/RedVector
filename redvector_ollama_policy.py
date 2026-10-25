"""Fail-closed execution policy for the Ollama client; MCP registrations are unchanged."""
import copy
import ipaddress
import re

class PolicyError(ValueError):
    pass

DIAGNOSTICS = frozenset({"server_health", "get_cache_stats"})
REVIEWED = DIAGNOSTICS | {"nmap_scan", "whois_lookup", "clear_cache"}

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
        return str(address)
    except ValueError:
        return hostname(value)

class Policy:
    def __init__(self, scope=()):
        self.scope=[]
        for value in scope:
            try:
                self.scope.append(ipaddress.ip_network(value,strict=False) if "/" in value else target(value))
            except (ValueError,TypeError) as exc:
                raise PolicyError("Invalid authorized target scope.") from exc

    def contains(self, value):
        canonical=target(value)
        for allowed in self.scope:
            if isinstance(allowed,(ipaddress.IPv4Network,ipaddress.IPv6Network)):
                try:
                    if ipaddress.ip_address(canonical) in allowed:
                        return True
                except ValueError:
                    pass
            elif allowed==canonical:
                return True
        return False

    def authorize(self, name, args, approve):
        if name not in REVIEWED:
            raise PolicyError("Tool is discoverable but has no reviewed execution policy.")
        if not isinstance(args,dict):
            raise PolicyError("Arguments must be an object.")
        if name in DIAGNOSTICS or name=="clear_cache":
            if args:
                raise PolicyError("This tool accepts no arguments.")
            result={}
        else:
            allowed={"target","additional_args"}
            if name=="nmap_scan":
                allowed|={"ports","scan_type"}
            if set(args)-allowed or "target" not in args:
                raise PolicyError("Unexpected or missing assessment arguments.")
            value=target(args["target"])
            if not self.contains(value):
                raise PolicyError("Target is outside the operator-authorized scope.")
            # Pin DNS targets to explicitly scoped IPs for active scans. Hostname resolution
            # can change between validation and execution; do not infer IP authorization.
            if name=="nmap_scan":
                try:
                    address=ipaddress.ip_address(value)
                except ValueError as exc:
                    raise PolicyError("Active scans require an explicitly scoped numeric IP.") from exc
                if address.version!=4:
                    raise PolicyError("IPv6 Nmap scans require a separate reviewed invocation and are currently disabled.")
            if args.get("additional_args","")!="":
                raise PolicyError("Free-form command arguments are disabled.")
            result={"target":value,"additional_args":""}
            if name=="nmap_scan":
                if args.get("scan_type","-sT")!="-sT":
                    raise PolicyError("Only the reviewed TCP connect scan (-sT) is enabled.")
                ports=args.get("ports","")
                if not isinstance(ports,str) or len(ports)>128:
                    raise PolicyError("Invalid port selection.")
                if ports:
                    for group in ports.split(","):
                        if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?",group):
                            raise PolicyError("Ports must be numbers or ascending ranges.")
                        nums=[int(n) for n in group.split("-")]
                        if not all(1<=n<=65535 for n in nums) or nums[0]>nums[-1]:
                            raise PolicyError("Ports must be within 1..65535 and ascending.")
                result.update(scan_type="-sT",ports=ports)
        if name not in DIAGNOSTICS and not approve({"tool":name,"arguments":result}):
            raise PolicyError("Operator declined this operation.")
        return result

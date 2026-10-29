"""Deterministic operator commands and assessment clarification, independent of models."""
import ipaddress
import json
import re
from redvector_ollama_policy import PolicyError, target as canonical_target
from redvector_ollama_setup import plain,SetupError
from redvector_ollama_help import COMMANDS, render_help, unknown_message

def show_scope(policy,term):
    values=policy.snapshot()
    lines=["Status: "+("Active" if values else "Inactive"),"Authorized targets:"]
    lines += ["  "+value for value in values] or ["  none"]
    for name,addresses in policy.dns_snapshot().items():
        lines.append("Pinned destinations for "+name+": "+", ".join(addresses))
    lines+=["Source: "+("Operator command" if policy.revision>1 or values else "Default"),
            "Scope is session-local. Network scope does not automatically scan every host."]
    term.box("REDVECTOR AUTHORIZED TARGET SCOPE",lines)

async def handle_command(text,agent,wizard):
    text=text.strip()
    if not text:return "handled"
    if not text.startswith("/"):return None
    parts=text.split(None,1);command=parts[0];argument=parts[1] if len(parts)>1 else ""
    term=wizard.term
    if command not in COMMANDS:
        term.message("error",unknown_message(command))
        return "handled"
    route=COMMANDS[command].route
    if route=="exit":
        if not argument:return "exit"
        term.message("error","Usage: "+command)
    elif route=="artifact":
        try:
            if argument=="--clear":await agent.clear_artifact();term.message("success","Artifact selection cleared.")
            elif argument:
                path=argument
                if len(path)>1 and path[0]==path[-1] and path[0] in ("'",'"'):path=path[1:-1]
                selected=await agent.select_artifact(path)
                term.message("success","Read-only artifact snapshot selected by the operator.")
            value=getattr(agent,"artifact",None)
            term.box("AUTHORIZED ARTIFACT SNAPSHOT",["Status: "+("Active" if value else "Inactive")]+
                (["File: "+plain(value["name"]),"Bytes: "+str(value["size"]),"SHA256: "+value["sha256"],"Only this immutable snapshot is authorized; select again after local edits."] if value else ["Use /artifact PATH to select a regular file."]))
        except (OSError,ValueError,SetupError) as exc:term.message("error","Artifact selection failed. "+plain(exc))
    elif route=="scope":
        if argument:
            values=[] if argument=="--clear" else argument.split()
            try:
                agent.policy.replace_scope(values)
                agent.history=[]
                term.message("success","Authorized scope replaced by the operator.")
                if any("/" in value and value not in agent.policy.snapshot() for value in values):
                    term.message("warning","CIDR host bits were normalized; review the canonical network shown below.")
            except PolicyError as exc:
                term.message("error","Invalid authorized target scope. "+plain(exc))
                return "handled"
        show_scope(agent.policy,term)
    elif route=="saved":
        from redvector_ollama_presentation import render_result
        try:
            words=argument.split()
            if command=="/results" and words==["list"]:
                ids=agent.results.ids()
                term.write("\n".join(ids) if ids else "No saved tool results.")
                return "handled"
            if len(words)>(2 if command=="/summary" else 1):raise ValueError("Invalid command arguments.")
            ident=words[0] if words and words[0]!="latest" else None
            if command=="/summary":
                page=int(words[1]) if len(words)==2 and words[1].isdecimal() else 1 if len(words)<2 else 0
                if page<1:raise ValueError("Invalid page.")
                # This calls evidence-only inference, never Agent.turn or execute.
                term.message("info",await agent.summarize_saved(ident,page))
            elif command=="/results":
                record=agent.results.load(ident);render_result(term,record)
                if not record.get("persisted"):term.message("warning","Evidence currently available in-session only.")
            elif command=="/raw":
                record=agent.results.load(ident)
                term.write(plain(json.dumps(record["wire"],ensure_ascii=True)))
            else:term.message("success","Exported private evidence: "+str(agent.results.export(ident)))
        except (ValueError,OSError,KeyError,TypeError):
            term.message("error","That saved-result request could not be completed. Ask to show your saved results, or analyze a valid result. No network scan was executed.")
    elif route=="status":
        if argument:term.message("error","Usage: /status")
        else:
            result=await agent.execute("server_health",{},{ "server_health"})
            if not getattr(agent,"terminal",None):
                from redvector_ollama_views import normalize
                render_result_local=__import__("redvector_ollama_presentation").render_result
                render_result_local(term,{"id":"diagnostic","findings":normalize("server_health",None,{},result,0)})
    elif route=="tools":
        if not argument:term.message("info","Usage: /tools QUERY")
        else:
            if hasattr(agent,"refresh_profiles"):await agent.refresh_profiles()
            matches=agent.select(argument)
            from redvector_ollama_presentation import render_tools
            render_tools(term,matches)
    elif route=="help":render_help(term,argument)
    return "handled"

def _looks_like_target(token):
    """True only for tokens shaped like a network destination: an IP literal, a CIDR, a
    bracketed IPv6 address, or a dotted hostname. Plain English words, bare port numbers and
    port ranges (e.g. 'of', '65535', '1-65535', '80,443') return False and are never read as
    hosts. This is the generic guard against false out-of-scope rejections; it hardcodes no
    target and defers actual authorization to the policy."""
    if not token:
        return False
    if "/" in token:
        try:
            ipaddress.ip_network(token,strict=False);return True
        except ValueError:
            return False
    host=token[1:-1] if token.startswith("[") and token.endswith("]") else token
    try:
        ipaddress.ip_address(host);return True
    except ValueError:
        pass
    # Dotted hostname grammar; the final label must start with a letter so numeric strings and
    # port ranges (all-numeric labels) are not mistaken for hosts.
    return bool("." in host and re.fullmatch(
        r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{0,61}",host))

# Closed grammatical classes (articles, determiners, prepositions, conjunctions, pronouns,
# quantifiers, polite/auxiliary verbs) plus the small, stable port-scan domain vocabulary.
# This is deliberately NOT an open-ended stopword list: the named-host check only ever inspects
# the token IMMEDIATELY after a scan verb, so adjectives, adverbs and other verbs elsewhere in
# the sentence are never mistaken for destinations and need not be enumerated.
_FUNCTION=frozenset("""a an the this that these those my our your his her their its it them they we us you i
of on in to at for from with without within via by over across against into onto upon about
and or but nor so then than as if when while
all any both each every some few more most no not none only just exactly precisely once twice also now up down out
please can could would will shall should may might must do does did let want wants like help""".split())
_DOMAIN=frozenset("""scan scans scanned scanning rescan nmap nmap_scan nmap_advanced_scan run runs running execute executes perform performs
port ports portrange service services version versions tcp udp protocol protocols intensity banner banners
target targets host hosts hostname hostnames machine machines box boxes system systems server servers
node nodes device devices network networks subnet subnets endpoint endpoints asset assets range ranges
number numbers ip address addresses""".split())

def _named_unknown_host(view,scope_lower):
    """Return hosts explicitly NAMED as the scan operand. Only the token immediately following a
    scan verb is considered, so ordinary words elsewhere in the sentence never trigger a false
    rejection. In-scope, destination-shaped, numeric and closed-class function/domain tokens are
    excluded; whatever remains is a named host whose authorization is decided by the policy. No
    target, network or hostname is hardcoded."""
    named=[]
    for match in re.finditer(r"(?i)\b(?:scan|rescan|nmap(?:_scan|_advanced_scan)?)\b\s+([A-Za-z0-9_][A-Za-z0-9_.\-]*)",view):
        token=match.group(1).rstrip(".?,;:")
        low=token.lower()
        if not low or low in scope_lower or low in _FUNCTION or low in _DOMAIN:continue
        if re.fullmatch(r"[0-9]+(?:[-,][0-9]+)*",low):continue  # port number / range / list
        if _looks_like_target(token):continue                   # shaped -> handled by the shape pass
        named.append(token)
    return named

def assessment_context(text,policy,allow_versions=False):
    """Return (is_assessment, chosen_target, clarification), without model calls."""
    text=text.strip()
    view=re.sub(r"(?i)^(?:(?:please|can you|could you|would you|will you|help me(?: to)?|i want you to|i would like you to)\s+)+","",text)
    knowledge=bool(re.match(r"(?i)^(?:what|why|how|explain|describe|compare|tell me about|is|does)\b",view))
    # An explicit prohibition is not an assessment request. Remove only its
    # directly negated scan verb for intent detection; retain the original text
    # for conservative destination validation whenever a positive scan remains.
    intent_view=re.sub(r"(?i)\b(?:do\s+not|don't|never)\s+(?:(?:run|use|execute|perform)\s+)?(?:(?:a|any|the)\s+)?(?:network\s+)?(?:scan|nmap(?:_[A-Za-z0-9_]+)?)\b"," ",view)
    intent=not knowledge and bool(re.search(r"(?i)\bscan\b|\bnmap(?:_[A-Za-z0-9_]+)?\b|\b(?:identify|find|check)\b.*\b(?:ports?|services?)\b",intent_view))
    if not intent:return False,None,None
    if re.fullmatch(r"(?i)(?:please\s+)?scan(?:\s+(?:my|the|our|this|a|an))?[.!?]*",view):
        return True,None,"Please specify what you want to scan.\nExample: Scan my authorized target for open TCP ports and running services.\nNo MCP operation was executed."
    scope=policy.snapshot()
    if not scope:
        return True,None,"No target has been authorized yet. Tell me which system you own or have permission to assess. No scan was executed."
    scope_lower={entry.lower() for entry in scope}
    # Single pass over the request: only destination-SHAPED tokens (IP/CIDR/bracketed IPv6/
    # dotted host) or tokens already in scope are considered targets. Ordinary words, bare port
    # numbers and port ranges are ignored, so they cannot trigger a false out-of-scope block.
    # A destination-shaped token that is genuinely out of scope is still rejected; scope is
    # never silently expanded.
    explicit=[]
    for raw in re.findall(r"[A-Za-z0-9:\[][A-Za-z0-9_.:/%\[\]\-]*",text):
        token=raw.rstrip(".?,;")
        if token.startswith("[") and token.endswith("]"):token=token[1:-1]
        if token.lower() in scope_lower:
            explicit.append(authorized_operand(token,policy));continue
        if "://" in token or "%" in token:
            return True,None,"Use a plain authorized host, without URLs or zone identifiers. No scan was executed."
        if not _looks_like_target(token):continue
        try:
            explicit.append(authorized_operand(token,policy))
        except (PolicyError,ValueError):
            return True,None,"The requested target is outside the operator-authorized scope. Tell me which system you own or have permission to assess, or name an already-authorized host. No scan was executed."
    # A host NAMED directly as the scan operand must be authorized even when it is a single
    # label; function/domain words in that position are ignored, so only a real named host here
    # can be rejected.
    for operand in _named_unknown_host(view,scope_lower):
        try:
            explicit.append(authorized_operand(operand,policy))
        except (PolicyError,ValueError):
            return True,None,"The requested target is outside the operator-authorized scope. Tell me which system you own or have permission to assess, or name an already-authorized host. No scan was executed."
    choices=list(dict.fromkeys(explicit))
    if len(choices)>1:return True,None,"Multiple targets were requested. Select one authorized host for this operation. No scan was executed."
    if not choices:
        if len(scope)!=1:return True,None,"Multiple targets are authorized. Specify the intended target in your request. No scan was executed."
        choices=list(scope)
    chosen=choices[0]
    if "/" in chosen:
        return True,None,"Specify one authorized host inside the network scope. A network scope does not automatically launch a subnet scan. No scan was executed."
    if requests_active_versions(text) and not allow_versions:
        return True,chosen,("Target is authorized. Execution policy restriction: active service-version detection (-sV) "
                            "and scripts are disabled in this MCP client. Port-name service labels do not verify versions. "
                            "Request open TCP ports and service labels only. No scan was executed.")
    return True,chosen,None

def operator_view(text):
    return re.sub(r"(?i)^(?:(?:please|can you|could you|would you|will you|help me(?: to)?|i want you to|i would like you to)\s+)+","",text.strip())

def saved_analysis_request(text):
    view=operator_view(text)
    return bool(re.match(r"(?i)^(?:summari[sz]e|(?:analy[sz]e|explain|review)\s+(?:my\s+|the\s+)?(?:saved|last|previous)|retry\s+(?:the\s+)?summary)\b",view))

def automatic_context(text,target):
    view=operator_view(text)
    if re.search(r"(?i)\b(?:not|never|don't|without|logs?|files?|code|memory)\b",view):return False
    if not re.match(r"(?i)^(?:scan|nmap(?:_scan)?|(?:run|execute)\s+nmap(?:_scan)?|(?:identify|find|check)\b.*\b(?:ports?|services?))\b",view):return False
    return bool(re.search(r"(?i)\b(?:ports?|services?|tcp|network|nmap_scan)\b",view) or
                re.search(r"(?<![A-Za-z0-9.:])"+re.escape(target or "")+r"(?![A-Za-z0-9.:])",view))

def authorized_operand(value,policy):
    """Use the same canonicalization/membership authority as MCP enforcement."""
    if "/" in value:
        network=ipaddress.ip_network(value,strict=False)
        for entry in policy.snapshot():
            if "/" not in entry:continue
            allowed=ipaddress.ip_network(entry)
            if network.version==allowed.version and network.subnet_of(allowed):return str(network)
        raise PolicyError("Network is outside the operator-authorized scope.")
    canonical=canonical_target(value)
    if not policy.contains(canonical):raise PolicyError("Target is outside the operator-authorized scope.")
    return canonical

def requests_active_versions(text):
    text=re.sub(r"(?i)\b(?:without|no)\s+(?:active\s+)?-sV\b"," ",text)
    text=re.sub(r"(?i)\b(?:do\s+not|don't|never)\s+(?:use|run|enable)\s+(?:active\s+)?-sV\b"," ",text)
    view=re.sub(r"(?i)\b(?:without|no)\s+(?:active\s+)?(?:service[- ]?)?versions?(?:\s+detection)?\b"," ",text)
    view=re.sub(r"(?i)\b(?:do\s+not|don't|never)\s+(?:detect|identify|check|probe|use|run)\s+(?:active\s+)?(?:service[- ]?)?versions?(?:\s+detection)?\b"," ",view)
    return bool(re.search(r"(?i)\bversions?\b|(?<!\S)-sV\b",view))

def requests_full_range(text):
    """True when the operator asks to cover the ENTIRE TCP port space (all 65535 ports / full
    range) rather than a bounded list. Reads intent only; no target or port list is hardcoded.
    Negated phrasing ('do not scan all ports') does not qualify."""
    view=re.sub(r"(?i)\b(?:do\s+not|don't|never|without|no)\s+(?:scan(?:ning)?\s+)?(?:the\s+)?(?:all|every|entire|full|whole|complete)\b"," ",text)
    return bool(re.search(
        r"(?i)(?:\b(?:all|every|entire|full|whole|complete)\s+(?:the\s+)?(?:single\s+)?(?:tcp\s+|udp\s+)?ports?\b"
        r"|\b(?:full|entire|whole|complete)(?:[- ](?:tcp|udp))?(?:[- ]port)?[- ]range\b"
        r"|\b(?:full|entire|whole|complete)\s+range\s+of\s+(?:tcp\s+|udp\s+)?ports?\b"
        r"|\ball\s+65535\b|\b65535\s+(?:tcp\s+|udp\s+)?ports?\b"
        r"|\b(?:0|1)\s*-\s*65535\b)",view))

def requests_service_identification(text):
    """True when the operator asks to identify/determine running services or versions (the
    second stage of a combined discovery+service workflow). No target is hardcoded."""
    if requests_active_versions(text):return True
    view=re.sub(r"(?i)\b(?:do\s+not|don't|never|without)\s+(?:also\s+)?(?:try\s+to\s+)?(?:identify|determine|detect|enumerate|fingerprint|find|discover|check)\b"," ",text)
    return bool(re.search(r"(?i)\b(?:identify|determine|detect|enumerate|fingerprint|discover|check|find)\b[^.?!]*\bservices?\b",view))

def requests_combined_discovery_service(text):
    """Area 9: a single request asking for FULL-RANGE discovery AND service/version
    identification together -> run the staged workflow (full discovery, then service-ID on the
    discovered open ports), never a truncated single 128-port version scan. A discovery-only or a
    bounded version request never qualifies, so neither is reclassified."""
    return requests_full_range(text) and requests_service_identification(text)

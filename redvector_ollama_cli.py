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
            term.message("error","Saved-result command failed. Use /results list, a valid result ID and positive page number. No network scan was executed.")
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

_STOPWORDS=frozenset("""a an the this that these those my our your his her their its it them they we you
scan scans scanned scanning nmap nmap_scan nmap_advanced_scan run runs running execute executes executing perform performs performing
do does did please can could would will shall want wants wanted like help let me i
identify identifies find finds check checks enumerate enumerates discover discovers probe probes detect detects map list show get
summarize summarise summarized analyze analyse analyzes report reports result results output outputs call calls then next
of on in into to at by for from with without within via using use over across against and or but as
all any both each more most some few only just exactly precisely once twice then also now new current up down live
open closed filtered tcp udp port ports service services version versions intensity banner banners actual real
host hosts hostname hostnames target targets authorized authorised unauthorized destination destinations machine machines box boxes
system systems node nodes device devices server servers endpoint endpoints asset assets lab labs environment
network networks subnet subnets cidr range ranges full complete comprehensive quick fast deep basic thorough standard default
number numbers entire whole every please""".split())

def _named_operands(view):
    """Yield host labels in scan-operand position (immediately after a scan verb or a target
    preposition), skipping English function/scan words and numeric/port tokens. This lets a
    genuinely named but unauthorized host (e.g. 'intranet') be rejected while ordinary words
    (e.g. 'of' in 'port scan of HOST') are never treated as destinations. No target is hardcoded."""
    operands=[]
    for anchor in re.finditer(r"(?i)\b(?:scan|nmap(?:_scan)?|on|against|at|target|host|hostname|named|called)\b",view):
        for raw in re.findall(r"[A-Za-z0-9_.:/%\[\]\-]+",view[anchor.end():]):
            token=raw.strip("[]").rstrip(".?,;")
            low=token.lower()
            if not token or low in _STOPWORDS:continue
            if re.fullmatch(r"[0-9]+(?:[-,][0-9]+)*",low):continue  # port number / range / list
            operands.append(token);break  # first content token after the verb is the operand
    return operands

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
        return True,None,"No authorized target is configured.\n\nUse /scope TARGET to configure an authorized target.\nNo scan was executed."
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
            return True,None,"The requested target is outside the operator-authorized scope. Use /scope TARGET or select an explicitly authorized host. No scan was executed."
    # A host NAMED as the scan operand (after a scan verb or target preposition) must be
    # authorized even when it is a single label; ordinary function words are skipped above.
    for operand in _named_operands(view):
        low=operand.lower()
        if low in scope_lower or _looks_like_target(operand):continue  # in scope or already validated by shape
        try:
            explicit.append(authorized_operand(operand,policy))
        except (PolicyError,ValueError):
            return True,None,"The requested target is outside the operator-authorized scope. Use /scope TARGET or select an explicitly authorized host. No scan was executed."
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

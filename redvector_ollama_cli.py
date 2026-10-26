"""Deterministic operator commands and assessment clarification, independent of models."""
import ipaddress
import json
import re
from redvector_ollama_policy import PolicyError
from redvector_ollama_setup import plain

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
    if command in ("/back","/exit"):
        if not argument:return "exit"
        term.message("error","Usage: "+command)
    elif command=="/scope":
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
    elif command=="/status":
        if argument:term.message("error","Usage: /status")
        else:term.write(plain(json.dumps(await agent.execute("server_health",{},{ "server_health"}))))
    elif command=="/tools":
        if not argument:term.message("info","Usage: /tools QUERY")
        else:
            matches=agent.select(argument)
            term.write(plain(json.dumps(matches,indent=2)) if matches else "No registered tools match this query.")
    elif command=="/help":
        term.box("OPERATOR COMMANDS",["/scope: display current scope","/scope TARGET [TARGET...]: replace scope",
            "/scope --clear: remove all targets","/tools QUERY: registered tools and execution policy",
            "/status: real read-only health call","/back or /exit: leave the session"])
    else:term.message("error","Unknown command. Use /help for operator commands; nothing was sent to Ollama.")
    return "handled"

def assessment_context(text,policy):
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
    relative={"my","our","the","a","an","this","authorized","target","targets","host","hosts","network","subnet","for","open","tcp","ports","port","services","and","on","against","all","current"}
    operand_patterns=(r"(?i)\b(?:scan|nmap(?:_scan)?)(?:\s+(?:on|against))?\s+([A-Za-z0-9_.:/%\-]+)",
                      r"(?i)\b(?:on|against|at|called|named|hostname|host|target)\s+([A-Za-z0-9_.:/%\-]+)")
    for pattern in operand_patterns:
        matches=list(re.finditer(pattern,view))
        if pattern==operand_patterns[0]:matches=matches[:1]
        for match in matches:
            operand=match.group(1)
            value=operand.rstrip(".?").lower()
            if match.group(0).lower().startswith("nmap") and value in {"exactly","once","only","then","with","using"}:continue
            if value in relative or value in scope:continue
            try:address=ipaddress.ip_address(value)
            except ValueError:
                return True,None,"The requested host is not in the authorized scope. Use /scope TARGET or select an explicitly authorized host. No scan was executed."
            if not policy.contains(str(address)):
                return True,None,"The requested target is outside the operator-authorized scope. No scan was executed."
    explicit=[]
    for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9_.:/%\-]*",text):
        token=token.rstrip(".")
        if token.lower() in scope:explicit.append(token.lower());continue
        if "://" in token or "%" in token:
            return True,None,"Use a plain authorized host, without URLs or zone identifiers. No scan was executed."
        try:address=ipaddress.ip_address(token)
        except ValueError:
            if "." in token or "/" in token:
                return True,None,"The requested hostname or network is not a selected authorized host. Use /scope and select one host. No scan was executed."
            continue
        if not policy.contains(str(address)):
            return True,None,"The requested target is outside the operator-authorized scope. No scan was executed."
        explicit.append(str(address))
    choices=list(dict.fromkeys(explicit))
    if len(choices)>1:return True,None,"Multiple targets were requested. Select one authorized host for this operation. No scan was executed."
    if not choices:
        if len(scope)!=1:return True,None,"Multiple targets are authorized. Specify the intended target in your request. No scan was executed."
        choices=list(scope)
    chosen=choices[0]
    if "/" in chosen:
        return True,None,"Specify one authorized host inside the network scope. A network scope does not automatically launch a subnet scan. No scan was executed."
    return True,chosen,None

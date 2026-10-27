"""Bind offline MCP formatters to real saved evidence, never model-invented findings."""
import json
from redvector_ollama_results import payloads

OFFLINE_TOOLS=frozenset({"create_vulnerability_report","create_scan_summary","format_tool_output_visual"})

def source_record(store):
    candidates=[]
    for ident in store.ids():
        record=store.load(ident)
        if record.get("tool") in OFFLINE_TOOLS:continue
        if record.get("mcp",{}).get("source")!="mcp":continue
        if record.get("findings",{}).get("status") not in ("COMPLETED","PARTIAL"):continue
        candidates.append(record)
    if not candidates:raise ValueError("No verified saved MCP evidence is available.")
    return max(candidates,key=lambda item:item.get("created",""))

def report_arguments(store,name):
    record=source_record(store)
    vulnerabilities=[]
    for payload in payloads(record["mcp"]):
        for key in ("vulnerabilities","findings","issues"):
            values=payload.get(key)
            if isinstance(values,list):
                for finding in values:
                    if not isinstance(finding,dict):continue
                    item={field:value for field,value in finding.items() if field in
                          {"title","name","description","severity","id","cve","cwe","cvss","cvss_version",
                           "port","service","evidence","confidence","validation","remediation","references"}}
                    if item not in vulnerabilities:vulnerabilities.append(item)
    if len(vulnerabilities)>100:raise ValueError("Use private export for more than 100 source findings.")
    # Reports from port discovery explicitly contain no inferred vulnerabilities.
    target=record.get("target") or ""
    summary={"target":target,"vulnerabilities":vulnerabilities,"tools_used":[record["tool"]],
             "execution_time":record["findings"].get("duration",0),
             "limitations":"Source evidence only; no new assessment or inferred vulnerabilities."}
    if name=="create_vulnerability_report":
        result={"vulnerabilities":json.dumps(vulnerabilities,ensure_ascii=True),"target":target,"scan_type":record["tool"]}
    elif name=="create_scan_summary":
        result={"target":target,"tools_used":record["tool"],"vulnerabilities_found":len(vulnerabilities),
                "execution_time":summary["execution_time"],
                "findings":json.dumps({"source_findings":vulnerabilities,"limitations":summary["limitations"]},ensure_ascii=True)}
    elif name=="format_tool_output_visual":
        result={"tool_name":record["tool"],"output":json.dumps(record["findings"],ensure_ascii=True),
                "success":record["findings"]["status"]=="COMPLETED"}
    else:raise ValueError("Unknown offline formatter.")
    if len(json.dumps(result).encode())>32000:raise ValueError("Saved reporting payload exceeds the bounded formatter limit; use /export.")
    # ANSI/control escapes cannot be promoted to active terminal instructions.
    from redvector_ollama_setup import plain
    result={key:plain(value) if isinstance(value,str) else value for key,value in result.items()}
    return result

def report_complete(name,data,arguments):
    values=payloads(data)
    if not values:return False
    payload=values[0]
    if name=="create_vulnerability_report":
        return (isinstance(payload.get("summary_report"),str) and bool(payload["summary_report"]) and
                isinstance(payload.get("vulnerability_cards"),list) and
                len(payload["vulnerability_cards"])==len(json.loads(arguments["vulnerabilities"])))
    field="summary_report" if name=="create_scan_summary" else "formatted_output"
    return not data.get("isError") and payload.get("success") is True and isinstance(payload.get(field),str) and bool(payload[field])

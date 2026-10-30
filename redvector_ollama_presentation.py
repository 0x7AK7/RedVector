"""Width-aware factual scan presentation; raw evidence stays separate."""
import shutil
import re
import textwrap
from redvector_ollama_setup import plain

def _text(value):
    # plain() already strips control/ANSI and keeps printable Unicode (an em dash stays "—", never a
    # literal "—"); re-escaping to ASCII is what leaked those sequences into the terminal.
    return plain(value)

def render_scan(term,value,ident,width=None):
    width=max(12,width if width is not None else shutil.get_terminal_size((80,24)).columns)
    def line(text="",kind=None):
        for part in _text(text).splitlines() or [""]:
            for wrapped in textwrap.wrap(part,width=width,replace_whitespace=True,drop_whitespace=True) or [""]:
                if kind=="port":
                    if term.color:
                        wrapped=re.sub(r"\bOPEN\b",lambda match:"\033[92m"+match.group(0)+"\033[0m",wrapped)
                        wrapped=re.sub(r"\b(?:unknown|Not verified)\b",lambda match:"\033[33m"+match.group(0)+"\033[0m",wrapped)
                    term.write(wrapped)
                elif kind:term.message(kind,wrapped)
                else:term.write(wrapped)
    border="+"+"-"*(width-2)+"+"
    line(border);line("REDVECTOR AI / NETWORK SCAN RESULTS");line(border)
    line("Target: "+str(value["target"]));line("Tool: "+str(value.get("tool","nmap_scan")))
    line("Scan type: "+str(value.get("scan_type","Not supplied")))
    line("Host status: "+value.get("host_status","Not verified"))
    line("Protocols: "+(", ".join(sorted({r["protocol"].upper() for r in value["ports"]})) or "Not reported"))
    status=value["status"]
    line("Scan status: "+status,"success" if status=="COMPLETED" else "error" if status=="FAILED" else "warning")
    line("Duration: "+format(value["duration"],".2f")+" s ("+value["duration_source"]+")")
    line("Open ports: "+str(value["open_count"]));line(border)
    if width>=64:
        service_width=max(12,(width-32)//2)
        line("PORT       STATE          "+"SERVICE".ljust(service_width)+" VERSION")
        for row in value["ports"]:
            service=textwrap.wrap(_text(row["service"]),width=service_width) or [""]
            version=textwrap.wrap(_text(row["version"]),width=max(10,width-27-service_width)) or [""]
            for n in range(max(len(service),len(version))):
                prefix=(str(row["port"])+"/"+row["protocol"]).ljust(11)+row["state"].upper().ljust(15) if n==0 else " "*26
                text=prefix+(service[n] if n<len(service) else "").ljust(service_width)+" "+(version[n] if n<len(version) else "")
                line(text.rstrip(),"port" if row["state"]=="open" else "warning")
    else:
        for row in value["ports"]:
            line(str(row["port"])+"/"+row["protocol"]+" "+row["state"].upper(),"success" if row["state"]=="open" else "warning")
            line("Service: "+row["service"],"warning" if row["service"]=="unknown" else None)
            line("Version: "+row["version"],"warning" if row["version"]=="Not verified" else None)
            line("-"*(width-2))
    line(border)
    line("Total open ports: "+str(value["open_count"]))
    line("Closed ports: "+(str(value["closed_count"]) if value["closed_count"] is not None else "Unknown"),"warning" if value["closed_count"] is None else None)
    line("Filtered ports: "+(str(value.get("filtered_count")) if value.get("filtered_count") is not None else "Unknown"))
    line("Scan errors: "+value["errors"],"error" if value["errors"]!="None reported" else None)
    for warning in value["warnings"]:line("Warning: "+warning,"warning")
    line("Service labels alone do not verify product versions or vulnerabilities.","warning")
    line("Evidence ID: "+ident)

def operation_message(term,lines):
    width=max(12,shutil.get_terminal_size((80,24)).columns)
    for value in lines:
        for line in textwrap.wrap(_text(value),width=width) or [""]:term.message("info",line)


from redvector_ollama_panels import Panel, status_kind

def render_result(term,record,width=None):
    value=record["findings"]
    authorization=record.get("authorization")
    if isinstance(authorization,dict):
        panel=Panel(term,width);panel.section("OPERATOR AUTHORIZATION AT EXECUTION")
        panel.fields([("Scope",", ".join(authorization.get("scope",[])) or "No network targets"),
                      ("Approval",authorization.get("approval","Not recorded"))])
        panel.line("Saved context is evidence, not authorization for another operation.","warning")
    if value.get("kind")!="generic":
        Panel(term,width).section("VERIFIED TOOL RESULTS")
        return render_scan(term,value,record["id"],width)
    from redvector_ollama_results import payloads
    values=payloads(record.get("mcp") or {})
    payload=values[0] if values and isinstance(values[0],dict) else {}
    if value.get("tool")=="ai_vulnerability_assessment" and payload:
        # The staged assessment always renders as the professional report — never a key dump.
        from redvector_report import build_report,render_report
        render_report(term,build_report(payload),width)
        Panel(term,width).line("Evidence ID: "+record["id"],"meta")
        return
    panel=Panel(term,width)
    panel.section("VERIFIED TOOL RESULTS / "+value["category"].upper())
    panel.fields([("Source",value.get("source","Not supplied")),("Tool",value["tool"]),("Target",value.get("target") or "Not supplied (diagnostic or source-specific)"),
                  ("Execution status",value["status"]),("Elapsed",format(value["duration"],".2f")+" s")])
    panel.line("Status: "+value["status"],status_kind(value["status"]))
    panel.line("Tool completion describes execution, not compromise or elevated access.","warning")
    if value["finding_count"]:
        panel.section("SOURCE-REPORTED FINDINGS")
        if value["status"]=="UNKNOWN":panel.line("Counts describe primary source fields only. Review alternate evidence and warnings before conclusions.","warning")
        panel.fields(value["severity"].items())
        panel.line("Source-confirmed validation: "+str(value["confirmed"]))
        panel.line("Other findings remain potential, informational or unverified as reported.","warning")
    panel.section("SOURCE EVIDENCE")
    # Compact by default: top-level facts only and a findings table — never the flattened key dump.
    # The complete, unmodified payload remains in storage and is shown only on explicit request.
    top=[(key,text) for key,text in value["fields"] if key.count(".")==1 and "[" not in key][:20]
    panel.fields(top)
    rows=payload.get("findings") if isinstance(payload.get("findings"),list) else []
    rows=[row for row in rows if isinstance(row,dict)]
    if not rows:
        # records without the raw payload attached: rebuild the findings table from normalized facts
        found={}
        for key,text in value["fields"]:
            match=re.search(r"\.findings\[(\d+)\]\.(title|severity)$",key)
            if match:found.setdefault(int(match.group(1)),{})[match.group(2)]=text
        rows=[found[i] for i in sorted(found)]
    if rows:
        panel.grid(["SEVERITY","FINDING"],[[str(row.get("severity","-")),str(row.get("title") or row.get("id") or row.get("message") or "-")] for row in rows])
    hidden=len(value["fields"])-len(top)
    if hidden>0:panel.line(str(hidden)+" further structured fields are stored; ask for the raw JSON payload to see them.","meta")
    if not value["fields"]:panel.line("No structured facts or text were returned.","warning")
    if value["errors"]!="None reported":panel.line(value["errors"],"error")
    for warning in value["warnings"]:panel.line(warning,"warning")
    panel.section("EVIDENCE AND REPORTING",["Evidence ID: "+record["id"],
                  "Ask to show the original evidence, or to export the report as JSON, for this evidence ID."])
    panel.line("AI SECURITY ANALYSIS: Unavailable until separately requested or verified.","warning")

def render_tools(term,matches,width=None):
    from redvector_ollama_views import category
    panel=Panel(term,width);panel.section("REGISTERED MCP TOOLS / EXECUTION ELIGIBILITY")
    for item in matches:
        panel.fields([("Tool",item["name"]),("Workflow",category(item["name"])),
                      ("Status",item.get("status",item["execution"])),("Details",item.get("detail","")),("Description",item.get("description",""))])
    if not matches:panel.line("No registered tools match this query.","warning")

def approval_panel(term,operation):
    # Compact: what will run, where, and why approval is needed — never a flattened argument dump.
    panel=Panel(term);panel.section("OPERATOR AUTHORIZATION REQUIRED",kind="warning")
    args=operation.get("arguments") if isinstance(operation.get("arguments"),dict) else {}
    rows=[("Operation",str(operation.get("tool","Unknown")))]
    target=operation.get("target") or args.get("target") or args.get("url")
    if target:rows.append(("Target",str(target)))
    if args.get("ports"):rows.append(("Ports",str(args["ports"])))
    if operation.get("provider"):rows.append(("Provider",str(operation["provider"])))
    panel.fields(rows)
    if operation.get("reason"):panel.line(str(operation["reason"]),"warning")
    panel.line("Enter APPROVE to authorize this exact operation. Enter DENY to cancel.","warning")

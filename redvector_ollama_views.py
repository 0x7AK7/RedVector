"""Read-only source adapters. Category labels never authorize execution."""
import json
import math
from redvector_ollama_results import payloads

# Ordered display families. Unknown registrations always retain a generic adapter.
FAMILIES = (
    ("Exploit Selection", ("exploit_select","searchsploit","metasploit_module_search","llm_suggest_exploits")),
    ("Privilege Escalation", ("privesc","linpeas","winpeas","exploit_suggester","gtfobins","lolbas","sudo_","suid_")),
    ("Pivoting", ("chisel","ligolo","proxychains","ssh_tunnel")),
    ("Lateral Movement", ("lateral","impacket_psexec","impacket_wmiexec","impacket_smbexec","evil_winrm","netexec_execute")),
    ("Post-Exploitation", ("post_exploit","persistence","secretsdump","mimikatz","exfil","lazagne")),
    ("Exploit Execution", ("metasploit_run","pwntools_exploit","web_vuln_chain_exploit","rce_","exploit_engine")),
    ("Session Management", ("session","active_processes","process_status","process_dashboard","terminate_process","pause_process","resume_process")),
    ("Digital Forensics", ("volatility","foremost","steghide","exiftool","forensic","binwalk","hash_evidence")),
    ("Wireless Security", ("wireless","wifi","aircrack")),
    ("Cloud Security", ("cloud","prowler","trivy","scout_suite","pacu","kube","docker_bench","clair","falco","checkov","terrascan")),
    ("API Security", ("api_","graphql","jwt_","arjun","paramspider","x8_parameter")),
    ("Authentication Security", ("hydra","hashcat","john_crack","kerbrute","auth_","credential")),
    ("CVE and Advisory Analysis", ("cve","threat_intelligence","vulnerability_intelligence","zeroday")),
    ("Vulnerability Assessment", ("nuclei","vulnerability","vuln_","jaeles")),
    ("Configuration and Exposure", ("config_audit","misconfiguration","checksec","config_")),
    ("Web Security", ("nikto","sqlmap","wpscan","gobuster","dirb","ffuf","feroxbuster","xsser","wfuzz","dirsearch","katana","dalfox","httpx","burp","zap_","wafw00f","commix","nosqlmap","owasp","http_","web_")),
    ("Network Protocol Security", ("testssl","smbmap","enum4linux","rpcclient","nbtscan","tshark","tcpdump")),
    ("OSINT", ("shodan","sherlock","theharvester","whois","osint","wayback","gau_discovery")),
    ("Reconnaissance and Asset Discovery", ("recon","amass","subfinder","fierce","dnsenum","dnsrecon","arp_scan")),
    ("Network Scanning", ("nmap","rustscan","masscan","scan")),
    ("AI Model Compatibility", ("llm_","model_","ollama")),
    ("Reporting and Export", ("report","export","summary")),
    ("MCP Diagnostics", ("server_health","cache","telemetry","error_handling","system_metrics","dashboard")),
)

def category(tool):
    name=str(tool).lower()
    return next((title for title,keys in FAMILIES if any(key in name for key in keys)),"Tool Results")

def flatten(value,path="result"):
    """Preserve every JSON leaf; no speculative semantic or privilege inference."""
    stack=[(path,value,0)];rows=[]
    while stack:
        key,item,depth=stack.pop()
        if depth>64:
            rows.append((key,"Nested data beyond display depth; use /raw."));continue
        if isinstance(item,dict) and item:
            stack.extend((key+"."+str(k),v,depth+1) for k,v in reversed(list(item.items())))
        elif isinstance(item,list) and item:
            stack.extend((key+"["+str(i)+"]",v,depth+1) for i,v in reversed(list(enumerate(item))))
        else:
            rendered=item if isinstance(item,str) else json.dumps(item,ensure_ascii=True)
            rows.append((key,rendered))
    return rows

def normalize(tool,target,arguments,data,elapsed):
    values=payloads(data)
    # Structured data is primary; duplicate JSON blocks are not printed twice.
    source={}
    unique=[]
    warnings=[];conflict=False
    for other in values:
        if other in unique:continue
        unique.append(other)
        for key in source.keys() & other.keys():
            if source[key]!=other[key]:conflict=True
        for key,value in other.items():
            if key not in source:source[key]=value
    state=str(source.get("execution_status",source.get("status",""))).strip().upper().replace("_"," ")
    code=source.get("return_code",source.get("returncode"))
    failed=bool(data.get("isError") or source.get("error") or source.get("success") is False or
                (type(code) is int and code!=0))
    states={"HEALTHY":"COMPLETED","SUCCESS":"COMPLETED","SUCCEEDED":"COMPLETED","COMPLETE":"COMPLETED",
            "COMPLETED":"COMPLETED","FAILED":"FAILED","ERROR":"FAILED","UNSUPPORTED":"UNSUPPORTED",
            "UNAVAILABLE":"UNAVAILABLE","NOT STARTED":"NOT STARTED","QUEUED":"QUEUED",
            "AWAITING AUTHORIZATION":"AWAITING AUTHORIZATION","PENDING APPROVAL":"PENDING APPROVAL",
            "RUNNING":"RUNNING","BLOCKED":"BLOCKED","CANCELLED":"CANCELLED","PARTIAL":"PARTIAL"}
    supplied_states=[states.get(str(source[key]).strip().upper().replace("_"," "))
                     for key in ("execution_status","status") if key in source]
    supplied_states=[item for item in supplied_states if item is not None]
    supplied_codes=[source[key] for key in ("return_code","returncode") if type(source.get(key)) is int]
    code_outcomes={code==0 for code in supplied_codes}
    if len(set(supplied_states))>1 or len(code_outcomes)>1:conflict=True
    completed="COMPLETED" in supplied_states
    if source.get("success") is True and "FAILED" in supplied_states:conflict=True
    if source.get("success") is False and completed:conflict=True
    if completed and False in code_outcomes:conflict=True
    if data.get("execution_status") in ("unknown","cancelled"):status="UNKNOWN"
    elif conflict:status="UNKNOWN";warnings.append("Conflicting MCP fields; inspect original evidence.")
    elif state in ("UNSUPPORTED","UNAVAILABLE","BLOCKED","CANCELLED"):status=state
    elif source.get("partial_results") is True or source.get("timed_out") is True:status="PARTIAL"
    elif failed:status="FAILED"
    elif state in states:status=states[state]
    elif source.get("success") is True or type(code) is int and code==0:status="COMPLETED"
    else:status="UNKNOWN"
    fields=flatten(source) if values else []
    for index,other in enumerate(unique):
        alternatives={key:value for key,value in other.items() if key in source and source[key]!=value}
        if alternatives:fields.extend(flatten(alternatives,"alternative["+str(index)+"]"))
    if "error" in data:fields.append(("execution.error",str(data["error"])))
    content=data.get("content",[])
    if not isinstance(content,list):
        warnings.append("Malformed MCP content retained in original evidence.")
        status="UNKNOWN";content=[]
    # Preserve plain/non-JSON text blocks as source evidence; omit exact JSON duplicates.
    for index,block in enumerate(content):
        if not isinstance(block,dict):continue
        text=block.get("text")
        if not isinstance(text,str):continue
        try:parsed=json.loads(text)
        except (ValueError,TypeError):parsed=None
        if isinstance(parsed,dict):continue
        if isinstance(parsed,list):fields.extend(flatten(parsed,"content["+str(index)+"]"))
        else:fields.append(("content["+str(index)+"]",text))
    counts={key:0 for key in ("Critical","High","Medium","Low","Informational","Unknown")}
    confirmed=0;finding_count=0
    stack=[source]
    while stack:
        item=stack.pop()
        if isinstance(item,dict):
            for key,value in item.items():
                if key.lower() in ("findings","vulnerabilities","issues","matches") and isinstance(value,list):
                    for finding in value:
                        if not isinstance(finding,dict):continue
                        finding_count+=1
                        severity=finding.get("severity")
                        if severity is None and isinstance(finding.get("info"),dict):severity=finding["info"].get("severity")
                        label=str(severity).title()
                        if label=="Info":label="Informational"
                        counts[label if label in counts else "Unknown"]+=1
                        validation=finding.get("validation_state",finding.get("validation"))
                        if isinstance(validation,str) and validation.lower()=="confirmed":confirmed+=1
                else:stack.append(value)
        elif isinstance(item,list):stack.extend(item)
    duration=source.get("execution_time",elapsed)
    if type(duration) not in (int,float) or not math.isfinite(duration) or duration<0:duration=elapsed
    return {"kind":"generic","source":data.get("source","Not supplied"),"category":category(tool),"tool":tool,"target":target,
            "status":status,"duration":duration,"fields":fields,"severity":counts,
            "finding_count":finding_count,"confirmed":confirmed,"warnings":warnings,
            "errors":"Tool reported a failure; inspect source evidence." if failed else "None reported"}

def evidence_page(value,page=1,budget=1800):
    if type(page) is not int or page<1 or budget<512:raise ValueError("Invalid analysis page.")
    def encoded(rows):
        return len(json.dumps({"status":value["status"],"fields":rows,
                              "page":999999999,"pages":999999999},ensure_ascii=True).encode())
    pages=[];current=[]
    # Split both paths and values by serialized ASCII-JSON size. Field IDs refer
    # to immutable source row/segment positions, never shortened source paths.
    for index,(key,text) in enumerate(value["fields"]):
        remaining=str(key)+": "+str(text);segment=0
        while remaining:
            size=min(len(remaining),160)
            ident=str(index+1)+"."+str(segment+1)
            while size and encoded([[ident,remaining[:size]]])>budget:size-=1
            if size==0:raise ValueError("Analysis budget too small.")
            row=[ident,remaining[:size]]
            if current and encoded(current+[row])>budget:
                pages.append(current);current=[]
            current.append(row);remaining=remaining[size:];segment+=1
    if current or not pages:pages.append(current)
    if page>len(pages):raise ValueError("Analysis page does not exist.")
    result={"status":value["status"],"fields":pages[page-1],"page":page,"pages":len(pages)}
    if len(json.dumps(result,ensure_ascii=True).encode())>budget:raise ValueError("Analysis budget exceeded.")
    return result

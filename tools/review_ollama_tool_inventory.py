"""Reproducible registration and bounded AST inventory. Never executes tool bodies."""
import argparse,ast,asyncio,hashlib,json,re,subprocess,sys
from collections import Counter,defaultdict
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
def loc(n,file="redvector_server.py"): return file+":"+str(n.lineno)
def adapter_group(row):
 name=row["name"];category=row["category"]
 if name in {"nmap_scan","nmap_advanced_scan","masscan_high_speed","rustscan_fast_scan"}:return "bounded-tcp-scanners"
 if name in {"http_framework_test","http_repeater","nuclei_scan","httpx_probe","nikto_scan","wafw00f_scan","jaeles_vulnerability_scan"}:return "confined-http-assessment"
 if name in {"create_scan_summary","create_vulnerability_report","format_tool_output_visual","llm_analyze_scan","llm_write_report","llm_chat","display_system_metrics","get_live_dashboard"}:return "saved-evidence-analysis-and-presentation"
 if category=="MCP Diagnostics":return "authenticated-runtime-diagnostics"
 if category=="Session Management":return "owned-process-management"
 if category in {"Exploit Execution","Lateral Movement","Post-Exploitation","Privilege Escalation","Pivoting","Authentication Security"} or any(x in name for x in ("exploit","payload","_rce","_exfil","_persist","_bypass","_spray","_bruteforce")):return "high-impact-authorized-workflows"
 if category in {"OSINT","CVE and Advisory Analysis"}:return "third-party-enrichment"
 if any(k in row["input_schema"].get("properties",{}) for k in ("binary","binary_path","file_path","memory_file","input_file")):return "bounded-local-artifact-analysis"
 if name.endswith(("_list","_policies","_dimensions","_providers","_manufacturers","_protocols","_strategies","_actions","_surfaces","_vectors","_techniques")):return "reference-catalogs-review-purity"
 if name in {"create_file","delete_file","modify_file","list_files","execute_command","execute_python_script","install_python_package"}:return "operator-workspace-execution"
 return "staged-assessment-orchestration"

def main(probe):
 import redvector_mcp
 import redvector_ollama_policy as policy
 from redvector_ollama_views import category
 tools=asyncio.run(redvector_mcp.setup_mcp_server(object()).list_tools())
 mt=ast.parse((ROOT/"redvector_mcp.py").read_text(encoding="utf-8-sig"))
 bt=ast.parse((ROOT/"redvector_server.py").read_text(encoding="utf-8-sig"))
 setup=next(n for n in mt.body if isinstance(n,ast.FunctionDef) and n.name=="setup_mcp_server")
 wrappers={n.name:n for n in setup.body if isinstance(n,ast.FunctionDef)}
 funcs=defaultdict(list);routes=defaultdict(list)
 for n in ast.walk(bt):
  if isinstance(n,ast.FunctionDef):
   funcs[n.name].append(n)
   for d in n.decorator_list:
    if isinstance(d,ast.Call) and isinstance(d.func,ast.Attribute) and d.func.attr=="route" and d.args and isinstance(d.args[0],ast.Constant):
     routes[d.args[0].value].append(n)
 ledger_path=ROOT/"docs/ollama-reviewed-validation.json"
 ledger=json.loads(ledger_path.read_text(encoding="utf-8")) if ledger_path.exists() else {}
 verified_sources=ledger.get("source_sha256",{})
 ledger_current=bool(verified_sources) and all((ROOT/name).is_file() and hashlib.sha256((ROOT/name).read_bytes().replace(b"\r\n",b"\n")).hexdigest()==digest for name,digest in verified_sources.items())
 rows=[]
 for tool in sorted(tools,key=lambda t:t.name):
  w=wrappers[tool.name];endpoints=[]
  client=next(n for n in mt.body if isinstance(n,ast.ClassDef) and n.name=="RedVectorClient")
  methods={n.name:n for n in client.body if isinstance(n,ast.FunctionDef)}
  extra=[methods[c.func.attr] for c in ast.walk(w) if isinstance(c,ast.Call) and isinstance(c.func,ast.Attribute) and isinstance(c.func.value,ast.Name) and c.func.value.id=="redvector_client" and c.func.attr in methods and c.func.attr not in ("safe_get","safe_post")]
  for c in (c for n in [w]+extra for c in ast.walk(n)):
   if isinstance(c,ast.Call) and isinstance(c.func,ast.Attribute) and c.func.attr in ("safe_get","safe_post") and c.args:
    a=c.args[0]
    route="/"+a.value.lstrip("/") if isinstance(a,ast.Constant) and isinstance(a.value,str) else ast.unparse(a)
    endpoints.append(dict(path=route,method=c.func.attr[5:].upper(),evidence=loc(c,"redvector_mcp.py")))
  roots=[n for e in endpoints for n in routes.get(e["path"],[])]
  pending=[(n,0) for n in roots];seen={}
  while pending:
   n,depth=pending.pop();key=(n.name,n.lineno)
   if key in seen: continue
   seen[key]=n
   if depth<3:
    for c in ast.walk(n):
     if isinstance(c,ast.Call):
      name=c.func.id if isinstance(c.func,ast.Name) else c.func.attr if isinstance(c.func,ast.Attribute) else ""
      pending.extend((f,depth+1) for f in funcs.get(name,[]))
  calls={};commands={}
  for n in seen.values():
   for c in ast.walk(n):
    if isinstance(c,ast.Call):
     name=ast.unparse(c.func)
     if any(k in name for k in ("requests.","session.request","session.get","session.post","socket.","urlopen","subprocess.","execute_command","Popen","os.system")):
      calls[(name,c.lineno)]=dict(call=name,evidence=loc(c))
    if isinstance(c,ast.Assign) and any(isinstance(t,ast.Name) and t.id in ("command","cmd","base_command") for t in c.targets):
     v=c.value
     prefix=v.value if isinstance(v,ast.Constant) and isinstance(v.value,str) else v.values[0].value if isinstance(v,ast.JoinedStr) and v.values and isinstance(v.values[0],ast.Constant) else ""
     match=re.match(r"^([a-zA-Z][a-zA-Z0-9_.+-]*)(?:\s|$)",prefix)
     if match: commands[(match[1],c.lineno)]=dict(executable=match[1],evidence=loc(c))
  props=tool.inputSchema.get("properties",{})
  dangerous=[p for p in props if any(k in p.lower() for k in ("password","credential","payload","script","command","shell","exploit","additional_args"))]
  dest=[p for p in props if any(k in p.lower() for k in ("target","url","domain","host","proxy","callback","lhost","ip"))]
  family=category(tool.name);reviewed=tool.name in policy.REVIEWED;diag=tool.name in policy.DIAGNOSTICS
  risk="low" if diag else "moderate" if tool.name=="clear_cache" else "high" if dangerous or any(k in family for k in ("Exploit","Movement","Authentication","Pivoting")) else "restricted-unknown"
  safeguards=[]
  if dest: safeguards.append("Validate/pin all destinations, redirects, referrals and callbacks; enforce authorized scope at every connection.")
  if dangerous: safeguards.append("Replace free-form command/payload/credential inputs with reviewed constrained adapters; protect secrets and require explicit approval.")
  if commands: safeguards.append("Review command/options; avoid shell interpolation; bound runtime, output, concurrency and retries.")
  if not reviewed: safeguards.append("Complete tool-specific transitive behavior review and execution policy before enabling.")
  if not roots: safeguards.append("Resolve dynamic or missing backend route mapping before enabling.")
  rows.append(dict(name=tool.name,category=family,category_source="redvector_ollama_views.category; Tool Results is generic fallback",registration_evidence=loc(w,"redvector_mcp.py"),input_schema=tool.inputSchema,
   backend=dict(routes=endpoints,handlers=[dict(name=n.name,evidence=loc(n)) for n in roots],availability="source handler registered; runtime health untested" if roots else "literal route unresolved; runtime untested"),
   dependencies=dict(command_candidates=sorted({x["executable"] for x in commands.values()}),command_evidence=list(commands.values()),completeness="Static command-prefix candidates only; Python packages, dynamic commands and transitive dependencies not exhaustive."),
   network_behavior=dict(backend_transport="HTTP to configured RedVectorClient backend" if endpoints else "No literal safe_get/safe_post route; indirect dispatch unresolved",destination_parameters=dest,source_observed_calls=list(calls.values()),assessment="Possible target/external network activity; confinement unproven." if dest or commands or calls else "No direct target-network evidence in bounded traversal; offline behavior unproven.",limitations="Name-based traversal depth 3 can over-approximate methods; misses dynamic dispatch, binary internals, plugins, templates, DNS and redirects."),
   risk=risk,sensitive_or_unconfined_parameters=dangerous,execution_policy=dict(reviewed_allowlist=reviewed,mode="diagnostic" if diag else "reviewed constrained policy; see policy source" if reviewed else "integration unfinished; not operational through this client yet",disabled_reason=getattr(policy,"DISABLED_REASONS",{}).get(tool.name)),
   feasibility="existing constrained policy, subject to runtime health/dependencies" if reviewed else "discoverable; requires tool-specific policy and dependency verification",missing_safeguards=safeguards,review_level="registration/schema plus bounded automated source evidence; not manual behavioral audit"))
 candidates=sorted({d for r in rows for d in r["dependencies"]["command_candidates"]});native={}
 if probe and candidates:
  script='for x in '+' '.join(candidates)+'; do if command -v "$x" >/dev/null 2>&1; then printf "%s present\\n" "$x"; else printf "%s absent\\n" "$x"; fi; done'
  result=subprocess.run(["wsl.exe","-d","kali-linux","--","sh"],input=script,capture_output=True,text=True,timeout=60)
  if result.returncode: raise RuntimeError("Kali read-only command probe failed; output not persisted")
  native=dict(line.split() for line in result.stdout.splitlines() if len(line.split())==2)
  if set(native)!=set(candidates): raise RuntimeError("Incomplete native presence output; refusing misleading report")
 for r in rows:
  r["dependencies"]["native_command_availability"]={d:native.get(d,"not checked") for d in r["dependencies"]["command_candidates"]}
  r["dependencies"]["native_availability_scope"]="Kali WSL PATH at generation; presence does not prove functionality"
  name=r["name"]
  reviewed=r["execution_policy"]["reviewed_allowlist"]
  r["implementation_status"]="Constrained adapter implemented; runtime verification required" if reviewed else "Incomplete client integration"
  r["actual_execution_test"]={"status":"Not executed in this audit","evidence":"Audit reads SDK metadata and source only; no runtime success inferred."}
  actual=ledger.get("tool_tests",{}).get(name)
  if actual and ledger_current:r["actual_execution_test"]=actual
  if name=="nmap_scan":
   r["implementation_status"]="Partial: TCP discovery and attested service-version profile; HTTP/SSH evidence only"

  r["authorization_requirements"]=(["Local read-only diagnostic; authenticated verified backend"] if name in policy.DIAGNOSTICS else ["Exact operator approval for backend cache mutation"] if name=="clear_cache" else ["Private saved real MCP evidence only; no new assessment"] if name in policy.OFFLINE_TOOLS else ["Explicit target scope; destination pinning", "Tool-specific reviewed execution profile", "Meaningful operator approval for high-impact effects"])
  issues=list(r["missing_safeguards"])
  if name=="nmap_scan":
   issues.append("Extend audited service probes beyond HTTP/SSH; implement and validate other intended Nmap modes separately. Current active profile is single-host TCP, 1..32 ports, intensity 0..2, no arbitrary NSE/UDP/OS detection.")

  if not reviewed:
   from redvector_ollama_availability import REASONS
   issues.insert(0,REASONS.get(name,"Implement a tool-specific argument adapter for "+name+" using its exact input_schema and mapped backend route; verify transitive destinations and recovery, then add a real authorized execution test."))
  if r["dependencies"]["command_candidates"]:
   absent=[d for d,v in r["dependencies"]["native_command_availability"].items() if v=="absent"]
   if absent:issues.append("Missing native PATH dependencies: "+", ".join(absent)+". Operator installation/configuration and a real workflow test remain required.")
  if not r["backend"]["handlers"]:issues.append("Resolve the recorded dynamic/missing route before implementing the adapter; verify request/response compatibility.")
  if name in {"http_framework_test","http_repeater","nuclei_scan","nmap_advanced_scan"}:
   r["implementation_status"]="Constrained shared backend profile implemented; real workflow evidence below"
   issues=["Broader registered arguments remain outside this reviewed profile; require separate bounded workflow adapters and real tests."]
   if name=="nuclei_scan":
    issues.append("Only passive root-response header checks implemented; arbitrary CVE templates, code/JS/headless/OAST and active payload checks require separate reviewed profiles. Reviewed Linux amd64 v3.11.1 is installed with tools/install_reviewed_nuclei.py; configure REDVECTOR_NUCLEI_BIN in the backend environment.")
   elif name=="nmap_advanced_scan":
    issues.append("Reviewed TCP -sV only; 1..128 explicit ports and SSH/HTTP/FTP/SMTP/POP3/IMAP/MySQL greeting evidence. NSE/UDP/OS/stealth flags require distinct profiles.")
   else:issues.append("Only one root GET/HEAD with pinned destination; custom headers, cookies, bodies, crawling and replay side effects are not implemented in this profile.")
  if name=="nmap_scan":
   r["implementation_status"]="Partial: TCP discovery and attested service-version profile; SSH/HTTP/FTP/SMTP/POP3/IMAP/MySQL greeting evidence, up to 128 explicit active ports"
   issues=[value.replace("beyond HTTP/SSH","beyond SSH/HTTP/FTP/SMTP/POP3/IMAP/MySQL greeting coverage").replace("1..32 ports","1..128 ports") for value in issues]
  if name in {"strings_extract","xxd_hexdump","objdump_analyze","checksec_analyze"}:
   engines={"strings_extract":"GNU strings","xxd_hexdump":"Python bounded byte formatter","objdump_analyze":"GNU objdump","checksec_analyze":"GNU readelf static security evidence"}
   r["implementation_status"]="Constrained operator-selected artifact profile implemented; current real-execution evidence below"
   r["authorization_requirements"]=["Explicit operator /artifact PATH selection; immutable SHA256 snapshot","No model-selected filesystem paths; no uploaded code execution","Native parsers in minimal readonly Bubblewrap filesystem/network namespace; hex uses actual selected bytes"]
   r["dependencies"]["reviewed_profile_runtime"]={"engine":engines[name],"required":["Python"] if name=="xxd_hexdump" else ["Linux user namespaces","Bubblewrap",engines[name],"ldd trusted shared-library inventory"]}
   issues=["Selected regular files only,1 byte..4MiB; private staging max16 snapshots/15-minute expiry.","Parser output <=512KiB, bounded time/CPU/memory and two concurrent jobs; output/time limits fail honestly.","Hex windows <=4096 bytes; strings minimum4..64; no arbitrary native arguments. Checksec reports readelf NX/RELRO/ELF type only; canaries/other protections not assessed.","Larger files, additional metadata/scanner engines and broader options require separately bounded adapters and real tests."]
  if name in {"list_active_processes","get_process_dashboard","get_live_dashboard","get_process_status","display_system_metrics"}:
   r["implementation_status"]="Shared sanitized runtime profile implemented; current named-MCP execution evidence below"
   r["authorization_requirements"]=["Authenticated independently verified local backend","Read-only existing backend ProcessManager registry; no job mutation","Specific PID requires prior actual discovery and matching recorded start time"]
   r["dependencies"]["reviewed_profile_runtime"]={"engine":"existing ProcessManager and psutil","required":["psutil","compatible reviewed backend runtime profile"]}
   issues=["At most256 registered backend records; partial flag if more.","Command arguments/output omitted; does not expose arbitrary OS processes.","Pause/resume/termination remain outside this reviewed read-only profile."]
  if name in {"monitor_cve_feeds","vulnerability_intelligence_dashboard"}:
   r["implementation_status"]="Fixed official NVD provider adapter implemented; current provider/named-MCP execution evidence below"
   r["authorization_requirements"]=["Exact operator approval for provider and publication window","Fixed NVD host, public-IP pinning and verified TLS; no redirects or environment proxies","Keyword/severity filters local; no target/artifact data sent; no inferred target applicability"]
   r["dependencies"]["reviewed_profile_runtime"]={"engine":"NVD CVE API2.0 and Python verified HTTPS","required":["public NVD API availability","working public DNS/TLS","compatible reviewed backend advisory profile"]}
   issues=["Anonymous NVD publication samples only,1..168 hours and <=100 records/2MiB.","Partial results explicit; sample statistics are not global threat trends or exploit availability.","Provider cooldown/cache and actual execution errors respected; other providers/CPE-target correlation require separate reviewed integrations."]
  if name in {"httpx_probe","nikto_scan","wafw00f_scan","jaeles_vulnerability_scan"}:
   kinds={"httpx_probe":"HTTP prober","nikto_scan":"web server misconfiguration scanner","wafw00f_scan":"WAF fingerprinter","jaeles_vulnerability_scan":"signature vulnerability scanner"}
   r["implementation_status"]="Confined passive HTTP-response assessment implemented; not full native "+kinds[name]+"; current named-MCP execution evidence below"
   r["authorization_requirements"]=["One explicit authorized root HTTP(S) URL; numeric destination pinning and verified TLS","Single confined GET; no redirects, proxies, credentials, bodies, cookies or crawling","Reviewed passive profile; the native "+kinds[name]+" binary is never executed"]
   r["dependencies"]["reviewed_profile_runtime"]={"engine":"RedVector reviewed passive root-response collector (Python stdlib http.client)","required":["reviewed HTTP read profile"]}
   issues=["Observations derive only from one bounded root response, not the full native "+kinds[name]+".","No active payloads, authentication, fuzzing, multi-path crawling or port lists.","Absence of a finding is not proof of safety; evidence is the actual observed root-response configuration only."]
  if name in {"masscan_high_speed","rustscan_fast_scan"}:
   native={"masscan_high_speed":"Masscan","rustscan_fast_scan":"RustScan"}
   r["implementation_status"]="Reviewed bounded TCP connect engine implemented; not native "+native[name]+"; current named-MCP execution evidence below"
   r["authorization_requirements"]=["One explicit in-scope target; numeric destination pinning","1..128 explicit TCP ports; unbounded full-range or high-speed scanning disabled","Shared RedVector Python TCP connect engine; native "+native[name]+" is never executed"]
   r["dependencies"]["reviewed_profile_runtime"]={"engine":"RedVector reviewed bounded TCP connect engine (Python stdlib sockets)","required":["reviewed TCP connect profile"]}
   issues=["At most 128 explicit ports, <=64 concurrent connections, 1s per-connect timeout and a 20s overall deadline.","TCP connect() discovery only: no raw sockets, UDP, OS detection, banners or internet-scale rates.","Engine labeled accurately as RedVector's bounded connect implementation; it is not "+native[name]+" and does not substitute another scanner while claiming native execution."]
  r["remaining_technical_issues"]=issues
  r["shared_adapter_group"]=adapter_group(r)
  if name=="nuclei_scan":
   r["dependencies"]["reviewed_profile_runtime"]="Pinned native Nuclei via REDVECTOR_NUCLEI_BIN or PATH; presence/actual execution evidenced separately. PATH candidates alone do not include configured binaries."


 assert len(rows)==len({r["name"] for r in rows})==328
 summary=dict(categories=dict(Counter(r["category"] for r in rows)),reviewed_allowlist_count=sum(r["execution_policy"]["reviewed_allowlist"] for r in rows),mapped_handler_count=sum(bool(r["backend"]["handlers"]) for r in rows),native_probe_enabled=probe,command_candidate_count=len(candidates))
 report=dict(inventory_version=3,tool_count=len(rows),method="Real SDK registration metadata; AST backend inspection; optional command -v only. No tool bodies, backend import/start/stop, scans or downloads.",limits=["Source route availability does not establish runtime availability.","Full execution coverage is unfinished. This automated source audit is not 328 manual behavioral reviews.","Schemas are exact SDK inputSchema including defaults; client policy accepts a stricter subset."],summary=summary,shared_adapter_groups=dict(Counter(r["shared_adapter_group"] for r in rows)),tools=rows)
 (ROOT/"docs").mkdir(exist_ok=True)
 (ROOT/"docs/ollama-tool-coverage.json").write_text(json.dumps(report,indent=2,ensure_ascii=True)+"\n",encoding="utf-8")
 lines=["# Ollama MCP execution coverage","","All 328 actual registrations are included. Full execution coverage is unfinished; an implemented adapter or executable on PATH does not prove a successful operation.","","Regenerate: python tools/review_ollama_tool_inventory.py --check-native","","Exact schemas, source locations, route mapping, dependency evidence, authorization requirements and concrete integration work are recorded per tool in ollama-tool-coverage.json. This generator executes no tool bodies. Actual-test status below therefore remains unverified until independent runtime evidence is recorded.","","Summary: "+json.dumps(summary,sort_keys=True),"","| Registered tool | Legacy / reviewed profile dependencies | Implementation status | Actual execution test | Authorization requirements | Remaining technical work |","|---|---|---|---|---|---|"]
 for r in rows:
  dependency_text=", ".join(r["dependencies"]["command_candidates"]) or "Not inferred; inspect mapped source"
  profile_runtime=r["dependencies"].get("reviewed_profile_runtime")
  if isinstance(profile_runtime,dict):dependency_text+="; reviewed profile: "+profile_runtime["engine"]
  cells=[r["name"],dependency_text,r["implementation_status"],r["actual_execution_test"]["status"]+": "+r["actual_execution_test"].get("evidence",""),"; ".join(r["authorization_requirements"]),"; ".join(r["remaining_technical_issues"]) or "Run real workflow regression and verify actual response."]
  lines.append("| "+" | ".join(value.replace("|","/").replace("\n"," ") for value in cells)+" |")
 groups=defaultdict(list)
 for row in rows:groups[row["shared_adapter_group"]].append(row["name"])
 lines+=["","## Shared adapter work groups","", "Groups organize implementation work; category membership does not authorize execution.",""]
 for group,names in sorted(groups.items()):
  members=[r for r in rows if r["name"] in names]
  verified=sum(r["actual_execution_test"]["status"].startswith("Passed real") for r in members)
  absent=sorted({name for r in members for name,state in r["dependencies"]["native_command_availability"].items() if state=="absent"})
  lines+=["### "+group+" ("+str(len(names))+")","",
          "Risk classifications: "+json.dumps(dict(Counter(r["risk"] for r in members)),sort_keys=True)+".",
          "Independently verified constrained tool workflows: "+str(verified)+".",
          "Missing PATH dependency candidates: "+(", ".join(absent) or "none inferred")+"; configured profile binaries are reported separately.",
          "",", ".join(names),""]
 (ROOT/"docs/ollama-tool-coverage.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
 print(json.dumps(summary,sort_keys=True))
if __name__=="__main__":
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("--check-native",action="store_true");main(p.parse_args().check_native)

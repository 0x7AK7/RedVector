"""Runtime-backed operational status; never an execution authorizer."""
REASONS={
 "nuclei_scan":"Missing integration: the MCP path forces recovery and accepts unrestricted templates. Requires isolated reviewed HTTP templates, disabled recovery and verified scanner execution.",
 "ai_vulnerability_assessment":"Missing integration: multi-tool smart-scan dispatcher needs per-stage destination/argument/approval enforcement.",
 "jaeles_vulnerability_scan":"Missing integration: signatures/config can execute unreviewed checks; requires immutable audited signatures and confined request budgets.",
 "clair_vulnerability_scan":"Missing integration: image/config/registry destinations and Clair service must be validated; not a web-scanning adapter.",
 "bugbounty_vulnerability_hunting":"Existing backend returns a workflow plan. Scenario execution and per-step authorization are not implemented by this client.",
 "vulnerability_intelligence_dashboard":"Missing integration: external NVD/third-party access and simulated research need provenance-controlled enrichment; not observed vulnerability evidence.",
 "whois_lookup":"Missing integration: registry/referral destinations require an explicitly authorized external-lookup policy.",
}
BINARIES={"nmap_scan":"nmap","nuclei_scan":"nuclei","jaeles_vulnerability_scan":"jaeles","clair_vulnerability_scan":"clairctl"}

def status(name,policy,runtime=None,verified=False,report_available=False):
    from redvector_ollama_policy import (DIAGNOSTICS,OFFLINE_TOOLS,ARTIFACT_TOOLS,RUNTIME_TOOLS,ADVISORY_TOOLS,
        HTTP_ASSESS_TOOLS,TCP_SCAN_TOOLS)
    runtime=runtime or {}
    dependency=BINARIES.get(name)
    binary_state=runtime.get("tools_status",{}).get(dependency) if verified else None
    if name in HTTP_ASSESS_TOOLS:
        # Reviewed PASSIVE HTTP adapter over the shared root-response collector; the native
        # scanner binary (nikto/jaeles/wafw00f/httpx) is never executed, so do not gate on it.
        native={"httpx_probe":"httpx","nikto_scan":"Nikto","wafw00f_scan":"Wafw00f","jaeles_vulnerability_scan":"Jaeles"}.get(name,name)
        capability=policy.profile_status.get("redvector-http-read-v1",{})
        if not verified:return "Restricted","Verified backend assessment capability required; refresh /tools."
        if capability.get("state")!="Ready":return capability.get("state","Restricted"),capability.get("detail","Reviewed assessment module required.")
        if not policy.snapshot():return "Restricted","Set /scope TARGET before a reviewed passive HTTP assessment."
        return "Ready","Reviewed passive HTTP-response assessment (one confined TLS-verified root GET); native "+native+" is NOT executed."
    if name in TCP_SCAN_TOOLS:
        native={"masscan_high_speed":"Masscan","rustscan_fast_scan":"RustScan"}.get(name,name)
        capability=policy.profile_status.get("redvector-tcp-connect-v1",{})
        if not verified:return "Restricted","Verified backend TCP-connect capability required; refresh /tools."
        if capability.get("state")!="Ready":return capability.get("state","Restricted"),capability.get("detail","Reviewed TCP connect profile required.")
        if not policy.snapshot():return "Restricted","Set /scope TARGET before bounded TCP discovery."
        return "Ready","Reviewed bounded TCP connect discovery (<=128 ports, capped concurrency/timeouts); native "+native+" is NOT executed."
    if name=="ai_vulnerability_assessment":
        discovery=policy.profile_status.get("tcp-discovery-v1",{})
        if not verified:return "Restricted","Verified backend required for this staged assessment integration; refresh /tools."
        if not policy.snapshot():return "Restricted","Set /scope TARGET before this staged assessment integration."
        if discovery.get("state")!="Ready":return discovery.get("state","Restricted"),discovery.get("detail","Reviewed discovery profile required for the staged assessment integration.")
        return "Requires Approval","Staged reviewed assessment integration (discovery -> service-version -> passive HTTP/Nuclei -> NVD) producing an evidence-ranked report; one operator approval."
    if name in ADVISORY_TOOLS:
        capability=policy.profile_status.get("nvd-advisory-v1",{})
        if not verified:return "Restricted","Verified advisory backend required."
        if capability.get("state")!="Ready":return capability.get("state","Restricted"),capability.get("detail","Updated advisory profile required.")
        return "Requires Approval","Anonymous fixed NVD public-provider request; bounded sample; keyword filtering local; no target applicability inferred."
    if name in RUNTIME_TOOLS:
        capability=policy.profile_status.get("runtime-read-v1",{})
        if not verified:return "Restricted","Verified runtime backend required."
        if capability.get("state")!="Ready":return capability.get("state","Restricted"),capability.get("detail","Updated runtime profile required.")
        if name=="get_process_status" and not policy.observed_processes:return "Restricted","Discover registered jobs with list_active_processes first."
        return "Ready","Read-only sanitized backend records and actual measurements."
    if name in ARTIFACT_TOOLS:
        capability=policy.profile_status.get("artifact-read-v1:"+name,{})
        if not verified:return "Restricted","Verified artifact backend required."
        if capability.get("state")!="Ready":return capability.get("state","Restricted"),capability.get("detail","Updated artifact profile required.")
        if policy.artifact_provider is None or not policy.artifact_provider():return "Restricted","Select an authorized file with /artifact PATH."
        return "Ready",capability.get("detail","Read-only selected artifact")
    if name in ("http_framework_test","http_repeater","nuclei_scan"):
        key="--redvector-profile=http-headers-v1" if name=="nuclei_scan" else "redvector-http-read-v1"
        capability=policy.profile_status.get(key,{})
        if not verified:return "Restricted","Verified backend assessment capability required; refresh /tools."
        if capability.get("state")!="Ready":return capability.get("state","Restricted"),capability.get("detail","Reviewed assessment module required.")
        if not policy.snapshot():return "Restricted","Set /scope TARGET before a root-response assessment."
        return "Ready",capability.get("detail","Root-response assessment profile")
    if name=="nmap_advanced_scan":
        capability=policy.profile_status.get("service-version-v1",{})
        if verified and policy.snapshot() and capability.get("state")=="Ready":
            return "Requires Approval","Reviewed service-version profile; 1..128 ports; no arbitrary NSE/UDP/OS flags."
        return capability.get("state","Restricted") if capability.get("state")!="Ready" else "Restricted",capability.get("detail","Verified service-version capability and scope required.")
    if dependency and binary_state is False:
        return "Missing Dependency","Backend runtime did not find "+dependency+". Install/configure it in the backend environment; "+REASONS.get(name,"then recheck /tools "+name+".")
    if name in DIAGNOSTICS:
        return ("Ready","Read-only local backend diagnostic") if verified else ("Restricted","Connection verification required; use /status.")
    if name in OFFLINE_TOOLS:
        return ("Ready","Saved-evidence formatting only; no new scan") if report_available else ("Restricted","Saved MCP evidence is required; model-generated findings are not accepted.")
    if name=="clear_cache":return "Requires Approval","Clears backend state; exact operator approval required."
    if name=="nmap_scan":
        if not verified or binary_state is not True:return "Restricted","Native scanner availability unverified; use /status or /tools to refresh."
        if not policy.snapshot():return "Restricted","Set /scope TARGET before assessment."
        reasons=[]
        if not policy.auto_discovery:reasons.append("unattended discovery disabled")
        if policy.auto_count>=5:reasons.append("unattended session limit reached")
        if policy.clock()-policy.last_auto<30:reasons.append("unattended cooldown active")
        if reasons:return "Requires Approval","; ".join(reasons)
        profile=policy.profile_status.get("service-version-v1",{})
        return "Ready","Authorized TCP discovery up to 1,000 ports; version profile: "+str(profile.get("state","unavailable"))+". Larger scans and application probes require approval."
    return "Restricted",REASONS.get(name,"Missing client integration: "+name+" needs a constrained argument adapter, dependency verification and a real authorized workflow test; see the tool coverage matrix.")

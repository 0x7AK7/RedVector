"""Two actual fixed-provider MCP interfaces; no target/credential data transmitted."""
import asyncio,os,sys
import pytest
from redvector_ollama_agent import Agent,bridge
from redvector_ollama_policy import Policy
from redvector_ollama_results import ResultsStore,payloads
from ollama_profile_runtime import owned_backend

@pytest.mark.skipif(not sys.platform.startswith("linux") or os.environ.get("REDVECTOR_RUN_PUBLIC_ADVISORY")!="1",reason="Requires explicit native public-provider acceptance")
def test_real_public_advisory_mcp(tmp_path):
    with owned_backend(tmp_path):asyncio.run(run(tmp_path))

async def run(directory):
    print("ADVISORY PHASE: starting isolated MCP backend",flush=True)
    async with bridge() as (session,catalog):
        print("ADVISORY PHASE:328 tools initialized",flush=True)
        assert len(catalog)==328
        approvals=[]
        agent=Agent(None,"unused",session,catalog,Policy(),lambda operation:approvals.append(operation) or True,lambda _:None,results=ResultsStore(directory/"evidence"))
        for name,args in [("monitor_cve_feeds",{"hours":24,"severity_filter":"ALL","keywords":""}),("vulnerability_intelligence_dashboard",{})]:
            print("ADVISORY PHASE: invoking "+name,flush=True)
            result=await agent.execute(name,args,{name})
            print("ADVISORY PHASE: completed "+name+" isError="+str(result.get("isError")),flush=True)
            assert not result["isError"],(name,result,agent.policy.profile_status)
            value=payloads(result)[0]
            assert value["success"] and value["provider"]=="NVD" and len(value["provider_payload_sha256"])==64
            assert isinstance(value["provider_total_results"],int) and value["sampled_records"]<=100
            assert "vulnerabilities" not in value and "exploitability_analysis" not in value
            if name=="vulnerability_intelligence_dashboard":assert value["dashboard"]["scope"].startswith("This retrieved sample")
            for row in value["advisories"]:assert row["id"].startswith("CVE-") and row["applicability"]=="Not assessed"
        assert len(approvals)==2
        print("REAL TWO-ADVISORY MCP PASS: official NVD publication data and payload SHA; both named interfaces; actual bounded sample; local filters; exact approvals; no simulated threat actors/exploit trends;328 tools.")

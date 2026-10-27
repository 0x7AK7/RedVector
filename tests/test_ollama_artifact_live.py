"""Four actual MCP artifact paths using one harmless compiled fixture."""
import asyncio,hashlib,os,subprocess,sys
from pathlib import Path
import pytest
from redvector_ollama_agent import Agent,bridge
from redvector_ollama_policy import Policy
from redvector_ollama_results import ResultsStore,payloads
from ollama_profile_runtime import owned_backend

@pytest.mark.skipif(not sys.platform.startswith("linux") or os.environ.get("REDVECTOR_RUN_SMOKE")!="1",reason="Requires native Linux and explicit smoke mode")
def test_real_selected_artifact_mcp_workflows(tmp_path):
    source=tmp_path/"owned.c";binary=tmp_path/"owned"
    source.write_text('const char marker[]="REDVECTOR_OWNED_ARTIFACT_MARKER";int main(void){return marker[0]==0;}')
    subprocess.run(["gcc","-fPIE","-pie","-Wl,-z,relro,-z,now","-o",str(binary),str(source)],capture_output=True,check=True)
    before=hashlib.sha256(binary.read_bytes()).hexdigest()
    with owned_backend(tmp_path):
        asyncio.run(run(tmp_path,binary,before))
    assert hashlib.sha256(binary.read_bytes()).hexdigest()==before

async def run(directory,binary,digest):
    async with bridge() as (session,catalog):
        assert len(catalog)==328
        agent=Agent(None,"unused",session,catalog,Policy(),lambda _:False,lambda _:None,results=ResultsStore(directory/"evidence"))
        selected=await agent.select_artifact(str(binary));assert selected["sha256"]==digest
        for name,args in [("strings_extract",{"file_path":"selected"}),("xxd_hexdump",{"file_path":"selected","length":"64"}),("objdump_analyze",{"binary":"selected","disassemble":False}),("checksec_analyze",{"binary":"selected"})]:
            result=await agent.execute(name,args,{name})
            assert not result["isError"],(name,result,agent.policy.profile_status)
            value=payloads(result)[0]
            assert value["artifact_sha256"]==digest and value["success"]
            if name=="strings_extract":assert "REDVECTOR_OWNED_ARTIFACT_MARKER" in value["stdout"] and value["engine"]=="strings"
            if name=="xxd_hexdump":assert value["stdout"].startswith("00000000: 7f45 4c46") and value["engine"]=="python-bounded-hex"
            if name=="objdump_analyze":assert "file format elf" in value["stdout"] and value["engine"]=="objdump"
            if name=="checksec_analyze":assert value["facts"]["NX_stack"]=="Enabled" and value["facts"]["RELRO"]=="Full" and value["engine"]=="readelf"
        await agent.clear_artifact();assert agent.artifact is None
        refused=await agent.execute("strings_extract",{"file_path":"selected"},{"strings_extract"})
        assert refused["isError"]
        print("REAL FOUR-ARTIFACT MCP PASS:328 registrations; operator snapshot SHA matched; real strings/objdump/readelf and computed hex; four named interfaces; original file unchanged; cleared selection refused.")

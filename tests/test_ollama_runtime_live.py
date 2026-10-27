"""Five actual MCP runtime interfaces observing an owned harmless managed job."""
import asyncio,os,shlex,sys
from pathlib import Path
import pytest
from redvector_ollama_agent import Agent,bridge
from redvector_ollama_policy import Policy
from redvector_ollama_results import ResultsStore,payloads
from ollama_profile_runtime import owned_backend

@pytest.mark.skipif(not sys.platform.startswith("linux") or os.environ.get("REDVECTOR_RUN_SMOKE")!="1",reason="Requires native Linux and smoke mode")
def test_real_managed_job_runtime_mcp(tmp_path):
    fifo=tmp_path/"owned-fifo";os.mkfifo(fifo,0o600)
    with owned_backend(tmp_path) as env:asyncio.run(run(tmp_path,fifo,env))

async def run(directory,fifo,env):
    import requests
    def read_one_byte():
        client=requests.Session();client.trust_env=False
        try:return client.post("http://127.0.0.1:"+env["REDVECTOR_PORT"]+"/api/command",json={"command":"head -c 1 "+shlex.quote(str(fifo)),"use_cache":False},headers={"Authorization":"Bearer "+env["REDVECTOR_API_TOKEN"]},timeout=25).json()
        finally:client.close()
    async with bridge() as (session,catalog):
        assert len(catalog)==328
        agent=Agent(None,"unused",session,catalog,Policy(),lambda _:False,lambda _:None,results=ResultsStore(directory/"evidence"))
        await agent.refresh_profiles()
        task=asyncio.create_task(asyncio.to_thread(read_one_byte));pid=None
        try:
            for _ in range(30):
                result=await agent.execute("list_active_processes",{},{"list_active_processes"})
                assert not result["isError"],(result,agent.policy.profile_status)
                rows=payloads(result)[0]["processes"]
                match=next((row for row in rows if row["tool"]=="head"),None)
                if match:pid=match["pid"];break
                await asyncio.sleep(.1)
            assert pid is not None,"Owned real FIFO reader was not registered."
            for name in ["get_process_dashboard","get_live_dashboard","display_system_metrics"]:
                result=await agent.execute(name,{}, {name});assert not result["isError"],(name,result)
                value=payloads(result)[0]
                assert isinstance(value["metrics"]["memory_percent"],float)
                assert "command" not in str(value["processes"]) and "last_output" not in str(value["processes"])
            result=await agent.execute("get_process_status",{"pid":pid},{"get_process_status"})
            assert not result["isError"],result
            assert payloads(result)[0]["process"]["pid"]==pid
            denied=await agent.execute("get_process_status",{"pid":2147483647},{"get_process_status"})
            assert denied["isError"]
            print("REAL FIVE-RUNTIME MCP PASS: real managed FIFO reader discovered/queried; three read views and actual psutil metrics; command arguments/output excluded; unknown PID refused;328 tools.")
        finally:
            try:
                fd=os.open(fifo,os.O_WRONLY|os.O_NONBLOCK);os.write(fd,b"Z");os.close(fd)
            except OSError:pass
            result=await task
            assert result.get("success") and result.get("stdout")=="Z",result

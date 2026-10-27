"""Two reviewed bounded TCP discovery MCP interfaces against an owned loopback listener."""
import asyncio,os,socket,sys,threading
import pytest
from redvector_ollama_agent import Agent,bridge
from redvector_ollama_policy import Policy
from redvector_ollama_results import ResultsStore,payloads
from ollama_profile_runtime import owned_backend

@pytest.mark.skipif(not sys.platform.startswith("linux") or os.environ.get("REDVECTOR_RUN_SMOKE")!="1",reason="Requires native Linux and explicit smoke mode")
def test_real_tcp_discovery_mcp_workflows(tmp_path):
    srv=socket.socket();srv.bind(("127.0.0.1",0));srv.listen(16);srv.settimeout(0.5)
    open_port=srv.getsockname()[1]
    closed=socket.socket();closed.bind(("127.0.0.1",0));closed_port=closed.getsockname()[1];closed.close()
    stop=threading.Event()
    def serve():
        while not stop.is_set():
            try:conn,_=srv.accept();conn.close()
            except (socket.timeout,OSError):pass
    thread=threading.Thread(target=serve,daemon=True);thread.start()
    try:
        with owned_backend(tmp_path):asyncio.run(run(tmp_path,open_port,closed_port))
    finally:stop.set();srv.close();thread.join(timeout=2)

async def run(directory,open_port,closed_port):
    async with bridge() as (session,catalog):
        assert len(catalog)==328
        agent=Agent(None,"unused",session,catalog,Policy(["127.0.0.1"]),lambda _:True,lambda _:None,results=ResultsStore(directory/"evidence"))
        await agent.refresh_profiles()
        spec=str(open_port)+","+str(closed_port)
        for tool in ("masscan_high_speed","rustscan_fast_scan"):
            r=await agent.execute(tool,{"target":"127.0.0.1","ports":spec},{tool});assert not r["isError"],(tool,r)
            v=payloads(r)[0]
            assert v["success"] and v["requested_tool"]==tool and v["engine"]=="redvector-reviewed-tcp-connect"
            assert "native masscan/rustscan not executed" in v["scanner"]["mode"]
            states={row["port"]:row["state"] for row in v["results"]}
            assert states[open_port]=="open" and states[closed_port]=="closed"
        print("REAL TCP-DISCOVERY MCP PASS: masscan_high_speed/rustscan_fast_scan reviewed bounded connect engine; owned loopback open/closed classified; native scanners not executed; 328 tools.")

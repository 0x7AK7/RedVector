"""Native end-to-end: authorized scope -> NL request -> tcp-discovery-v1 Ready via real
attestation -> full-range 1-65535 discovery executed through the agent, not truncated to 128.
Uses a dynamically chosen loopback listener; no production target is hardcoded."""
import asyncio,os,socket,sys,threading
import pytest
from redvector_ollama_agent import Agent,bridge
from redvector_ollama_policy import Policy
from redvector_ollama_results import ResultsStore,payloads
from redvector_ollama_cli import assessment_context
from ollama_profile_runtime import owned_backend

@pytest.mark.skipif(not sys.platform.startswith("linux") or os.environ.get("REDVECTOR_RUN_SMOKE")!="1",
                    reason="Requires native Linux and REDVECTOR_RUN_SMOKE=1")
def test_fullrange_discovery_profile_ready_and_executed(tmp_path):
    srv=socket.socket();srv.bind(("127.0.0.1",0));srv.listen(16);srv.settimeout(0.5)
    open_port=str(srv.getsockname()[1]);stop=threading.Event()
    def serve():
        while not stop.is_set():
            try:conn,_=srv.accept();conn.close()
            except (socket.timeout,OSError):pass
    thread=threading.Thread(target=serve,daemon=True);thread.start()
    try:
        with owned_backend(tmp_path):asyncio.run(_run(tmp_path,open_port))
    finally:stop.set();srv.close();thread.join(timeout=2)

async def _run(directory,open_port):
    async with bridge() as (session,catalog):
        assert len(catalog)==328
        agent=Agent(None,"unused",session,catalog,Policy(["127.0.0.1"]),lambda op:True,lambda _:None,
                    results=ResultsStore(directory/"evidence"))
        await agent.refresh_profiles()
        # Item 3: Ready through the genuine backend attestation pipeline, never injected.
        state=agent.policy.profile_status.get("tcp-discovery-v1",{})
        assert state.get("state")=="Ready",agent.policy.profile_status
        # Item 2: the operator's natural-language request resolves to the scoped host with no
        # false out-of-scope rejection (port numbers and ordinary words are not destinations).
        ok,target,clar=assessment_context(
            "Scan all 65535 TCP ports on 127.0.0.1. Identify services on discovered open ports. Do not exploit anything.",
            agent.policy)
        assert ok and target=="127.0.0.1" and (clar is None or "outside" not in clar),(target,clar)
        # Item 4: full-range discovery executes through the agent and is NOT truncated to 128.
        agent.assessment_target=target
        result=await agent.execute("nmap_scan",{"target":target,"ports":"1-65535"},{"nmap_scan"})
        assert not result["isError"],result
        payload=payloads(result)[0]
        assert payload["profile"]=="tcp-discovery-v1" and payload.get("success"),payload
        assert payload["reviewed_profile"]["ports_count"]==65535
        states={entry["port"]:entry["state"] for entry in payload["parsed"]["ports"]}
        assert states.get(open_port)=="open",payload["parsed"]["state_counts"]
        print("REAL FULL WORKFLOW PASS: scope -> NL -> tcp-discovery-v1 Ready (attested) -> full-range 1-65535 executed, not truncated; owned open port found.")

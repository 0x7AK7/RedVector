"""Reviewed bounded TCP connect engine: real connect classification, marker gating, policy bounds."""
import socket,threading
import pytest
import redvector_reviewed_assessment as a

def _listener():
    srv=socket.socket();srv.bind(("127.0.0.1",0));srv.listen(16);srv.settimeout(0.5)
    stop=threading.Event()
    def serve():
        while not stop.is_set():
            try:conn,_=srv.accept();conn.close()
            except (socket.timeout,OSError):pass
    t=threading.Thread(target=serve,daemon=True);t.start()
    return srv,srv.getsockname()[1],stop,t

def _closed_port():
    s=socket.socket();s.bind(("127.0.0.1",0));port=s.getsockname()[1];s.close();return port

def test_marker_required():
    assert a.run_tcp_connect("masscan_high_speed",{"target":"127.0.0.1","ports":"80"})["success"] is False

def test_unknown_tool_and_unexpected_args_refused():
    assert a.run_tcp_connect("nope",{"additional_args":a.SCAN_MARKER})["success"] is False
    assert a.run_tcp_connect("rustscan_fast_scan",{"target":"127.0.0.1","ports":"80","evil":1,"additional_args":a.SCAN_MARKER})["success"] is False

def test_real_connect_classifies_open_and_closed():
    srv,open_port,stop,t=_listener();closed=_closed_port()
    try:
        out=a.run_tcp_connect("masscan_high_speed",{"target":"127.0.0.1","ports":str(open_port)+","+str(closed),"additional_args":a.SCAN_MARKER})
        assert out["success"] and out["engine"]=="redvector-reviewed-tcp-connect"
        assert "native masscan/rustscan not executed" in out["scanner"]["mode"]
        states={r["port"]:r["state"] for r in out["results"]}
        # A live listener must be detected open; a non-listening port must never be reported open
        # (refused->closed on Linux, often dropped->filtered on Windows: both are "not open").
        assert states[open_port]=="open" and states[closed] in ("closed","filtered")
        assert out["open_ports"]==[open_port] and out["ports_scanned"]==2
    finally:stop.set();srv.close();t.join(timeout=2)

def test_full_range_and_oversized_are_refused():
    assert a.run_tcp_connect("masscan_high_speed",{"target":"127.0.0.1","ports":"1-65535","additional_args":a.SCAN_MARKER})["success"] is False
    assert a.run_tcp_connect("rustscan_fast_scan",{"target":"127.0.0.1","ports":"1-200","additional_args":a.SCAN_MARKER})["success"] is False

def test_policy_pins_injects_marker_and_rejects_unbounded():
    from redvector_ollama_policy import Policy,PolicyError
    from redvector_reviewed_assessment import SCAN_PROFILE,SCAN_MARKER
    pol=Policy(["127.0.0.1"]);pol.profile_status={SCAN_PROFILE:{"state":"Ready"}}
    out=pol._prepare("masscan_high_speed",{"target":"127.0.0.1","ports":"22,80,443"})
    assert out=={"target":"127.0.0.1","ports":"22,80,443","additional_args":SCAN_MARKER}
    for bad in ({"target":"127.0.0.1","ports":"1-65535"},{"target":"127.0.0.1","ports":""},
                {"target":"127.0.0.1","ports":"1-200"},{"target":"10.0.0.1","ports":"80"},
                {"target":"127.0.0.1","ports":"80","additional_args":"-sS"}):
        with pytest.raises(PolicyError):pol._prepare("rustscan_fast_scan",bad)

def test_policy_requires_ready_capability():
    from redvector_ollama_policy import Policy,PolicyError
    pol=Policy(["127.0.0.1"]);pol.profile_status={}
    with pytest.raises(PolicyError):pol._prepare("masscan_high_speed",{"target":"127.0.0.1","ports":"80"})

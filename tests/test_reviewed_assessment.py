"""Confinement and real observations; scanner live test is separately gated."""
import json,socket,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from unittest.mock import patch
import pytest
import redvector_reviewed_assessment as a

@pytest.mark.parametrize("url",["file:///tmp/x","http://name.invalid/","http://127.0.0.1/?token=x","http://127.0.0.1/path","http://u:p@127.0.0.1/","http://224.0.0.1/"])
def test_invalid_or_unpinned_urls_refused(url):
    with pytest.raises(a.AssessmentError):a.validate_url(url)

def test_http_fetch_no_redirect_no_environment_proxy():
    seen=[];trap=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            seen.append(self.path);self.send_response(302);self.send_header("Location","http://127.0.0.1:1/");self.end_headers()
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        with patch.dict("os.environ",{"HTTP_PROXY":"http://127.0.0.1:1"}):
            result=a.fetch("http://127.0.0.1:"+str(server.server_port)+"/")
        assert result["status_code"]==302 and seen==["/"]
        assert result["redirect_followed"] is False
    finally:server.shutdown();server.server_close();thread.join()

def test_result_shape_is_factual_not_inferred():
    with patch.object(a,"fetch",return_value={"status_code":200,"headers":{"server":"Example/1"},"body":"","raw":"HTTP/1.0 200 OK\r\nServer: Example/1\r\n\r\n","redirect_followed":False}):
        data=a.run_http({"url":"http://127.0.0.1/","method":"GET","headers":{},"cookies":None,"data":None,"action":a.HTTP_PROFILE})
    assert data["success"] and data["result"]["status_code"]==200
    assert "vulnerabilities" not in data["result"]

def test_free_form_profiles_rejected_before_execution():
    for params in [{"url":"http://127.0.0.1/","action":a.HTTP_PROFILE,"method":"POST"},
                   {"url":"http://127.0.0.1/","action":a.HTTP_PROFILE,"headers":{"Authorization":"secret"}}]:
        assert not a.run_http(params)["success"]

def test_http_concurrency_exhaustion_fails_before_socket_creation():
    with patch.object(a._HTTP_SLOTS,"acquire",return_value=False),patch.object(a,"_fetch") as request:
        with pytest.raises(a.AssessmentError,match="concurrency"):a.fetch("http://127.0.0.1/")
        request.assert_not_called()

def test_nuclei_internal_authority_reaches_confined_collector():
    from types import SimpleNamespace
    with patch.object(a,"nuclei_binary",return_value=__import__("pathlib").Path("fixture")),patch.object(a,"fetch",return_value={"status_code":200,"headers":{"x-content-type-options":"nosniff","x-frame-options":"DENY"},"raw":"HTTP/1.0 200 OK\r\n\r\n"}) as request,patch.object(a,"_command",return_value=SimpleNamespace(returncode=0,stdout=b"",stderr=b"")):
        result=a.run_nuclei({"target":"https://192.0.2.15/","template":a.NUCLEI_PROFILE,"use_recovery":False,"additional_args":"--redvector-authority=lab.example"})
        assert result["success"],result
        request.assert_called_once_with("https://192.0.2.15/",headers={"Host":"lab.example"})

def test_nuclei_match_mismatch_is_failure_not_false_clean():
    from types import SimpleNamespace
    from pathlib import Path
    with patch.object(a,"nuclei_binary",return_value=Path("fixture")),patch.object(a,"fetch",return_value={"status_code":200,"headers":{},"raw":"HTTP/1.0 200 OK\r\n\r\n"}),patch.object(a,"_command",return_value=SimpleNamespace(returncode=0,stdout=b"",stderr=b"")):
        result=a.run_nuclei({"target":"http://127.0.0.1/","template":a.NUCLEI_PROFILE,"use_recovery":False})
    assert not result["success"] and "conflict" in result["error"]

def test_truncated_declared_http_body_is_not_reported_complete():
    from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
    import threading
    class H(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            self.send_response(200);self.send_header("Content-Length","1000");self.end_headers();self.wfile.write(b"owned")
    server=ThreadingHTTPServer(("127.0.0.1",0),H);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        with pytest.raises(a.AssessmentError,match="declared"):
            a.fetch("http://127.0.0.1:"+str(server.server_port)+"/")
    finally:server.shutdown();server.server_close();thread.join()

def test_deadline_closes_response_socket_after_connection_close_headers():
    from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
    import threading,time
    timer=threading.Timer
    class H(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            self.send_response(200);self.send_header("Connection","close");self.send_header("Content-Length","1000");self.end_headers()
            try:
                for _ in range(50):self.wfile.write(b"x");self.wfile.flush();time.sleep(.02)
            except (OSError,ConnectionError):pass
    server=ThreadingHTTPServer(("127.0.0.1",0),H);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        with patch.object(a.threading,"Timer",side_effect=lambda seconds,callback:timer(.05,callback)):
            with pytest.raises(a.AssessmentError,match="deadline"):
                a.fetch("http://127.0.0.1:"+str(server.server_port)+"/")
    finally:server.shutdown();server.server_close();thread.join()

import io
import json
from unittest.mock import patch
from redvector_ollama_setup import Terminal
from redvector_ollama_results import ResultsStore,findings
from redvector_ollama_presentation import render_result

def test_shared_boxes_respect_actual_width():
    stream=io.StringIO();term=Terminal(stream)
    with patch("shutil.get_terminal_size",return_value=__import__("os").terminal_size((24,20))):
        term.box("AUTHORIZATION SCOPE",["A very long line that must wrap safely for a narrow terminal"])
    assert all(len(line)<=24 for line in stream.getvalue().splitlines())

def test_scan_host_filtered_protocol_and_invocation_type(tmp_path):
    data={"isError":False,"structuredContent":{"success":True,"stdout":"Host is up.\nNot shown: 997 filtered tcp ports\n",
        "parsed":{"open_ports":[{"port":80,"protocol":"tcp","state":"open","service":"http"}]}}}
    record=ResultsStore(tmp_path/"evidence").save("nmap_scan","fixture",{"scan_type":"-sT"},data,data,1)
    assert record["findings"]["filtered_count"]==997
    assert record["findings"]["host_status"]=="Up (source reported)"
    stream=io.StringIO();render_result(Terminal(stream),record,100)
    assert "Scan type: -sT" in stream.getvalue()
    assert "Filtered ports: 997" in stream.getvalue()

def test_unfamiliar_tool_reports_completion_without_fabricated_security_fields():
    from redvector_ollama_views import normalize
    value=normalize("unknown",None,{},{"structuredContent":{"success":True,"custom_measurement":8}},0)
    stream=io.StringIO();render_result(Terminal(stream),{"findings":value,"id":"a"*32},80)
    output=stream.getvalue()
    assert "result.custom_measurement" in output
    assert "compromise or elevated access" in output
    assert "CVE-" not in output

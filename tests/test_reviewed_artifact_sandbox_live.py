"""Real OS boundary probes; these are not additional registered MCP tools."""
import hashlib,os,subprocess,sys,tempfile
from pathlib import Path
from unittest.mock import patch
import pytest
import redvector_reviewed_artifacts as a

pytestmark=pytest.mark.skipif(not sys.platform.startswith("linux") or os.environ.get("REDVECTOR_RUN_SMOKE")!="1",reason="Requires native artifact sandbox")

def test_selected_input_is_readonly_and_outside_files_hidden(tmp_path):
    selected=tmp_path/"input";selected.write_bytes(b"owned-selected")
    outside=tmp_path/"outside";outside.write_bytes(b"outside-private-sentinel")
    command,_=a.sandbox_command("strings_extract",selected,["-a",str(outside)])
    hidden=subprocess.run(command,capture_output=True,timeout=10)
    assert hidden.returncode!=0 and b"outside-private-sentinel" not in hidden.stdout
    with patch.dict(a.ENGINES,{"strings_extract":"sh"}):
        command,_=a.sandbox_command("strings_extract",selected,["-c","printf changed > /work/input"])
        changed=subprocess.run(command,capture_output=True,timeout=10)
    assert changed.returncode!=0 and selected.read_bytes()==b"owned-selected"

def test_parser_has_a_different_network_namespace(tmp_path):
    selected=tmp_path/"input";selected.write_bytes(b"owned")
    with patch.dict(a.ENGINES,{"strings_extract":"readlink"}):
        command,_=a.sandbox_command("strings_extract",selected,["/proc/self/ns/net"])
        result=subprocess.run(command,capture_output=True,text=True,timeout=10)
    assert result.returncode==0 and result.stdout.strip()!=os.readlink("/proc/self/ns/net")
    print("REAL ARTIFACT SANDBOX PASS: selected input readonly; outside host file inaccessible; network namespace differs.")

def test_excessive_parser_output_is_failure_not_success():
    data=b"A"*(600*1024)
    token=a.store().put("b"*32,data,hashlib.sha256(data).hexdigest())
    try:
        result=a.run_profile("strings_extract",{"file_path":token})
        assert not result["success"] and "output" in result["error"].lower()
    finally:a.store().remove(token)

from types import SimpleNamespace
import pytest
import redvector_reviewed_runtime as r

def test_snapshot_omits_arguments_outputs_and_process_objects():
    manager=SimpleNamespace(list_active_processes=lambda:{123:{"pid":123,"command":"tool --password secret","process":object(),"last_output":"secret","start_time":1.0,"status":"running","progress":.5,"bytes_processed":5}})
    result=r.snapshot(manager)
    assert result["success"] and result["processes"][0]["tool"]=="tool"
    assert "secret" not in str(result) and "command" not in result["processes"][0]
    assert all(isinstance(value,(float,int)) for value in result["metrics"].values())

def test_pid_is_only_a_managed_backend_record():
    manager=SimpleNamespace(list_active_processes=lambda:{})
    result=r.snapshot(manager,pid=123)
    assert not result["success"] and "not" in result["error"]

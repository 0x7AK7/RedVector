"""Approval input lifecycle and distinct execution states (areas 2 & 3). No hardcoded targets.

These exercise the real decision loop via an injected input source (empty/whitespace/invalid
re-prompt, case-insensitive, explicit deny), which is the input-handling logic a PTY drives;
a full pexpect PTY test is a planned follow-up."""
from redvector_ollama_agent import _resolve_approval, _execution_state

def _seq(values):
    it=iter(values)
    return lambda *a,**k:next(it)

def test_explicit_approve_case_insensitive():
    for word in ("APPROVE","approve","Approve","yes","y","  approve  "):
        assert _resolve_approval(_seq([word])) is True

def test_explicit_deny():
    for word in ("DENY","deny","no","n","cancel"):
        assert _resolve_approval(_seq([word])) is False

def test_empty_input_is_not_deny_it_reprompts():
    notes=[]
    # two empty/whitespace entries then a valid APPROVE -> approved, with retry notices
    assert _resolve_approval(_seq(["","   ","approve"]),notes.append) is True
    assert any("RETRY" in n for n in notes) and len(notes)==2

def test_exhausted_invalid_cancels_not_denies_silently():
    notes=[]
    assert _resolve_approval(_seq(["","x","?"]),notes.append,attempts=3) is False
    assert any("CANCELLED BY OPERATOR" in n for n in notes)

def test_execution_state_categories():
    assert _execution_state("Operator declined this operation.")=="TOOL EXECUTION / CANCELLED BY OPERATOR"
    assert _execution_state("The requested target is outside the operator-authorized scope.")=="TOOL EXECUTION / AUTHORIZATION DENIED"
    assert _execution_state("Missing Dependency: configure REDVECTOR_NUCLEI_BIN")=="TOOL EXECUTION / DEPENDENCY UNAVAILABLE"
    assert _execution_state("Missing integration: multi-tool dispatcher")=="TOOL EXECUTION / UNSUPPORTED INTEGRATION"
    assert _execution_state("Reviewed active service probes require exact operator approval")=="TOOL EXECUTION / APPROVAL REQUIRED"
    assert _execution_state("Arguments do not match the discovered tool schema.")=="TOOL EXECUTION / INVALID INPUT — RETRY"
    assert _execution_state("some backend error")=="TOOL EXECUTION / EXECUTION FAILED"

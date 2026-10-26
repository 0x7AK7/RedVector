import sys
from types import SimpleNamespace
from unittest.mock import patch
import pytest

class Reader:
    __doc__="GNU readline"
    __file__="fixture-module"
    def __init__(self):self.completer=None;self.delims="original"
    def get_completer(self):return self.completer
    def set_completer(self,value):self.completer=value
    def get_completer_delims(self):return self.delims
    def set_completer_delims(self,value):self.delims=value
    def get_line_buffer(self):return "/he"
    def get_begidx(self):return 0

def test_custom_completer_is_never_replaced():
    from redvector_ollama_completion import command_completion
    reader=Reader();reader.completer=object()
    before=reader.completer
    with patch.dict(sys.modules,{"readline":reader}):
        with command_completion() as enabled:assert not enabled
    assert reader.completer is before and reader.delims=="original"

def test_completion_restores_all_owned_state_even_on_input_error():
    import redvector_ollama_completion as module
    reader=Reader();events=[]
    class Binding:
        def __init__(self,rl):pass
        def activate(self):events.append("enable")
        def restore(self):events.append("restore")
    with patch.dict(sys.modules,{"readline":reader}),patch.object(module,"NativeTab",Binding):
        with pytest.raises(ValueError):
            with module.command_completion() as enabled:
                assert enabled
                assert reader.completer("/he",0)=="/help"
                assert reader.completer("/he",1) is None
                raise ValueError("input exception")
    assert reader.completer is None and reader.delims=="original"
    assert events==["enable","restore"]

def test_unavailable_native_binding_leaves_input_unchanged():
    import redvector_ollama_completion as module
    reader=Reader()
    with patch.dict(sys.modules,{"readline":reader}),patch.object(module,"NativeTab",side_effect=RuntimeError("unavailable")):
        with module.command_completion() as enabled:assert not enabled
    assert reader.completer is None and reader.delims=="original"

@pytest.mark.skipif(not sys.platform.startswith("linux"),reason="Requires native GNU readline")
def test_real_gnu_binding_is_restored():
    import readline
    from redvector_ollama_completion import command_completion,NativeTab
    before=NativeTab(readline).original
    completer=readline.get_completer();delims=readline.get_completer_delims()
    with command_completion() as enabled:assert enabled
    assert NativeTab(readline).original==before
    assert readline.get_completer() is completer
    assert readline.get_completer_delims()==delims

def test_existing_completer_does_not_swallow_input_exception():
    from redvector_ollama_completion import command_completion
    reader=Reader();reader.completer=object()
    with patch.dict(sys.modules,{"readline":reader}),pytest.raises(RuntimeError,match="operator input"):
        with command_completion():raise RuntimeError("operator input")

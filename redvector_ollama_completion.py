"""Optional reversible GNU-readline command completion. No input replacement."""
from contextlib import contextmanager
from redvector_ollama_help import completion_candidates

class NativeTab:
    """Save/restore only an existing ordinary GNU Tab function binding.

    Python readline exposes no binding getter. Use the installed extension's
    public GNU symbols when available; skip macros, custom bindings and libedit.
    No library paths, keymaps, or function addresses are hardcoded.
    """
    def __init__(self,readline):
        import ctypes
        if "libedit" in (readline.__doc__ or "").lower():raise RuntimeError("libedit")
        lib=ctypes.CDLL(readline.__file__)
        lib.rl_get_keymap.argtypes=[];lib.rl_get_keymap.restype=ctypes.c_void_p
        lib.rl_function_of_keyseq.argtypes=[ctypes.c_char_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_int)]
        lib.rl_function_of_keyseq.restype=ctypes.c_void_p
        lib.rl_named_function.argtypes=[ctypes.c_char_p];lib.rl_named_function.restype=ctypes.c_void_p
        lib.rl_bind_keyseq_in_map.argtypes=[ctypes.c_char_p,ctypes.c_void_p,ctypes.c_void_p]
        lib.rl_bind_keyseq_in_map.restype=ctypes.c_int
        self.lib=lib;self.keymap=lib.rl_get_keymap()
        if not self.keymap:raise RuntimeError("No readline keymap")
        kind=ctypes.c_int()
        self.original=lib.rl_function_of_keyseq(b"\t",self.keymap,ctypes.byref(kind))
        self.complete=lib.rl_named_function(b"complete")
        insert=lib.rl_named_function(b"self-insert")
        if kind.value!=0 or not self.original or not self.complete or self.original not in (insert,self.complete):
            raise RuntimeError("Preserve custom Tab binding")
    def activate(self):
        if self.lib.rl_bind_keyseq_in_map(b"\t",self.complete,self.keymap)!=0:raise RuntimeError("Cannot bind Tab")
    def restore(self):
        self.lib.rl_bind_keyseq_in_map(b"\t",self.original,self.keymap)

@contextmanager
def command_completion():
    try:
        import readline
        old=readline.get_completer()
        binding=NativeTab(readline) if old is None else None
        delimiters=readline.get_completer_delims()
    except (ImportError,AttributeError,OSError,RuntimeError):
        yield False;return
    if binding is None:
        yield False;return
    def complete(text,state):
        values=completion_candidates(readline.get_line_buffer(),text,readline.get_begidx())
        return values[state] if state<len(values) else None
    try:
        binding.activate()
        readline.set_completer_delims(" \t\n")
        readline.set_completer(complete)
    except Exception:
        binding.restore()
        readline.set_completer(old);readline.set_completer_delims(delimiters)
        yield False;return
    try:yield True
    finally:
        readline.set_completer(old)
        readline.set_completer_delims(delimiters)
        binding.restore()

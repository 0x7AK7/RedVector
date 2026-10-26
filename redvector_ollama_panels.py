"""Shared portable terminal primitives. No execution or authorization logic."""
import shutil
import textwrap
from redvector_ollama_setup import plain

def safe(value):
    return plain(value).encode("ascii","backslashreplace").decode("ascii")

class Panel:
    def __init__(self,term,width=None):
        self.term=term
        self.width=max(4,width if width is not None else shutil.get_terminal_size().columns)
    def line(self,value="",kind=None):
        text=safe(value)
        for part in text.splitlines() or [""]:
            for line in textwrap.wrap(part,width=self.width,replace_whitespace=True,drop_whitespace=True) or [""]:
                if kind:self.term.message(kind,line)
                else:self.term.write(line)
    def section(self,title,lines=(),kind="info"):
        self.line("+"+"-"*(self.width-2)+"+",kind)
        self.line(title,"info")
        for line in lines:self.line(line,kind if kind!="info" else None)
    def fields(self,rows):
        # Wide terminals align labels; narrow terminals use wrapped field cards.
        for key,value in rows:
            key=safe(key);value=safe(value)
            if self.width>=64 and len(key)<28:
                prefix=key.ljust(28)+" "
                pieces=textwrap.wrap(value,width=self.width-29) or [""]
                self.line(prefix+pieces[0])
                for piece in pieces[1:]:self.line(" "*29+piece)
            else:self.line(key+": "+value)
    def table(self,headers,rows):
        self.section(" | ".join(headers))
        for row in rows:
            self.fields(zip(headers,map(str,row)))

def status_kind(state):
    return "success" if state=="COMPLETED" else "error" if state in ("FAILED","BLOCKED") else "warning"

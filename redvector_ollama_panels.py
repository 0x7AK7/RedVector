"""Shared portable terminal primitives. No execution or authorization logic."""
import shutil
import textwrap
from redvector_ollama_setup import plain

def safe(value):
    # plain() already strips control characters and ANSI escapes while keeping printable Unicode
    # (e.g. an em dash renders as "—", never a literal "—"); do not re-escape to ASCII.
    return plain(value)

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
    def grid(self,headers,rows,kinds=None):
        """Aligned, width-aware table with an optional per-row color kind. Wide terminals get fixed
        columns (truncated to fit, never wrapped so alignment holds); narrow terminals fall back to
        stacked labeled cards. Cells are sanitized; no raw ANSI survives into redirected output."""
        headers=[safe(h) for h in headers];ncol=len(headers)
        cells=[[safe(str(c)) for c in row] for row in rows]
        kinds=list(kinds or [])
        def kind_for(i):return kinds[i] if i<len(kinds) else None
        def emit(text,kind=None):
            text=text[:self.width]
            if kind and self.term.color:self.term.message(kind,text)
            else:self.term.write(safe(text))
        if ncol and self.width>=64:
            widths=[len(headers[i]) for i in range(ncol)]
            for row in cells:
                for i in range(ncol):widths[i]=max(widths[i],len(row[i]) if i<len(row) else 0)
            avail=self.width-3*(ncol-1)
            if sum(widths)>avail:
                scale=avail/float(sum(widths));widths=[max(4,int(w*scale)) for w in widths]
            def fmt(cols):return " | ".join((cols[i] if i<len(cols) else "")[:widths[i]].ljust(widths[i]) for i in range(ncol))
            emit(fmt(headers));emit("-"*min(self.width,sum(widths)+3*(ncol-1)))
            for idx,row in enumerate(cells):emit(fmt(row),kind_for(idx))
        else:
            # narrow terminals: stacked labeled cards that WRAP (never truncate) so no value is lost
            for idx,row in enumerate(cells):
                for i in range(ncol):self.line(headers[i]+": "+(row[i] if i<len(row) else ""),kind_for(idx) if i==0 else None)
                self.line("-"*max(1,self.width-2))

def status_kind(state):
    return "success" if state=="COMPLETED" else "error" if state in ("FAILED","BLOCKED") else "warning"

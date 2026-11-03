"""Shared portable terminal primitives. No execution or authorization logic."""
import os
import re
import shutil
import sys
import textwrap


def plain(value):
    value = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|$))", "", str(value))
    return "".join(c for c in value if c in "\n\t" or (ord(c) >= 32 and not 127 <= ord(c) <= 159))


def safe(value):
    return plain(value)


class Terminal:
    def __init__(self, stream=None):
        self.stream = stream or sys.stdout
        self.color = bool(self.stream.isatty() and os.environ.get("TERM", "") not in ("", "dumb") and "NO_COLOR" not in os.environ)

    def write(self, value=""):
        print(value, file=self.stream, flush=True)

    def prompt(self, readline=False):
        if not self.color or not sys.stdin.isatty():
            return "redvector> "
        start = "\033[1;91m"
        reset = "\033[0m"
        if readline:
            start = "\001" + start + "\002"
            reset = "\001" + reset + "\002"
        return start + "redvector>" + reset + " "

    def message(self, kind, text):
        colors = {"success": "92", "warning": "33", "error": "91", "info": "36",
                  "critical": "91", "high": "38;5;208", "medium": "33", "low": "36", "meta": "38;5;245"}
        value = plain(text)
        self.write(("\033[" + colors.get(kind, "0") + "m" + value + "\033[0m") if self.color else value)

    def box(self, title, lines):
        Panel(self).section(title, lines)


class Panel:
    def __init__(self, term, width=None):
        self.term = term
        self.width = max(4, width if width is not None else shutil.get_terminal_size().columns)

    def line(self, value="", kind=None):
        text = safe(value)
        for part in text.splitlines() or [""]:
            for line in textwrap.wrap(part, width=self.width, replace_whitespace=True, drop_whitespace=True) or [""]:
                if kind:
                    self.term.message(kind, line)
                else:
                    self.term.write(line)

    def section(self, title, lines=(), kind="info"):
        self.line("+" + "-" * (self.width - 2) + "+", kind)
        self.line(title, "info")
        for line in lines:
            self.line(line, kind if kind != "info" else None)

    def fields(self, rows):
        for key, value in rows:
            key = safe(key)
            value = safe(value)
            if self.width >= 64 and len(key) < 28:
                prefix = key.ljust(28) + " "
                pieces = textwrap.wrap(value, width=self.width - 29) or [""]
                self.line(prefix + pieces[0])
                for piece in pieces[1:]:
                    self.line(" " * 29 + piece)
            else:
                self.line(key + ": " + value)

    def table(self, headers, rows):
        self.section(" | ".join(headers))
        for row in rows:
            self.fields(zip(headers, map(str, row)))

    def grid(self, headers, rows, kinds=None):
        """Aligned, width-aware table with an optional per-row color kind."""
        headers = [safe(h) for h in headers]
        ncol = len(headers)
        cells = [[safe(str(c)) for c in row] for row in rows]
        kinds = list(kinds or [])

        def kind_for(i):
            return kinds[i] if i < len(kinds) else None

        def emit(text, kind=None):
            text = text[:self.width]
            if kind and self.term.color:
                self.term.message(kind, text)
            else:
                self.term.write(safe(text))

        if self.width >= 60:
            widths = [max(len(h), *(len(cells[r][c]) for r in range(len(cells)))) if cells else len(h)
                      for c, h in enumerate(headers)]
            total = sum(widths) + 3 * (ncol - 1)
            if total > self.width:
                excess = total - self.width
                for i in sorted(range(ncol), key=lambda j: -widths[j]):
                    cut = min(excess, widths[i] - len(headers[i]))
                    if cut > 0:
                        widths[i] -= cut
                        excess -= cut
                    if excess <= 0:
                        break
            header_line = " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
            emit(header_line)
            emit("-" * len(header_line))
            for r, row in enumerate(cells):
                line = " | ".join(row[c][:widths[c]].ljust(widths[c]) for c in range(ncol))
                emit(line, kind_for(r))
        else:
            for r, row in enumerate(cells):
                for c in range(ncol):
                    self.line(headers[c] + ": " + row[c], kind_for(r))
                if r < len(cells) - 1:
                    self.line()

"""Inc A: professional dark-terminal palette, the \\u2014 leak fix, NO_COLOR / non-TTY safety and no
raw ANSI in redirected output. No target or version is hardcoded."""
import io
from redvector_ollama_setup import Terminal, plain
from redvector_ollama_panels import Panel, safe
from redvector_ollama_presentation import _text


class TTY(io.StringIO):
    def isatty(self):
        return True


def _colored(monkeypatch):
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.delenv("NO_COLOR", raising=False)
    return Terminal(TTY())


def test_em_dash_is_not_escaped_to_backslash_u():
    for fn in (safe, _text, plain):
        out = fn("Stage 1 — full-range discovery")
        assert "—" in out and "\\u2014" not in out and "u2014" not in out


def test_safe_still_strips_ansi_and_control():
    assert "\x1b" not in safe("\x1b[31mred\x1b[0m\x07") and "red" in safe("\x1b[31mred\x1b[0m")


def test_palette_has_severity_kinds_with_distinct_colors(monkeypatch):
    term = _colored(monkeypatch)
    codes = {}
    for kind in ("success", "critical", "high", "medium", "low", "info", "meta", "warning", "error"):
        term.stream.truncate(0); term.stream.seek(0)
        term.message(kind, "x")
        codes[kind] = term.stream.getvalue()
    assert "92m" in codes["success"]                 # green
    assert "91m" in codes["critical"] and "91m" in codes["error"]   # red
    assert "38;5;208m" in codes["high"]              # orange
    assert "33m" in codes["medium"] and "33m" in codes["warning"]   # yellow
    assert "36m" in codes["info"] and "36m" in codes["low"]         # cyan
    assert "38;5;245m" in codes["meta"]              # gray
    assert "38;5;196" not in codes["info"]           # the old info=red bug is gone


def test_no_color_env_disables_ansi(monkeypatch):
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("NO_COLOR", "1")
    term = Terminal(TTY())
    term.message("high", "critical finding")
    assert "\x1b" not in term.stream.getvalue() and "critical finding" in term.stream.getvalue()


def test_non_tty_output_has_no_ansi(monkeypatch):
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.delenv("NO_COLOR", raising=False)
    term = Terminal(io.StringIO())                   # a plain StringIO is not a TTY
    assert term.color is False
    term.message("high", "finding")
    assert "\x1b" not in term.stream.getvalue()


def test_panel_renders_unicode_without_ansi_when_not_tty():
    term = Terminal(io.StringIO())
    Panel(term, 60).section("STAGE — SUMMARY", ["open ports — 3"])
    out = term.stream.getvalue()
    assert "—" in out and "\x1b" not in out

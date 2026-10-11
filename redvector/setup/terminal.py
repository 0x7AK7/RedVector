"""Terminal UX for the RedVector setup manager.

Semantic colors with a mandatory textual state in every status line (never color
alone), NO_COLOR / non-TTY fallbacks, no blinking, and a compact banner (no giant
ASCII art). Everything is injectable so tests can drive it without a real TTY.
"""
from __future__ import annotations

import os
import sys
from typing import Callable, List, Optional, TextIO

from redvector.version import __version__

# ANSI SGR codes (only ever emitted when color is enabled).
_CODES = {
    "red": "31", "green": "32", "yellow": "33", "cyan": "36",
    "dim": "2", "bold": "1", "reset": "0",
}

# Semantic status tags -> color. The tag text is ALWAYS printed, so meaning never
# depends on color alone.
_STATUS_COLOR = {
    "READY": "green", "CONNECTED": "green", "PASS": "green", "OK": "green",
    "CONFIGURED": "green", "ADDED": "green", "UPDATED": "green", "INSTALLED": "green",
    "LIVE": "green", "ARMED": "red",
    "INFO": "cyan", "DETECTED": "cyan",
    "WARN": "yellow", "RESTART REQUIRED": "yellow", "MANUAL REQUIRED": "yellow",
    "NOT CONFIGURED": "yellow", "NOT INSTALLED": "yellow", "PREVIEW": "yellow",
    "PLATFORM DEPENDENT": "yellow", "UNVERIFIED": "yellow", "DEGRADED": "yellow",
    "STARTING": "yellow", "INSTALLED / STOPPED": "yellow", "STOPPED": "yellow",
    "STALE": "yellow", "SETUP REQUIRED": "yellow", "NOT RUNNING": "yellow",
    "NOT CONNECTED": "yellow",
    "NOT OBSERVABLE": "dim", "NOT APPLICABLE": "dim", "UNKNOWN": "dim",
    "ERROR": "red", "FAILED": "red", "CRITICAL": "red", "INVALID": "red",
}


class Terminal:
    def __init__(self, stream: Optional[TextIO] = None, env: Optional[dict] = None,
                 isatty: Optional[bool] = None, input_fn: Optional[Callable[[str], str]] = None) -> None:
        self.stream = stream if stream is not None else sys.stdout
        self.env = env if env is not None else os.environ
        if isatty is None:
            try:
                isatty = bool(self.stream.isatty())
            except Exception:
                isatty = False
        self._isatty = isatty
        self._input = input_fn or input
        self.eof = False   # set when the last prompt hit EOF (no interactive input)

    # -- color decision --
    @property
    def color_enabled(self) -> bool:
        if self.env.get("NO_COLOR") is not None:
            return False
        if self.env.get("REDVECTOR_NO_COLOR") is not None:
            return False
        if str(self.env.get("TERM", "")).lower() == "dumb":
            return False
        return self._isatty

    def colorize(self, text: str, color: str) -> str:
        if not self.color_enabled or color not in _CODES:
            return text
        return "\x1b[%sm%s\x1b[0m" % (_CODES[color], text)

    # -- primitives --
    def write(self, text: str = "") -> None:
        self.stream.write(text + "\n")

    def tagged(self, tag: str) -> str:
        """Return a colorized ``[TAG]`` string (always contains the textual tag)."""
        tag_u = tag.upper()
        color = _STATUS_COLOR.get(tag_u, "cyan")
        return self.colorize("[%s]" % tag_u, color)

    def status(self, tag: str, text: str = "") -> str:
        line = ("%s %s" % (self.tagged(tag), text)).rstrip()
        self.write(line)
        return line

    def info(self, text: str) -> None:
        self.status("INFO", text)

    def warn(self, text: str) -> None:
        self.status("WARN", text)

    def error(self, text: str) -> None:
        self.status("ERROR", text)

    def hint(self, text: str) -> None:
        self.write(self.colorize(text, "dim"))

    def banner(self) -> List[str]:
        title = "RedVector %s" % __version__
        sub = "AI-Assisted Offensive Security Platform"
        width = max(len(title), len(sub)) + 6
        top = "+" + "=" * width + "+"
        lines = [
            self.colorize(top, "red"),
            self.colorize("|" + title.center(width) + "|", "red"),
            self.colorize("|" + sub.center(width) + "|", "dim"),
            self.colorize(top, "red"),
        ]
        for ln in lines:
            self.write(ln)
        return lines

    def classic_banner(self, host: str = "127.0.0.1", port: str = "8888") -> None:
        """Render the ORIGINAL classic RedVector banner by reusing the single
        implementation in redvector.branding (no approximate duplicate). ANSI is
        stripped when color is disabled (NO_COLOR / non-TTY)."""
        from redvector import branding
        self.stream.write(branding.create_banner(host, port, color=self.color_enabled))
        self.stream.write("\n")

    def menu(self, title: str, options: List[str]) -> None:
        self.write()
        self.write(self.colorize(title, "cyan"))
        for i, opt in enumerate(options, 1):
            self.write("%s %s" % (self.colorize("%d." % i, "cyan"), opt))

    def ask(self, prompt_text: str) -> str:
        """Read one line. Returns '' on EOF / non-interactive input (and sets self.eof)."""
        self.eof = False
        try:
            return self._input(prompt_text).strip()
        except (EOFError, KeyboardInterrupt):
            self.eof = True
            self.write()
            return ""

    EOF = -1       # input stream ended (no interactive responder)
    INVALID = -2   # garbage / out-of-range input -> caller should reprompt

    def choose(self, title: str, options: List[str], back_label: str = "Main menu") -> int:
        """Render a numbered menu (1..N) plus a '0. <back_label>' entry and return:
        the 1-based choice, 0 for the back/exit entry, Terminal.EOF (-1) on end-of-
        input, or Terminal.INVALID (-2) for unrecognized input."""
        self.menu(title, options)
        if back_label:
            self.write("%s %s" % (self.colorize("0.", "cyan"), back_label))
        raw = self.ask(self.colorize("Select> ", "cyan"))
        if self.eof:
            return self.EOF
        try:
            n = int(raw)
        except ValueError:
            return self.INVALID
        if n == 0:
            return 0
        return n if 1 <= n <= len(options) else self.INVALID

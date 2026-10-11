"""Single source of the classic RedVector startup banner.

This is the ORIGINAL RedVector banner (large ASCII logo, By Adam K., the pipeline
lines, ARMED) extracted so both the backend (redvector.server) and the setup/chat
"Start RedVector" screen reuse ONE implementation - no approximate duplicate. The
only change from the historical code is that the ARMED marker no longer blinks
(blinking is disallowed by the current terminal-style rules); it stays red.
"""
from __future__ import annotations

import re

# Palette (256-color ANSI), matching the historical ModernVisualEngine colors.
_C = {
    "ACCENT": "\033[38;5;196m",      # HACKER_RED (logo)
    "GRADIENT": "\033[38;5;124m",    # BLOOD_RED (By Adam K.)
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
    "CRIM": "\033[38;5;160m",        # CRIMSON
    "RED": "\033[38;5;196m",         # HACKER_RED
    "GRN": "\033[38;5;46m",          # MATRIX_GREEN
    "CYAN": "\033[38;5;51m",         # NEON_BLUE
    "WHT": "\033[97m",               # BRIGHT_WHITE
    "GRAY": "\033[38;5;240m",        # TERMINAL_GRAY
    "YEL": "\033[38;5;208m",         # CYBER_ORANGE
    "ARMED": "\033[38;5;196m",       # red, non-blinking (was PULSE=red+blink)
}

_LOGO = r"""
██████╗ ███████╗██████╗ ██╗   ██╗███████╗ ██████╗████████╗ ██████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝█████╗  ██║  ██║██║   ██║█████╗  ██║        ██║   ██║   ██║██████╔╝
██╔══██╗██╔══╝  ██║  ██║╚██╗ ██╔╝██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
██║  ██║███████╗██████╔╝ ╚████╔╝ ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝╚═════╝   ╚═══╝  ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝"""

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def create_banner(host: str = "127.0.0.1", port: str = "8888", color: bool = True) -> str:
    """Return the classic RedVector banner. ``color=False`` yields plain text
    (for NO_COLOR / non-TTY)."""
    c = _C
    line = "  " + ("-" * 70)
    banner = (
        "\n%s%s%s%s\n"
        "%s%s%s\n"
        "%s%s%s\n"
        "%s%s  |> %sTHREAT FRAMEWORK    %s|%s %s325 attack vectors%s %sacross 33 autonomous engines%s\n"
        "%s%s  |> %sEXECUTION MODE      %s|%s %sreal tool chains%s  %snmap > nuclei > netexec > msf%s\n"
        "%s%s  |> %sOFFENSIVE PIPELINE  %s|%s %s8-stage lifecycle%s %srecon > exploit > persist > exfil%s\n"
        "%s%s  |> %sAI DECISION ENGINE  %s|%s %sadaptive replanning%s %son failure with fallback chains%s\n"
        "%s%s%s\n"
        "%s%s  [%s ARMED %s%s%s]%s  %sWaiting for targets on %s%s:%s%s\n"
        "%s%s  Authorized red team operations only. Unauthorized use is prohibited.%s\n"
    ) % (
        c["ACCENT"], c["BOLD"], _LOGO, c["RESET"],
        "", c["GRADIENT"] + "                                                                    By Adam K.", c["RESET"],
        c["DIM"] + c["GRAY"], line, c["RESET"],
        c["CRIM"], c["BOLD"], c["WHT"], c["RED"], c["RESET"], c["GRN"], c["RESET"], c["DIM"], c["RESET"],
        c["CRIM"], c["BOLD"], c["WHT"], c["RED"], c["RESET"], c["GRN"], c["RESET"], c["DIM"], c["RESET"],
        c["CRIM"], c["BOLD"], c["WHT"], c["RED"], c["RESET"], c["GRN"], c["RESET"], c["DIM"], c["RESET"],
        c["CRIM"], c["BOLD"], c["WHT"], c["RED"], c["RESET"], c["GRN"], c["RESET"], c["DIM"], c["RESET"],
        c["DIM"] + c["GRAY"], line, c["RESET"],
        c["RED"], c["BOLD"], c["ARMED"], c["RESET"], c["RED"], c["BOLD"], c["RESET"], c["GRAY"], c["CYAN"], host, port, c["RESET"],
        c["YEL"], c["BOLD"], c["RESET"],
    )
    return banner if color else strip_ansi(banner)

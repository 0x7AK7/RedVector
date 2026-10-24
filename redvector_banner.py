#!/usr/bin/env python3
"""Shared original startup artwork. Importing this module never starts the backend."""
import argparse
import ast
import os
from pathlib import Path

API_PORT = int(os.environ.get('REDVECTOR_PORT', 8888))
API_HOST = os.environ.get('REDVECTOR_HOST', '127.0.0.1')
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 300
CACHE_SIZE = 1000
CACHE_TTL = 3600

COLORS = {
    'MATRIX_GREEN': '\033[38;5;46m',
    'NEON_BLUE': '\033[38;5;51m',
    'ELECTRIC_PURPLE': '\033[38;5;129m',
    'CYBER_ORANGE': '\033[38;5;208m',
    'HACKER_RED': '\033[38;5;196m',
    'TERMINAL_GRAY': '\033[38;5;240m',
    'BRIGHT_WHITE': '\033[97m',
    'RESET': '\033[0m',
    'BOLD': '\033[1m',
    'DIM': '\033[2m',
    # New reddish tones and highlighting colors
    'BLOOD_RED': '\033[38;5;124m',
    'CRIMSON': '\033[38;5;160m',
    'DARK_RED': '\033[38;5;88m',
    'FIRE_RED': '\033[38;5;202m',
    'ROSE_RED': '\033[38;5;167m',
    'BURGUNDY': '\033[38;5;52m',
    'SCARLET': '\033[38;5;197m',
    'RUBY': '\033[38;5;161m',
# Unified theme primary/secondary (used going forward instead of legacy blue/green accents)
'PRIMARY_BORDER': '\033[38;5;160m',  # CRIMSON
'ACCENT_LINE': '\033[38;5;196m',      # HACKER_RED
'ACCENT_GRADIENT': '\033[38;5;124m',  # BLOOD_RED (for subtle alternation)
    # Highlighting colors
    'HIGHLIGHT_RED': '\033[48;5;196m\033[38;5;15m',  # Red background, white text
    'HIGHLIGHT_YELLOW': '\033[48;5;226m\033[38;5;16m',  # Yellow background, black text
    'HIGHLIGHT_GREEN': '\033[48;5;46m\033[38;5;16m',  # Green background, black text
    'HIGHLIGHT_BLUE': '\033[48;5;51m\033[38;5;16m',  # Blue background, black text
    'HIGHLIGHT_PURPLE': '\033[48;5;129m\033[38;5;15m',  # Purple background, white text
    # Status colors with reddish tones
    'SUCCESS': '\033[38;5;46m',  # Bright green
    'WARNING': '\033[38;5;208m',  # Orange
    'ERROR': '\033[38;5;196m',  # Bright red
    'CRITICAL': '\033[48;5;196m\033[38;5;15m\033[1m',  # Red background, white bold text
    'INFO': '\033[38;5;51m',  # Cyan
    'DEBUG': '\033[38;5;240m',  # Gray
    # Vulnerability severity colors
    'VULN_CRITICAL': '\033[48;5;124m\033[38;5;15m\033[1m',  # Dark red background
    'VULN_HIGH': '\033[38;5;196m\033[1m',  # Bright red bold
    'VULN_MEDIUM': '\033[38;5;208m\033[1m',  # Orange bold
    'VULN_LOW': '\033[38;5;226m',  # Yellow
    'VULN_INFO': '\033[38;5;51m',  # Cyan
    # Tool status colors
    'TOOL_RUNNING': '\033[38;5;46m\033[5m',  # Blinking green
    'TOOL_SUCCESS': '\033[38;5;46m\033[1m',  # Bold green
    'TOOL_FAILED': '\033[38;5;196m\033[1m',  # Bold red
    'TOOL_TIMEOUT': '\033[38;5;208m\033[1m',  # Bold orange
    'TOOL_RECOVERY': '\033[38;5;129m\033[1m',  # Bold purple
    # Progress and animation colors
    'PROGRESS_BAR': '\033[38;5;46m',  # Green
    'PROGRESS_EMPTY': '\033[38;5;240m',  # Gray
    'SPINNER': '\033[38;5;51m',  # Cyan
    'PULSE': '\033[38;5;196m\033[5m'  # Blinking red
}


def count_mcp_tools() -> int:
    """Read registrations without importing the MCP client or its dependencies."""
    tree = ast.parse(Path(__file__).with_name('redvector_mcp.py').read_text(encoding='utf8'))
    return sum(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
               and isinstance(node.func.value, ast.Name) and node.func.value.id == 'mcp'
               and node.func.attr == 'tool' for node in ast.walk(tree))


def render_banner(host: str = API_HOST, port: int = API_PORT) -> str:
    """Create the enhanced RedVector banner"""
    border_color = COLORS['PRIMARY_BORDER']
    accent = COLORS['ACCENT_LINE']
    gradient = COLORS['ACCENT_GRADIENT']
    RESET = COLORS['RESET']
    BOLD = COLORS['BOLD']
    CRIM = COLORS['CRIMSON']
    RED = COLORS['HACKER_RED']
    GRN = COLORS['MATRIX_GREEN']
    CYAN = COLORS['NEON_BLUE']
    DIM = COLORS['DIM']
    WHT = COLORS['BRIGHT_WHITE']
    GRAY = COLORS['TERMINAL_GRAY']
    PULSE = COLORS['PULSE']
    YEL = COLORS['CYBER_ORANGE']
    title_block = f"{accent}{BOLD}"
    banner = f"""
{title_block}
██████╗ ███████╗██████╗ ██╗   ██╗███████╗ ██████╗████████╗ ██████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝█████╗  ██║  ██║██║   ██║█████╗  ██║        ██║   ██║   ██║██████╔╝
██╔══██╗██╔══╝  ██║  ██║╚██╗ ██╔╝██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
██║  ██║███████╗██████╔╝ ╚████╔╝ ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝╚═════╝   ╚═══╝  ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
                                                                    {gradient}By Adam K.{RESET}
{DIM}{GRAY}  ──────────────────────────────────────────────────────────────────────{RESET}
{CRIM}{BOLD}  ▸ {WHT}THREAT FRAMEWORK    {RED}│{RESET} {GRN}325 attack vectors{RESET} {DIM}across 33 autonomous engines{RESET}
{CRIM}{BOLD}  ▸ {WHT}EXECUTION MODE     {RED}│{RESET} {GRN}real tool chains{RESET}  {DIM}nmap > nuclei > netexec > msf{RESET}
{CRIM}{BOLD}  ▸ {WHT}OFFENSIVE PIPELINE {RED}│{RESET} {GRN}8-stage lifecycle{RESET} {DIM}recon > exploit > persist > exfil{RESET}
{CRIM}{BOLD}  ▸ {WHT}AI DECISION ENGINE {RED}│{RESET} {GRN}adaptive replanning{RESET} {DIM}on failure with fallback chains{RESET}
{DIM}{GRAY}  ──────────────────────────────────────────────────────────────────────{RESET}
{RED}{BOLD}  [{PULSE} ARMED {RESET}{RED}{BOLD}]{RESET}  {GRAY}Waiting for targets on {CYAN}{host}:{port}{RESET}
{YEL}{BOLD}  Authorized red team operations only. Unauthorized use is prohibited.{RESET}
"""
    return banner


def render_startup_panel(host: str = API_HOST, port: int = API_PORT,
                         cache_size: int = CACHE_SIZE, cache_ttl: int = CACHE_TTL,
                         command_timeout: int = COMMAND_TIMEOUT, debug: bool = DEBUG_MODE,
                         mcp_tools=None) -> str:
    """Render the original panel with the selected server values and current tool count."""
    C = COLORS
    mcp_tools = count_mcp_tools() if mcp_tools is None else mcp_tools
    return f"""
{C['HACKER_RED']}{C['BOLD']}  ┌──────────────────────────────────────────────────────────────────┐{C['RESET']}
{C['HACKER_RED']}{C['BOLD']}  │{C['RESET']}  {C['CRIMSON']}root@redvector{C['RESET']}{C['TERMINAL_GRAY']}:{C['NEON_BLUE']}~/{C['RESET']} {C['MATRIX_GREEN']}./redvector --deploy{C['RESET']}
{C['HACKER_RED']}{C['BOLD']}  ├──────────────────────────────────────────────────────────────────┤{C['RESET']}
{C['HACKER_RED']}{C['BOLD']}  │{C['RESET']}  {C['MATRIX_GREEN']}[+]{C['RESET']} {C['BRIGHT_WHITE']}BIND      {C['RESET']}{C['TERMINAL_GRAY']}....{C['RESET']} {C['NEON_BLUE']}{host}:{port}{C['RESET']}
{C['HACKER_RED']}{C['BOLD']}  │{C['RESET']}  {C['MATRIX_GREEN']}[+]{C['RESET']} {C['BRIGHT_WHITE']}SYSTEMS   {C['RESET']}{C['TERMINAL_GRAY']}....{C['RESET']} {C['MATRIX_GREEN']}33 autonomous engines online{C['RESET']}
{C['HACKER_RED']}{C['BOLD']}  │{C['RESET']}  {C['MATRIX_GREEN']}[+]{C['RESET']} {C['BRIGHT_WHITE']}ROUTES    {C['RESET']}{C['TERMINAL_GRAY']}....{C['RESET']} {C['MATRIX_GREEN']}325 attack vectors loaded{C['RESET']}
{C['HACKER_RED']}{C['BOLD']}  │{C['RESET']}  {C['MATRIX_GREEN']}[+]{C['RESET']} {C['BRIGHT_WHITE']}MCP TOOLS {C['RESET']}{C['TERMINAL_GRAY']}....{C['RESET']} {C['MATRIX_GREEN']}{mcp_tools} tool handlers armed{C['RESET']}
{C['HACKER_RED']}{C['BOLD']}  │{C['RESET']}  {C['MATRIX_GREEN']}[+]{C['RESET']} {C['BRIGHT_WHITE']}CACHE     {C['RESET']}{C['TERMINAL_GRAY']}....{C['RESET']} {C['CYBER_ORANGE']}{cache_size} slots | {cache_ttl}s TTL{C['RESET']}
{C['HACKER_RED']}{C['BOLD']}  │{C['RESET']}  {C['MATRIX_GREEN']}[+]{C['RESET']} {C['BRIGHT_WHITE']}TIMEOUT   {C['RESET']}{C['TERMINAL_GRAY']}....{C['RESET']} {C['CYBER_ORANGE']}{command_timeout}s per command{C['RESET']}
{C['HACKER_RED']}{C['BOLD']}  │{C['RESET']}  {C['MATRIX_GREEN']}[+]{C['RESET']} {C['BRIGHT_WHITE']}DEBUG     {C['RESET']}{C['TERMINAL_GRAY']}....{C['RESET']} {C['CYBER_ORANGE']}{debug}{C['RESET']}
{C['HACKER_RED']}{C['BOLD']}  │{C['RESET']}  {C['MATRIX_GREEN']}[+]{C['RESET']} {C['BRIGHT_WHITE']}ENGINE    {C['RESET']}{C['TERMINAL_GRAY']}....{C['RESET']} {C['MATRIX_GREEN']}AI decision + fallback chains active{C['RESET']}
{C['HACKER_RED']}{C['BOLD']}  └──────────────────────────────────────────────────────────────────┘{C['RESET']}
{C['HACKER_RED']}{C['BOLD']}  [{C['PULSE']} LIVE {C['RESET']}{C['HACKER_RED']}{C['BOLD']}]{C['RESET']}  {C['TERMINAL_GRAY']}All systems operational. Awaiting engagement.{C['RESET']}
"""


def main():
    parser = argparse.ArgumentParser(description='Render the original RedVector startup banner only')
    parser.add_argument('--host', default=API_HOST)
    parser.add_argument('--port', type=int, default=API_PORT)
    parser.add_argument('--debug', action='store_true', default=DEBUG_MODE)
    args = parser.parse_args()
    print(render_banner(args.host, args.port))
    print(render_startup_panel(args.host, args.port, debug=args.debug).strip())


if __name__ == '__main__':
    main()

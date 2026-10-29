"""Deterministic natural-language intent routing for the interactive operator session.

Maps ordinary English to the SAME validated operator actions the (now unadvertised) slash commands
invoke — authorization, scope display, status, tool discovery, saved-result analysis/raw/export and
navigation — so the operator never needs command syntax. Routing is deterministic (regex), never an
LLM guess. Authorization is kept separate from a mere mention of an address: only an explicit
authorization instruction yields the `authorize` intent, so a scan request that happens to name an IP
never configures scope. Scan/discovery/analysis-of-a-scan requests are left to the agent's existing
deterministic turn() routing (the `task` intent).

classify(text) -> (intent, payload). Intents: authorize (payload: [targets]), authorize_needs_target,
deauthorize, show_scope, status, tools (payload: query), analyze, results (payload: ident|"list"),
raw (payload: ident), export (payload: ident), help, back, task. `task` means "not an operator
command — hand to turn()".
"""
import re
from redvector_ollama_cli import _looks_like_target

# Natural-language capability help (no slash commands advertised).
HELP_TEXT = (
    "You can talk to RedVector in plain English — there are no commands to memorize.\n"
    "- Authorize a target you own or may test: \"Authorize <your target> as my lab target.\"\n"
    "- Assess: \"Scan my authorized target and identify running services.\"\n"
    "- Discover + versions: \"Discover open TCP ports and identify service versions.\"\n"
    "- Review evidence: \"Analyze the latest results.\" / \"Show the raw evidence.\" / \"Export the report as JSON.\"\n"
    "- Check state: \"Show my authorized targets.\" / \"Check system status.\" / \"Show available tools.\"\n"
    "- Navigate: \"Return to the main menu.\"\n"
    "Authorization is explicit and session-local; merely mentioning an address never authorizes it, "
    "and out-of-scope targets stay blocked. High-impact operations still require your explicit approval.")

_AUTHORIZE = re.compile(r"(?i)(?:\bauthori[sz]e\b|\bauthori[sz]ation\s+(?:for|to)\b|\bi\s+(?:own|operate|control|manage)\b"
                        r"|\bi\s+have\s+(?:permission|authori[sz]ation|consent|rights)\b"
                        r"|\b(?:add|set)\s+(?:the\s+)?(?:authori[sz]ed\s+)?(?:scope|target)\b"
                        r"|\bscope\s+(?:is|to)\b"
                        r"|\bis\s+(?:my|our)\s+(?:lab\s+|authori[sz]ed\s+|assessment\s+)?(?:target|host|machine|system|box)\b"
                        r"|\b(?:my|our)\s+(?:lab\s+|authori[sz]ed\s+|assessment\s+)(?:target|host|machine|system|box)\s+(?:is|are)\b)")
_DEAUTH = re.compile(r"(?i)\b(?:clear|reset|remove|forget|drop)\b(?:\s+\w+){0,3}?\s+(?:scope|authori[sz]ed\s+targets?|authori[sz]ation)\b|\b(?:clear|reset)\s+(?:my\s+|the\s+)?scope\b")
_SHOW_SCOPE = re.compile(r"(?i)\b(?:show|list|display|what(?:'s| is| are)?|which\s+are)\b(?:\s+\w+){0,3}?\s+(?:authori[sz]ed\s+)?(?:scope|targets?)\b|\bwhat\s+(?:am\s+i|targets?\s+am\s+i)\s+authori[sz]ed\b")
_STATUS = re.compile(r"(?i)\bsystem\s+status\b|\bstatus\s+of\s+(?:the\s+)?(?:system|backend|server|mcp|redvector)\b|\bhealth\s*check\b|\bcheck\b(?:\s+\w+){0,3}?\s+status\b|\bis\s+(?:the\s+)?(?:backend|server|mcp|system)\s+(?:up|healthy|running|available|ok)\b")
_TOOLS = re.compile(r"(?i)\b(?:show|list|display|what|which)\b(?:\s+\w+){0,4}?\s+(?:security\s+)?(?:tools?|scanners?|engines?|capabilit(?:y|ies))\b|\bavailable\s+(?:security\s+)?tools?\b")
_HELP = re.compile(r"(?i)\bwhat\s+can\s+(?:redvector|you)\s+do\b|\bhow\s+do\s+i\s+use\b|\bwhat\s+can\s+i\s+(?:say|ask|do)\b|^\s*help\s*$|\bshow\s+(?:me\s+)?help\b")
_ANALYZE = re.compile(r"(?i)\b(?:analy[sz]e|summari[sz]e|explain|interpret|review)\b(?:\s+\w+){0,4}?\s+(?:scan|assessment|result|results|finding|findings|evidence|output)\b|\b(?:analy[sz]e|summari[sz]e)\s+(?:the\s+)?(?:latest|last|previous|recent|saved)\b")
_RAW = re.compile(r"(?i)\b(?:show|display|view|see|give\s+me)\b(?:\s+\w+){0,4}?\s+(?:original|raw)\b(?:\s+\w+){0,3}?\s+(?:evidence|output|wire|results?|data|nmap)\b|\braw\s+(?:nmap\s+)?(?:evidence|output|wire)\b|\boriginal\s+(?:nmap\s+)?evidence\b")
_RESULTS = re.compile(r"(?i)\b(?:show|list|display|view)\b(?:\s+\w+){0,3}?\s+(?:saved\s+)?(?:scan\s+)?results?\b|\blist\b(?:\s+\w+){0,3}?\s+(?:result|evidence)\s+ids?\b|\bevidence\s+ids?\b")
_EXPORT = re.compile(r"(?i)\bexport\b(?:\s+\w+){0,4}?\s+(?:report|results?|evidence|findings?)\b|\bexport\s+(?:my|the|it|that)\b|\bsave\b(?:\s+\w+){0,3}?\s+report\b")
_BACK = re.compile(r"(?i)\b(?:back|return|go)\s+(?:back\s+)?to\s+(?:the\s+)?(?:main|startup)?\s*menu\b|\bmain\s+menu\b|\b(?:switch|change)\s+(?:the\s+)?model\b|\bstartup\s+menu\b")
_LIST = re.compile(r"(?i)\blist\b")
_ID = re.compile(r"\b([0-9a-f]{8,32})\b", re.I)


def _targets(text):
    found = []
    for raw in re.findall(r"[A-Za-z0-9:\[][A-Za-z0-9_.:/%\[\]\-]*", text):
        token = raw.rstrip(".?,;:")
        if token.startswith("[") and token.endswith("]"):
            token = token[1:-1]
        if _looks_like_target(token):
            found.append(token)
    return list(dict.fromkeys(found))


def _ident(text):
    match = _ID.search(text)
    return match.group(1) if match else None


def classify(text):
    """Deterministically classify an operator instruction. Operator-command intents are recognized
    here; anything else (scanning, discovery, analysing a described task) is returned as `task` for
    the agent's existing turn() routing."""
    if not isinstance(text, str):
        return "task", None
    view = text.strip()
    if not view:
        return "task", None
    # Authorization first: an explicit authorization act. Requires a destination-shaped target;
    # without one we ask, and a bare IP mention with no authorization verb is NOT authorization.
    if _AUTHORIZE.search(view):
        targets = _targets(view)
        return ("authorize", targets) if targets else ("authorize_needs_target", None)
    if _DEAUTH.search(view):
        return "deauthorize", None
    if _SHOW_SCOPE.search(view):
        return "show_scope", None
    if _STATUS.search(view):
        return "status", None
    if _TOOLS.search(view):
        return "tools", view
    if _HELP.search(view):
        return "help", None
    if _RAW.search(view):
        return "raw", _ident(view)
    if _RESULTS.search(view):
        return ("results", "list") if _LIST.search(view) else ("results", _ident(view))
    if _EXPORT.search(view):
        return "export", _ident(view)
    if _ANALYZE.search(view):
        return "analyze", None
    if _BACK.search(view):
        return "back", None
    return "task", None

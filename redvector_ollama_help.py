"""Shared built-in command registry, help and safe command-name completion."""
from dataclasses import dataclass
from difflib import get_close_matches
from redvector_ollama_panels import Panel

@dataclass(frozen=True)
class Command:
    route:str
    group:str
    usage:str
    description:str
    arguments:str
    examples:tuple
    restrictions:str

COMMANDS={
 "/artifact":Command("artifact","Evidence and analysis","/artifact [PATH | --clear]",
    "Select a read-only regular-file snapshot for compatible offline artifact tools.",
    "PATH: one regular file up to 4 MiB, quoted or unquoted; no symlinks/junctions. Omitted displays selection; --clear clears it.",
    ("/artifact PATH","/artifact","/artifact --clear"),
    "Only operator input selects files. Bytes are copied privately and hashed; selected code is never executed. Select again to analyze later file changes."),
 "/scope":Command("scope","Targets and authorization","/scope [TARGET ... | --clear]",
    "Display or atomically replace the operator-authorized session scope.",
    "TARGET: IPv4, IPv6, CIDR or exact hostname. No arguments displays scope; --clear removes all targets.",
    ("/scope TARGET","/scope CIDR","/scope --clear"),
    "Only the operator authorizes scope. Hostnames are DNS-pinned and rechecked. Select one host inside a CIDR for a scan; scope does not authorize every tool."),
 "/status":Command("status","Connection and tools","/status",
    "Call the real read-only MCP server_health diagnostic and display its result.",
    "None.",("/status",),"Requires an available authenticated local MCP/backend connection. Does not scan targets."),
 "/tools":Command("tools","Connection and tools","/tools QUERY",
    "Search registered MCP tools and show reviewed or blocked execution policy.",
    "QUERY: tool name or task keywords.",("/tools scan","/tools server_health"),
    "Discovery does not authorize execution. Unreviewed and high-impact tools remain blocked."),
 "/results":Command("saved","Evidence and analysis","/results [ID | latest | list]",
    "Display saved factual tool results or list their evidence IDs.",
    "ID: an evidence ID shown after execution; omitted/latest selects the latest result; list lists IDs.",
    ("/results","/results list","/results RESULT_ID"),
    "Reads private saved evidence only. Does not execute tools. Evidence available only in-session must be exported before exit."),
 "/summary":Command("saved","Evidence and analysis","/summary [ID | latest] [PAGE]",
    "Analyze an existing evidence page with the selected local model.",
    "ID: saved evidence ID or latest. PAGE: positive page number, default 1; use latest before PAGE.",
    ("/summary","/summary latest 2","/summary RESULT_ID 1"),
    "Tool-free AI analysis only; never repeats the original operation. Failed/unknown execution cannot be presented as successful. AI output must match evidence."),
 "/raw":Command("saved","Evidence and analysis","/raw [ID | latest]",
    "Display original MCP wire evidence separately from formatted results.",
    "ID: a saved evidence ID; omitted/latest selects the latest result.",
    ("/raw","/raw RESULT_ID"),
    "May contain sensitive assessment data. Reads local evidence; does not execute tools."),
 "/export":Command("saved","Evidence and analysis","/export [ID | latest]",
    "Create a private JSON copy of original evidence and its reporting context.",
    "ID: a saved evidence ID; omitted/latest selects the latest result.",
    ("/export","/export RESULT_ID"),
    "Writes a new private local evidence export. No upload or publication. Keep exports confidential."),
 "/back":Command("exit","Navigation and help","/back",
    "Return to the startup menu, where you can select another model.",
    "None.",("/back",),"Does not stop the existing backend or Ollama service. Session-local authorization ends with the session."),
 "/exit":Command("exit","Navigation and help","/exit",
    "Alias of /back: return from the interactive session to the startup menu.",
    "None.",("/exit",),"Use the startup menu Exit option to close the launcher. Does not stop existing services."),
 "/help":Command("help","Navigation and help","/help [COMMAND | search TEXT]",
    "List real built-in commands, explain one command, or search command help.",
    "COMMAND: command name with or without /. search TEXT: words to find in command descriptions.",
    ("/help","/help scope","/help /summary","/help search authorization"),
    "Help and command search are local and never call the model or MCP tools. Natural-language instructions remain supported."),
}

SAFETY=("Authorize targets with /scope before assessment. Public and private targets use the same checks.",
        "Reviewed single-host TCP discovery covers up to 1,000 ports with fixed rate/session limits. Larger scans require exact approval.",
        "High-impact/unreviewed tools require separate reviewed paths. Active service-version profiles require exact approval; arbitrary scripts remain unavailable.",
        "Use /tools QUERY to inspect tool availability; port-name labels do not verify versions.",
        "Enter a natural-language task alongside these commands. Type /help COMMAND for detail; /help search TEXT searches help.",
        "Tab completes command names where GNU readline can safely preserve your current editing configuration.")

def suggestions(name):
    return get_close_matches(name,COMMANDS,n=3,cutoff=.55)

def render_help(term,argument=""):
    panel=Panel(term)
    argument=argument.strip()
    if not argument:
        panel.section("REDVECTOR OPERATOR HELP")
        groups=list(dict.fromkeys(spec.group for spec in COMMANDS.values()))
        for group in groups:
            panel.section(group)
            panel.fields((spec.usage,spec.description) for spec in COMMANDS.values() if spec.group==group)
        panel.section("AUTHORIZATION AND EXECUTION RESTRICTIONS",SAFETY,"warning")
        return
    words=argument.split(None,1)
    if words[0]=="search":
        if len(words)<2:
            panel.section("HELP SEARCH",["Usage: /help search TEXT","Search command names, usage, descriptions and restrictions locally."])
            return
        tokens=words[1].casefold().split()
        matches=[(name,spec) for name,spec in COMMANDS.items()
                 if all(token in (" ".join((name,spec.usage,spec.description,spec.arguments,spec.restrictions))).casefold() for token in tokens)]
        panel.section("COMMAND SEARCH")
        panel.fields((spec.usage,spec.description) for name,spec in matches)
        if not matches:panel.line("No commands match. Use /help to view all commands.","warning")
        return
    name=argument if argument.startswith("/") else "/"+argument
    spec=COMMANDS.get(name)
    if spec is None:
        panel.section("HELP / UNKNOWN COMMAND",[unknown_message(name)],"warning");return
    panel.section("COMMAND HELP / "+name)
    for label,text in (("Usage",spec.usage),("Description",spec.description),("Arguments",spec.arguments)):
        panel.line(label+": "+text)
    panel.line("Examples:")
    for example in spec.examples:panel.line("  "+example)
    panel.line("Restrictions: "+spec.restrictions,"warning")

def unknown_message(name):
    matches=suggestions(name)
    return ("Unknown command: "+name+". "+("Did you mean "+", ".join(matches)+"? " if matches else "")+
            "Type /help to view all commands or /help search TEXT. Nothing was sent to Ollama.")

def completion_candidates(line,text,begin):
    prefix=line[:begin].strip()
    if not prefix and text.startswith("/"):return sorted(name for name in COMMANDS if name.startswith(text))
    if prefix=="/help":
        choices=list(COMMANDS) if text.startswith("/") else [name[1:] for name in COMMANDS]+["search"]
        return sorted(name for name in choices if name.startswith(text))
    return []

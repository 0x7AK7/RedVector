"""Unified native-tool status layer for RedVector AI.

Queries each reviewed native adapter's capabilities() function and normalises the result into
a single structured status dict with actionable installation guidance. Never installs tools,
executes binaries, modifies configuration, or bypasses integrity checks. Safe to call on any
platform: Missing Dependency is returned for tools that require native Linux when running on
Windows or macOS.

Usage::

    import redvector_tool_manager as tool_manager
    tool_status = tool_manager.discover_tools()
    reason = tool_manager.unavailability_reason("nikto-native-v1", tool_status)
"""

READY = "Ready"
MISSING = "Missing Dependency"
UNSUPPORTED = "Unsupported"
DISABLED = "Disabled"
RESTRICTED = "Restricted"

# Each entry describes one installed Kali tool and the adapter that reviews it.
# profiles lists every profile ID the adapter exposes, in the order they appear
# in that adapter's capabilities() dict.
_TOOLS = [
    {
        "name": "nmap",
        "display": "native Nmap",
        "execution_class": "detection",
        "profiles": ("tcp-discovery-v1", "service-version-v1", "nse-vuln-v1"),
        "adapter": "redvector_reviewed_profiles",
        "install_hint": "sudo apt-get install nmap",
    },
    {
        "name": "nuclei",
        "display": "native Nuclei (reviewed offline header profile)",
        "execution_class": "web-scan",
        "profiles": ("--redvector-profile=http-headers-v1",),
        "adapter": "redvector_reviewed_assessment",
        "install_hint": "python3 tools/install_reviewed_nuclei.py  (reviewed build required)",
    },
    {
        "name": "nikto",
        "display": "native Nikto (reviewed non-destructive tuning)",
        "execution_class": "web-scan",
        "profiles": ("nikto-native-v1",),
        "adapter": "redvector_reviewed_nikto",
        "install_hint": "sudo apt-get install nikto",
    },
    {
        "name": "searchsploit",
        "display": "native Searchsploit (offline Exploit-DB, read-only)",
        "execution_class": "exploit-db",
        "profiles": ("searchsploit-v1",),
        "adapter": "redvector_reviewed_searchsploit",
        "install_hint": "sudo apt-get install exploitdb",
    },
]

# Build a fast profile → spec index for unavailability_reason()
_PROFILE_TO_SPEC = {pid: spec for spec in _TOOLS for pid in spec["profiles"]}


def discover_tools():
    """Query each reviewed adapter and return a unified status dict.

    Returns a dict keyed by tool name (nmap, nuclei, nikto, searchsploit). Each value:
      {display, execution_class, install_hint, profiles: {profile_id: {state, detail}}}.
    """
    result = {}
    for spec in _TOOLS:
        cap = _capabilities_safe(spec["adapter"])
        profiles = {}
        for pid in spec["profiles"]:
            if pid in cap:
                profiles[pid] = cap[pid]
            elif "_error" in cap:
                profiles[pid] = cap["_error"]
            else:
                profiles[pid] = {"state": UNSUPPORTED, "detail": "Profile not registered on this platform"}
        result[spec["name"]] = {
            "display": spec["display"],
            "execution_class": spec["execution_class"],
            "install_hint": spec["install_hint"],
            "profiles": profiles,
        }
    return result


def unavailability_reason(profile_id, tool_status):
    """Return a precise human-readable reason why a profile is not Ready.

    Explains the specific root cause so the operator knows exactly what to fix:
    tool not installed / native Linux required / unsupported version / attestation
    failed / script allowlist empty / disabled / restricted.
    """
    spec = _PROFILE_TO_SPEC.get(profile_id)
    if spec is None:
        return "no approved adapter for profile {!r}".format(profile_id)

    info = tool_status.get(spec["name"], {}).get("profiles", {}).get(profile_id, {})
    state = info.get("state", "")
    detail = info.get("detail", "")
    detail_l = detail.lower()

    if state == READY:
        return "ready"
    if MISSING in state or "missing" in state.lower():
        return "not installed: {} — to install: {}".format(spec["display"], spec["install_hint"])
    if "linux" in detail_l:
        return "not enabled: native Linux required — {} runs on native Kali only".format(spec["display"])
    if "allowlist" in detail_l or ("empty" in detail_l and "nse" in profile_id.lower()):
        return ("not run: script allowlist not yet curated — "
                "run python3 tools/collect_kali_evidence.py on native Kali and review nse.vuln_and_safe")
    if "sha256" in detail_l or "attestation" in detail_l or ("build" in detail_l and "unsupported" in state.lower()):
        return "not enabled: attestation failed or unsupported build — {}".format(detail[:120])
    if "version" in detail_l and "unsupported" in state.lower():
        return "not enabled: unsupported version — {}".format(detail[:120])
    if DISABLED in state:
        return "disabled: {}".format(detail[:120])
    if RESTRICTED in state:
        return "restricted: {}".format(detail[:120])
    if state:
        return "not enabled: {} — {}".format(state, detail[:100])
    return "not enabled: status unknown for profile {!r}".format(profile_id)


def format_tool_report(tool_status):
    """Return a list of one-line status strings for display in the assessment report."""
    lines = []
    for name, entry in tool_status.items():
        for pid, info in entry.get("profiles", {}).items():
            state = info.get("state", "unknown")
            mark = "✓" if state == READY else "✗"
            lines.append("{} {} [{}]: {}".format(mark, entry["display"], state,
                                                  info.get("detail", "")[:80]))
    return lines


def _capabilities_safe(adapter_name):
    """Import the named adapter module and call capabilities(); suppress all errors."""
    try:
        import importlib
        mod = importlib.import_module(adapter_name)
        return mod.capabilities()
    except ImportError:
        return {}
    except Exception as exc:
        return {"_error": {"state": UNSUPPORTED, "detail": str(exc)[:200]}}

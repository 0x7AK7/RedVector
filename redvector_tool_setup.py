"""Operator-facing native-tool discovery + guided install / fallback (TASK 1 & TASK 2).

Builds on the four-state runtime discovery in ``redvector_tool_registry`` (installed / capability
supported / integrity verified / execution ready) to report which supported native Kali tools are
present and usable, and — only for tools that are genuinely MISSING (not installed at all) — guides
the operator through:

  1. an explicit Yes/No install of the official apt package (``redvector_reviewed_install``), which
     requires a separate system-change approval and NEVER marks the tool authorized; or
  2. an honest internal RedVector fallback when one exists; or
  3. skipping the capability, with a stated coverage limitation.

Key safety properties, all preserved here:

  * An **installed-but-blocked** tool (present but capability/integrity not satisfied) is reported as
    such and is NEVER treated as "missing" or offered for apt install — installing again cannot fix a
    blocked/unverified build, and silently doing so would mask the real reason.
  * A successful install NEVER auto-authorizes the tool: discovery is re-run afterwards and the new
    state is reported honestly (installed, not yet verified).
  * The internal fallback is always clearly identified as the internal engine, never as the native
    tool, and normal target authorization is unchanged by any choice here.

The decision logic is pure and the interactive driver takes injected ``confirm`` / ``approve`` /
``discover`` / ``install`` callables, so the whole flow is unit-testable on any OS.
"""
import re
import redvector_tool_registry as registry
import redvector_reviewed_install as installer

# The reviewed native tools an operator may discover/install through this flow.
SUPPORTED = ("nmap", "nikto", "searchsploit", "nuclei")


def classify_state(record):
    """Map a four-state discovery record to one operator-facing status.

      * ``missing``            — not installed at all (install may be offered).
      * ``installed_blocked``  — present but required capabilities are not satisfied (NOT missing;
                                 install is never offered — the build is there but unusable/unverified).
      * ``installed``          — present and capability-supported (execution is verified separately).
    """
    if not record.get("installed"):
        return "missing"
    if record.get("capability_supported"):
        return "installed"
    return "installed_blocked"


def requested_tools(text):
    """Supported tools explicitly named in the instruction, else all supported tools."""
    lowered = str(text or "").lower()
    named = [name for name in SUPPORTED if re.search(r"(?<![a-z])" + re.escape(name) + r"(?![a-z])", lowered)]
    return named or list(SUPPORTED)


def status_line(tool, record, state):
    """One honest operator-facing status line for a discovered tool (no side effects)."""
    version = record.get("version") or "version-undetected"
    if state == "installed":
        return (tool + ": installed (" + version + ", capability supported) — execution is verified "
                "separately against the authorized target; not yet proven here.")
    if state == "installed_blocked":
        missing = [flag for flag, ok in (record.get("capabilities") or {}).items() if not ok]
        detail = ("missing required capability flag(s): " + ", ".join(missing)) if missing else \
                 "present but not capability-verified"
        return (tool + ": INSTALLED BUT BLOCKED — " + detail + ". Installed-but-blocked is not the "
                "same as missing; re-installing will not enable it, so no install is offered.")
    return tool + ": not installed."


def run_setup(text, *, confirm, approve, message, discover=None, install=None):
    """Interactive discovery + guided install/fallback. ``confirm(label)->bool`` asks the operator a
    Yes/No question, ``approve(operation)->bool`` is the strong system-change approval, and
    ``message(kind, line)`` prints an operator-facing line. ``discover`` / ``install`` default to the
    real modules and are injectable for testing. Returns a structured summary of what happened per
    tool (also useful for assertions); it performs no action without the operator's explicit Yes."""
    discover = discover or registry.discover
    install = install or installer.run_install
    outcomes = []
    for tool in requested_tools(text):
        record = discover(tool)
        state = classify_state(record)
        message("info", status_line(tool, record, state))
        if state != "missing":
            outcomes.append({"tool": tool, "state": state, "action": "none"})
            continue
        plan = installer.plan(tool)
        if not plan["installable"]:
            # e.g. nuclei: a reviewed build is required, apt is not an option.
            message("warning", tool + " is not installed and has no apt install path: " + plan["note"])
            action = _offer_fallback(tool, plan, confirm, message)
            outcomes.append({"tool": tool, "state": state, "action": action})
            continue
        if not confirm("The required tool " + tool + " is not installed. Would you like to install it?"):
            action = _offer_fallback(tool, plan, confirm, message)
            outcomes.append({"tool": tool, "state": state, "action": action})
            continue
        # Operator said yes to installing: show the exact package + action, then require the strong
        # system-change approval before anything is changed.
        message("info", "Official package: " + plan["package"] + "  |  action: " + plan["action"])
        operation = {"tool": "native package install", "package": plan["package"],
                     "action": plan["action"], "target": "local backend host",
                     "reason": ("Install the official Debian/Kali package for native " + tool +
                                ". Official package only; no third-party repositories or scripts. "
                                "The tool will NOT be authorized until capability/attestation is re-verified.")}
        if not approve(operation):
            message("warning", "Install not approved; " + tool + " was not changed.")
            outcomes.append({"tool": tool, "state": state, "action": "install_declined"})
            continue
        result = install(tool, approved=True)
        if result.get("execution_mode") != "A" or not result.get("success"):
            message("error", "Install did not complete: " + str(result.get("error") or
                     ("apt returned " + str(result.get("return_code")))) + ". " + tool + " is not authorized.")
            outcomes.append({"tool": tool, "state": state, "action": "install_failed", "result": result})
            continue
        # Re-discover: report the new state honestly. A successful install is 'installed', never
        # 'verified'/'authorized' — capability/attestation is re-checked by the normal profile flow.
        after = discover(tool)
        after_state = classify_state(after)
        message("success", tool + " installed via " + plan["package"] + ". " + status_line(tool, after, after_state))
        message("info", "Capability and integrity are re-checked by the normal reviewed-profile "
                        "attestation before this tool is authorized for any operation.")
        outcomes.append({"tool": tool, "state": state, "action": "installed", "after_state": after_state})
    return {"outcomes": outcomes}


def _offer_fallback(tool, plan, confirm, message):
    """Offer the internal RedVector alternative (if any); otherwise explain the coverage gap."""
    fb = plan.get("internal_fallback") or installer.fallback(tool)
    if fb:
        if confirm("Would you like to use the available RedVector internal alternative?"):
            message("info", "Using internal alternative — " + fb + " Target authorization is unchanged.")
            return "fallback_internal"
        message("warning", "Skipping native " + tool + ". Coverage limitation: the native "
                + tool + " capability will not be part of the assessment, and its internal alternative "
                "was declined.")
        return "skipped"
    message("warning", "Skipping native " + tool + ". Coverage limitation: no internal alternative "
            "exists for this capability, so it will not be part of the assessment.")
    return "skipped_no_fallback"

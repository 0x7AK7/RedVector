"""Natural-language-first interactive routing. Verifies that ordinary English maps deterministically
to the right operator action, that authorization is separated from a mere IP mention, and that no
user-facing guidance or error text advertises slash commands. 192.0.2.x / 192.168.5.130 here are
test inputs only — nothing is hardcoded in product code."""
import redvector_nl_router as nl


def test_natural_language_authorization_sets_scope_intent():
    for text, target in [
        ("Authorize 192.168.5.130 as my lab target.", "192.168.5.130"),
        ("I own 192.0.2.10, please register it.", "192.0.2.10"),
        ("I have permission to assess 192.0.2.7.", "192.0.2.7"),
        ("192.0.2.9 is my lab target.", "192.0.2.9"),
        ("Set the scope to 10.10.0.0/24.", "10.10.0.0/24"),
    ]:
        intent, payload = nl.classify(text)
        assert intent == "authorize", (text, intent)
        assert target in payload, (text, payload)


def test_mere_mention_of_ip_is_not_authorization():
    # a scan that names an address must NOT configure scope — it is a task for turn()/scope checks
    for text in ("Scan 192.0.2.5 for open TCP ports.",
                 "Scan my authorized target for open ports.",
                 "Discover open TCP ports and identify service versions.",
                 "Run native Nmap against 192.0.2.5."):
        assert nl.classify(text)[0] == "task", text


def test_authorization_without_target_asks():
    assert nl.classify("Authorize my lab machine.")[0] == "authorize_needs_target"


def test_show_scope_requests():
    for text in ("Show my authorized targets.", "What's my scope?", "List my authorized targets."):
        assert nl.classify(text)[0] == "show_scope", text


def test_status_requests():
    for text in ("Check RedVector system status.", "Is the backend up?", "Run a health check."):
        assert nl.classify(text)[0] == "status", text


def test_tools_requests_vs_help():
    for text in ("Show available security tools.", "What tools can scan web apps?", "List the scanners."):
        assert nl.classify(text)[0] == "tools", text
    assert nl.classify("What can RedVector do?")[0] == "help"       # capability help, not the tool list


def test_analyze_latest_results():
    for text in ("Analyze the latest scan results.", "Summarize the last assessment.", "Explain the recent findings."):
        assert nl.classify(text)[0] == "analyze", text


def test_raw_evidence_request():
    for text in ("Show the original Nmap evidence.", "Display the raw evidence."):
        assert nl.classify(text)[0] == "raw", text


def test_results_and_export_requests():
    assert nl.classify("Show my saved results.")[0] == "results"
    assert nl.classify("List evidence ids.") == ("results", "list")
    assert nl.classify("Export my latest report as JSON.")[0] == "export"


def test_navigation_and_help_without_slash():
    assert nl.classify("Return to the main menu.")[0] == "back"
    assert nl.classify("Switch the model.")[0] == "back"
    assert nl.classify("What can I ask you to do?")[0] == "help"


def test_deauthorize():
    assert nl.classify("Clear my scope.")[0] == "deauthorize"


def test_help_text_and_router_advertise_no_slash_commands():
    for token in ("/scope", "/status", "/tools", "/summary", "/results", "/raw", "/export", "/back", "/help"):
        assert token not in nl.HELP_TEXT


def test_natural_language_error_messages_have_no_slash():
    # the no-scope and out-of-scope messages the operator sees must be natural language, not "/scope"
    from redvector_ollama_policy import Policy
    from redvector_ollama_cli import assessment_context
    ok, target, clar = assessment_context("Scan my lab host for open ports.", Policy())
    assert clar and "No target has been authorized yet" in clar and "/scope" not in clar
    scoped = Policy(["192.0.2.1"])
    ok, target, clar = assessment_context("Scan 192.0.2.250 for open ports.", scoped)
    assert clar and "outside the operator-authorized scope" in clar and "/scope" not in clar


def test_empty_and_nonstring_are_tasks():
    assert nl.classify("") == ("task", None)
    assert nl.classify(None) == ("task", None)

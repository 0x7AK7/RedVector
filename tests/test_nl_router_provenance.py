"""Inc C: fixed intent precedence — requests about a PRIOR scan (provenance, discovered ports,
original evidence) never produce the tool catalog, and explicit no-scan instructions never route to
a scan. Covers the exact spec example. No target/version hardcoded."""
import redvector_nl_router as nl

# The real request that previously produced "REGISTERED MCP TOOLS / EXECUTION ELIGIBILITY".
_SPEC_EXAMPLE = ("Show the original native tool execution evidence for my latest scan. Identify which "
                 "tools actually ran, their execution status, the discovered open TCP ports and service "
                 "versions. Do not launch another scan.")


def test_spec_example_routes_to_provenance_not_tool_catalog():
    intent, _ = nl.classify(_SPEC_EXAMPLE)
    assert intent == "provenance"               # NOT "tools"
    assert nl.no_scan(_SPEC_EXAMPLE) is True     # the explicit no-scan instruction is detected


def test_required_intent_map():
    assert nl.classify("Show available security tools.")[0] == "tools"             # catalog
    assert nl.classify("Which tools actually ran?")[0] == "provenance"             # last-run provenance
    assert nl.classify("Show the discovered ports.")[0] == "ports"                 # saved scan results
    assert nl.classify("Show the original evidence.")[0] == "raw"                  # archived MCP evidence
    assert nl.classify("Analyze the latest results.")[0] == "analyze"              # no rescan
    assert nl.classify("Export my report.")[0] == "export"


def test_which_tools_ran_variants_are_provenance_not_catalog():
    for text in ("Which tools actually ran?", "What engines executed in the last scan?",
                 "Show the native tool execution evidence.", "Which scanners were run?"):
        assert nl.classify(text)[0] == "provenance", text


def test_tool_catalog_queries_still_resolve_to_tools():
    for text in ("Show available security tools.", "What tools can scan web apps?", "List the scanners."):
        assert nl.classify(text)[0] == "tools", text


def test_discovered_ports_request_is_results_not_scan():
    assert nl.classify("Show the discovered open TCP ports.")[0] == "ports"
    # a no-scan instruction attached to an evidence request still does not become a scan task
    assert nl.classify("Show the discovered ports; do not scan again.")[0] == "ports"


def test_no_scan_detection():
    for text in ("Do not launch another scan.", "don't run a new scan", "without scanning", "no new scan please"):
        assert nl.no_scan(text) is True
    assert nl.no_scan("Scan my authorized target.") is False

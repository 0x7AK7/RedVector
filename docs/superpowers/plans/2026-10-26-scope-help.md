# Scope extraction and interactive help
Continue clean branch 0x7AK7/ollama-mcp-integration at validated checkpoint.
No commit, push, README, backend, MCP registration, policy or Claude configuration changes.

Confirmed reproduction: secondary preposition regex extracts "them." from
"versions running on them." and rejects it as an unscoped hostname before model/MCP.
The same Policy object retains the correct snapshot; direct policy authorization
accepts the target. This is a CLI extraction bug, not lost scope.

Plan:
1. Add exact reproduction and consecutive-request tests (allowed/denied IPv4/IPv6,
   CIDR member hosts, exact pinned hostnames, unchanged scope and tool selection).
2. Recognize referential pronouns without treating unrelated explicit hosts as
   authorized. Canonicalize candidate addresses consistently with Policy.
   Explain disabled active version detection as execution policy, never scope denial.
3. Add one shared registry used by dispatcher, grouped /help, /help COMMAND,
   /help search TEXT, typo suggestions and command completion.
4. Keep natural language unchanged outside target extraction/restriction handling.
   Use existing Panel/Terminal, preserve red prompt, NO_COLOR and width behavior.
5. Offer GNU-readline completion only when a safe reversible tab binding can be
   established and no custom completer is already installed; otherwise retain input
   behavior and provide help search. No dependency installation.
6. Run Windows and native Kali regressions, real harmless MCP/loopback checks and
   actual PTY help/completion tests where available. Preserve prior evidence.

Completed: reproduction/root-cause trace, shared canonical scope interpretation, version-policy distinction, registry-driven help/search/suggestions, reversible native completion, review fixes and regressions. Windows398pass27skip; Kali422pass1skip. Native actual PTY and authenticated MCP328-tool/health/owned-loopback tests passed. External Claude configuration hash changed during validation; left untouched and documented. No commit/push/README changes. Report: docs/ollama-scope-help-validation.md.

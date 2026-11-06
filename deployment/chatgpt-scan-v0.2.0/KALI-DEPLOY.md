# Stage 5C — Controlled Kali deployment of RedVector Scan Plugin v0.2.0-dev

**No real scan in this stage. Hostname scanning stays disabled. No backend/Claude
changes. No manual cache edits. No git.** Run these on Kali and capture the output
as the deployment evidence. Replace every `<PLACEHOLDER>`. The API token is never
echoed. Steps are ordered; step 7 (install) is gated on step 1.

Bundle to transfer (produced on the build host):
- `redvector-scan-plugin-dev-0.2.0-dev.tar.gz`
- `SHA256SUMS`
- `kali_mcp_probe.py` (read-only verifier; performs no scan)

---

## 1. Verify ChatGPT Desktop version + supported plugin schema
```bash
# Identify the installed ChatGPT Desktop build (pick whichever applies):
#   GUI: ChatGPT > Settings/About  -> record the version string
# If installed from a package/AppImage, inspect its bundled metadata, e.g.:
ls -1 ~/.config/ChatGPT* 2>/dev/null; ls -1 /opt/ChatGPT* 2>/dev/null
# Confirm the local-plugin manifest schema your build supports is Agent Plugins 1.0.0
# (this package declares "$schema": .../1.0.0/plugin.schema.json and mcp.schema.json).
```
Record: installed version string, and that it supports local stdio MCP plugins
(Plugin Creator / personal marketplace). If it does not, STOP and report.

## 2. Transfer the verified package (approved method: scp)
```bash
mkdir -p ~/rv-scan-plugin-dev-pkg && cd ~/rv-scan-plugin-dev-pkg
# from the build host (adjust user@kali and path), OR copy from your USB/approved channel:
#   scp redvector-scan-plugin-dev-0.2.0-dev.tar.gz SHA256SUMS kali_mcp_probe.py <user>@<kali>:~/rv-scan-plugin-dev-pkg/
ls -l
```

## 3. Verify integrity with SHA-256 BEFORE install
```bash
cd ~/rv-scan-plugin-dev-pkg
tar -xzf redvector-scan-plugin-dev-0.2.0-dev.tar.gz
# Verify the 7 extracted package files against the manifest (stable, per-file):
grep 'redvector-scan-plugin-dev/' SHA256SUMS | sha256sum -c -
# Expect: each line "... OK". If any FAILED -> STOP, do not install.
```
Expected adapter digest:
`89f1938822397efdb58b7899bfd0243e35ff29ccfcf0e82161c4a4a4129462e1  redvector-scan-plugin-dev/adapter/redvector_scan_adapter.py`

## 4. Confirm backend connectivity + Nmap availability
```bash
export REDVECTOR_HOST=127.0.0.1
export REDVECTOR_PORT=<BACKEND_PORT>              # the real backend port; no default
curl -fsS "http://127.0.0.1:${REDVECTOR_PORT}/health" ; echo       # expect {"status":"healthy",...}
command -v nmap && nmap --version | head -n1                        # expect a path + version
```

## 5. Configure a NON-DEFAULT backend API token securely (never echoed)
```bash
# Enter the real backend token without printing it to the screen or history:
read -r -s -p "REDVECTOR_API_TOKEN: " REDVECTOR_API_TOKEN; echo; export REDVECTOR_API_TOKEN
# Safety checks that do NOT reveal the token:
[ -n "$REDVECTOR_API_TOKEN" ] && echo "token set: yes" || echo "token set: NO"
[ "$REDVECTOR_API_TOKEN" = "redvector-dev-token" ] && echo "REFUSE: dev-token in use" || echo "non-default token: ok"
```

## 6. Define and verify the explicitly approved scan scope (IP-only)
```bash
cat > ~/rv-scan-plugin-dev-pkg/scan_scope.conf <<'EOF'
# Approved IP-only lab scope for the initial test. Replace with YOUR authorized IPs.
<APPROVED_IP_OR_CIDR_1>
<APPROVED_IP_OR_CIDR_2>
EOF
export REDVECTOR_SCAN_SCOPE_FILE=~/rv-scan-plugin-dev-pkg/scan_scope.conf
# Hostname scanning stays OFF (do NOT set REDVECTOR_SCAN_ALLOW_HOSTNAMES).
sed -n '1,20p' "$REDVECTOR_SCAN_SCOPE_FILE"
```

## 7. Install ALONGSIDE v0.1.0 (supported plugin management; version-gated by step 1)
Use the SAME supported flow you used to install the v0.1.0 diagnostic plugin,
adding a NEW entry — never overwriting it. The dev plugin uses a distinct name
(`redvector-scan-plugin-dev`) and MCP server (`redvector-scan-dev`), so it cannot
collide with v0.1.0 (`redvector-diagnostic-plugin` / `redvector-diagnostics`).
```bash
# Place the plugin where your supported flow expects a local plugin, e.g. a
# dedicated dev directory, then register it as a NEW plugin via Plugin Creator /
# your personal marketplace (the mechanism your build from step 1 supports).
# Do NOT hand-edit the versioned plugin cache. Do NOT touch the v0.1.0 entry.
PLUGIN_ROOT=~/rv-scan-plugin-dev-pkg/redvector-scan-plugin-dev
python3 -m json.tool "$PLUGIN_ROOT/plugin.json" >/dev/null && echo "plugin.json valid"
python3 -m json.tool "$PLUGIN_ROOT/mcp.json"   >/dev/null && echo "mcp.json valid"
# Provide REDVECTOR_HOST/PORT/API_TOKEN/SCAN_SCOPE_FILE to the plugin via the
# plugin's environment configuration (not in any file in the package).
```

## 8. Confirm v0.1.0 is untouched
```bash
# Its adapter must still hash to the known-good value:
sha256sum <PATH_TO_INSTALLED_v0.1.0>/adapter/redvector_diag_adapter.py
# expect: 037614be0fea1790e437e2022ec551d6a9659015d35489c220850720e967446e
```

## 9–12. Verify discovery, diagnostics, scope rejection, scan tool presence (NO scan)
```bash
cd ~/rv-scan-plugin-dev-pkg
export REDVECTOR_HOST=127.0.0.1 REDVECTOR_PORT=<BACKEND_PORT>
python3 kali_mcp_probe.py redvector-scan-plugin-dev/adapter/redvector_scan_adapter.py
# Expect: "exactly 4 tools discovered", all 3 diagnostics operate (backend
# reachable: True), out-of-scope + unauthorized rejected with no-backend-request,
# hostname disabled (policy). "NO scan performed".
```
Then, in the ChatGPT Desktop UI (after it reloads plugins): confirm the dev plugin
lists exactly `backend_health`, `service_status`, `backend_version`, `scan_tcp_ports`,
and that v0.1.0 still lists its three tools.

## Rollback (supported operations only)
```bash
# Disable/remove ONLY the redvector-scan-plugin-dev entry through the same
# plugin-management UI used to add it; v0.1.0 remains the live diagnostic baseline.
# Do NOT delete plugin cache directories by hand. Do NOT touch unrelated plugins.
rm -rf ~/rv-scan-plugin-dev-pkg   # only the transferred dev files; never the installed v0.1.0
```

## STOP
Do not run `scan_tcp_ports` against any real target. The first IP-only lab scan
requires separate explicit approval.

"""Read-only VMware Kali evidence collector for RedVector native-engine review.

Prints one JSON document describing the installed native engines (nmap, nuclei, nikto, searchsploit):
resolved path, real path, SHA256, owning Debian package and version, `dpkg -V` integrity result and
the binary's own version banner, plus a read-only inventory of Nmap NSE scripts in the "vuln" and
"safe" categories for allowlist review. It performs NO network activity, runs no scan, changes no
configuration and writes nothing except to stdout. Usage (on Kali):

    python3 tools/collect_kali_evidence.py > kali-evidence.json
"""
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys

TOOLS = {"nmap": ["--version"], "nuclei": ["-version"], "nikto": ["-Version"], "searchsploit": None}


def _run(argv, timeout=30, limit=4000):
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return out.returncode, (out.stdout + out.stderr)[:limit]
    except (OSError, subprocess.SubprocessError) as exc:
        return None, str(exc)[:300]


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def tool_evidence(name, version_args):
    found = shutil.which(name)
    if not found:
        return {"installed": False}
    real = os.path.realpath(found)
    entry = {"installed": True, "path": found, "realpath": real, "sha256": _sha256(real)}
    code, owner = _run(["dpkg", "-S", real])
    package = owner.split(":", 1)[0].strip() if code == 0 and ":" in owner else ""
    entry["package"] = package or "not owned by a Debian package"
    if package:
        entry["package_version"] = _run(["dpkg-query", "-W", "-f=${Version}", package])[1].strip()
        code, text = _run(["dpkg", "-V", package])
        entry["dpkg_verify"] = "clean" if code == 0 and not text.strip() else ("modified: " + text.strip()[:500])
    if version_args:
        entry["version_banner"] = _run([real] + version_args)[1].strip()[:400]
    return entry


def nse_inventory():
    code, text = _run(["nmap", "--script-help", "vuln"], timeout=60, limit=4_000_000)
    scripts = []
    if code == 0:
        lines = text.splitlines()
        for index, line in enumerate(lines[1:], start=1):
            cats = re.match(r"Categories:\s*(.+)", line)
            name = lines[index - 1].strip()
            if cats and name:
                categories = sorted(c.strip() for c in cats.group(1).split())
                scripts.append({"script": name, "categories": categories,
                                "safe": "safe" in categories, "intrusive": "intrusive" in categories or "dos" in categories})
    return {"vuln_scripts": len(scripts), "vuln_and_safe": [s["script"] for s in scripts if s["safe"] and not s["intrusive"]],
            "scripts": scripts}


def main():
    doc = {"collector": "redvector collect_kali_evidence (read-only)", "platform": platform.platform(),
           "python": sys.version.split()[0], "tools": {n: tool_evidence(n, a) for n, a in TOOLS.items()},
           "nse": nse_inventory() if shutil.which("nmap") else {"vuln_scripts": 0}}
    json.dump(doc, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()

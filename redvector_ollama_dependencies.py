"""Check declared dependencies without importing the backend or starting processes."""
from importlib import metadata
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent

def dependency_issues(paths):
    from packaging.requirements import Requirement
    issues=[]
    for path in paths:
        for raw in Path(path).read_text(encoding="utf-8-sig").splitlines():
            line=raw.split("#",1)[0].strip()
            if not line:continue
            requirement=Requirement(line)
            if requirement.marker and not requirement.marker.evaluate():continue
            try:installed=metadata.version(requirement.name)
            except metadata.PackageNotFoundError:
                issues.append(f"Missing Python dependency: {requirement.name}")
                continue
            if installed not in requirement.specifier:
                issues.append(f"Incompatible Python dependency: {requirement.name} {installed}; required {requirement.specifier}")
    return issues

def main():
    try:
        issues=dependency_issues([ROOT/"requirements.txt",ROOT/"requirements-ollama.txt"])
        if not issues:
            from mcp import ClientSession,StdioServerParameters
            from mcp.client.stdio import stdio_client
            from mcp.server.fastmcp import FastMCP
            from jsonschema import Draft202012Validator
            for name in ("initialize","list_tools","call_tool"):
                if not callable(getattr(ClientSession,name,None)):
                    issues.append("MCP SDK lacks required client API: "+name)
        if issues:
            for issue in issues:print(issue,file=sys.stderr)
            return 1
        return 0
    except (ImportError,OSError,ValueError) as exc:
        print("Python dependencies are missing or incompatible: "+str(exc),file=sys.stderr)
        return 1

if __name__=="__main__":raise SystemExit(main())

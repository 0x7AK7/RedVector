"""Opt-in native Kali acceptance: actual Bash menus, real Ollama/model and MCP."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
RUNTIME=ROOT/".ollama-linux-env"/"ollama-native"/"runtime"
OUTPUT=ROOT/"docs"/"kali-uat"

@unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("REDVECTOR_RUN_KALI_UAT")=="1",
                     "Requires explicit native Kali acceptance runtime")
class KaliAcceptance(unittest.TestCase):
    def test_real_installer_launcher_restart_errors_and_native_model_loop(self):
        import psutil
        import requests
        from ollama_terminal_driver import TerminalSession
        from ollama_live_helpers import live_model_roundtrip
        from redvector_ollama_agent import bridge
        OUTPUT.mkdir(parents=True,exist_ok=True)
        started=time.time();sessions=[];owned={}
        self.assertTrue((RUNTIME/"bin"/"ollama").is_file())
        models=Path(os.environ.get("REDVECTOR_UAT_MODELS",Path.home()/".ollama"/"models"))
        manifest=models/"manifests"/"registry.ollama.ai"/"library"/"qwen3"/"8b"
        self.assertTrue(manifest.is_file(),"Reuse the existing approved model store; never pull")
        model_digest=hashlib.sha256(manifest.read_bytes()).hexdigest()
        manifests_before={str(p.relative_to(models)):hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in (models/"manifests").rglob("*") if p.is_file()}
        protected=["start_redvector.sh","redvector_server.py","redvector_mcp.py","redvector_banner.py",
                   "start_redvector.ps1","redvector-mcp.json","ollama-mcp.json",
                   "install_redvector_claude_mcp.sh","install_claude_desktop_kali.sh"]
        before={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in protected}
        with socket.socket() as probe:probe.bind(("127.0.0.1",0));port=probe.getsockname()[1]
        with socket.socket() as probe:probe.bind(("127.0.0.1",11434))
        work=ROOT/".ollama-linux-env"/("uat-"+str(int(started)))
        work.mkdir();bindir=work/"bin";bindir.mkdir()
        python=bindir/"python3"
        python.write_text('#!/bin/bash\nexec "'+sys.executable+'" "$@"\n',newline="\n");python.chmod(0o755)
        # Transparent observer: record the real daemon PID before exec/bind.
        # Every CLI operation still execs the unmodified official binary.
        pidfile=work/"ollama-pids.jsonl"
        recorder=work/"record-ollama.py"
        recorder.write_text(
            "import json,sys,psutil\nfrom pathlib import Path\n"
            "p=psutil.Process(int(sys.argv[1]))\n"
            "with Path(sys.argv[2]).open('a') as out: "
            "out.write(json.dumps({'pid':p.pid,'created':p.create_time()})+'\\n')\n")
        cli=bindir/"ollama"
        cli.write_text('#!/bin/bash\nset -e\nif [[ "$1" == serve ]]; then\n'
            '  "'+sys.executable+'" "'+str(recorder)+'" "$$" "'+str(pidfile)+'"\nfi\n'
            'exec "'+str(RUNTIME/"bin"/"ollama")+'" "$@"\n',newline="\n")
        cli.chmod(0o755)
        python_only=work/"python-only";python_only.mkdir()
        python_copy=python_only/"python3";python_copy.write_bytes(python.read_bytes());python_copy.chmod(0o755)
        env=dict(os.environ,PATH=str(bindir)+os.pathsep+str(RUNTIME/"bin")+os.pathsep+os.environ["PATH"],
                 XDG_CONFIG_HOME=str(work/"config"),OLLAMA_MODELS=str(models),
                 OLLAMA_HOST="127.0.0.1:11434",OLLAMA_NO_CLOUD="true",TERM="xterm-256color",
                 REDVECTOR_HOST="127.0.0.1",REDVECTOR_PORT=str(port),
                 REDVECTOR_LIVE_EVIDENCE=str(OUTPUT/"live-evidence.json"))
        env.pop("NO_COLOR",None)
        def start(script,name,custom=None):
            session=TerminalSession(["/bin/bash",str(ROOT/script)],custom or env,ROOT,OUTPUT,name)
            sessions.append(session);return session
        def menu(session):session.expect(r"Choose 1-6:")
        def choose_existing(session,name):
            session.expect(r"Choose 1-7:",timeout=120);session.send("5")
            session.expect(r"Choose an installed model number:")
            options=re.findall(r"(?m)^\s*([0-9]+)\. "+re.escape(name)+r"\s*$",
                               session.raw.decode("utf8",errors="replace"))
            self.assertTrue(options,"Selected installed model was not in the actual menu")
            session.send(options[-1])
            session.expect("Reusing installed model: "+re.escape(name))
        def identity(process,kind):
            args=process.cmdline()
            if kind=="ollama":
                return ((str(RUNTIME/"bin"/"ollama") in args or str(cli) in args) and "serve" in args)
            return (str(ROOT/"redvector_server.py") in args and "--port" in args
                    and args[args.index("--port")+1]==str(port))
        def listener(port_number):
            found={c.pid for c in psutil.net_connections(kind="tcp") if c.status=="LISTEN"
                   and c.laddr.port==port_number and c.pid}
            self.assertEqual(len(found),1)
            process=psutil.Process(found.pop())
            self.assertGreaterEqual(process.create_time(),started-1)
            self.assertTrue(identity(process,"ollama" if port_number==11434 else "backend"),
                            "The listener belongs to another executable; it will not be stopped")
            owned[process.pid]=process.create_time()
            return process.pid
        def stop_owned(pid):
            process=psutil.Process(pid)
            self.assertEqual(process.create_time(),owned[pid])
            self.assertTrue(identity(process,"ollama") or identity(process,"backend"))
            children=process.children(recursive=True)
            process.terminate()
            _,alive=psutil.wait_procs([process]+children,timeout=8)
            for child in alive:
                try:child.kill()
                except psutil.NoSuchProcess:pass
            psutil.wait_procs(alive,timeout=5)
            owned.pop(pid,None)
        try:
            installer=start("install_redvector_ollama.sh","01-installer")
            installer.expect("Ollama detected.")
            choose_existing(installer,"qwen3:8b")
            menu(installer)
            daemon=listener(11434)
            installer.send("3");installer.expect("Ollama: healthy");installer.expect("Selected model: qwen3:8b");menu(installer)
            installer.send("4");installer.expect("qwen3:8b");menu(installer)
            installer.send("2");installer.expect("Choose 1-7:");installer.send("4")
            installer.expect("Ollama model identifier:");installer.send("bad;id")
            installer.expect("Invalid model identifier");menu(installer)
            installer.send("5");installer.expect("Real MCP initialized: 328 discovered tools",timeout=150)
            installer.expect("Read-only MCP health invocation completed with real output.",timeout=40);menu(installer)
            backend=listener(port)
            installer.send("1");installer.expect("Loading and verifying qwen3:8b");installer.expect("Connected: qwen3:8b",timeout=480)
            installer.expect("redvector> ");installer.send("Call server_health once and summarize the actual status and exact version in one short sentence.")
            installer.expect("MCP RESULT:",timeout=480);installer.expect("ASSISTANT:",timeout=480)
            installer.expect("redvector> ",timeout=480)
            from ollama_terminal_driver import plain as terminal_plain
            summary=terminal_plain(installer.raw).split("ASSISTANT:")[-1]
            self.assertIn("healthy",summary.lower());self.assertIn("8.0.0",summary)
            installer.send("/scope");installer.expect("Enter explicitly authorized targets")
            installer.send("bad;id");installer.expect("Invalid authorized target scope.");installer.expect("redvector> ")
            installer.send("/back");menu(installer);installer.send("6");first=installer.finish()
            self.assertIn("\x1b[38;5;196m",installer.raw.decode("utf8"))
            self.assertIn("By Adam K.",first)
            self.assertEqual(listener(port),backend);self.assertEqual(listener(11434),daemon)

            launcher=start("start_redvector_ollama.sh","02-restart")
            menu(launcher);launcher.send("3");launcher.expect("Selected model: qwen3:8b");menu(launcher)
            launcher.send("2");choose_existing(launcher,"dolphin-llama3:8b")
            launcher.expect("tool calling is not advertised");menu(launcher)
            launcher.send("1");launcher.expect("does not advertise tool calling",timeout=30);menu(launcher)
            launcher.send("2");choose_existing(launcher,"qwen3:8b");menu(launcher)
            launcher.send("1");launcher.expect("Connected: qwen3:8b",timeout=480)
            launcher.expect("redvector> ");launcher.send("/status")
            launcher.expect(r'"status".*healthy',timeout=40);launcher.expect("redvector> ")
            launcher.send("/back");menu(launcher);launcher.send("6");launcher.finish()
            self.assertEqual(listener(port),backend);self.assertEqual(listener(11434),daemon)

            # Record a complete actual model/API/MCP transcript directly inside Kali.
            from unittest.mock import patch
            with patch.dict(os.environ,env):
                async def actual_loop():
                    async with bridge() as (session,catalog):
                        self.assertEqual(len(catalog),328)
                        return await live_model_roundtrip(session,catalog,"qwen3:8b")
                evidence=asyncio.run(actual_loop())
            self.assertTrue(evidence["returned_real_result_to_model"])

            plain_env=dict(env,NO_COLOR="1")
            plain=start("start_redvector_ollama.sh","03-no-color-exit",plain_env)
            menu(plain);plain.send("6");plain.finish()
            self.assertNotIn(b"\x1b",plain.raw)
            cancel=start("start_redvector_ollama.sh","04-eof-cancel")
            menu(cancel);os.write(cancel.master,b"\x04")
            cancel.expect("Cancelled safely.");cancel.finish()

            # Real unavailable-service status, followed by the missing-install decline path.
            stop_owned(daemon)
            unavailable=start("start_redvector_ollama.sh","05-service-unavailable")
            menu(unavailable);unavailable.send("3");unavailable.expect("Ollama: unavailable")
            menu(unavailable);unavailable.send("6");unavailable.finish()
            without_cli=dict(env,PATH=str(python_only)+os.pathsep+os.environ["PATH"])
            decline=start("install_redvector_ollama.sh","06-install-declined",without_cli)
            decline.expect("Install Ollama?");decline.expect("Choose 1-3:");decline.send("2")
            decline.expect("Installation skipped.");menu(decline);decline.send("6");decline.finish()

            manifest_after={str(p.relative_to(models)):hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in (models/"manifests").rglob("*") if p.is_file()}
            self.assertEqual(manifest_after,manifests_before,"No model download/update is allowed")
            for name,digest in before.items():self.assertEqual(hashlib.sha256((ROOT/name).read_bytes()).hexdigest(),digest)
            result={"model":"qwen3:8b","manifest_sha256":model_digest,"model_store_unchanged":True,
                    "native_kali_model_loop":True,"tool_count":328,"source_hashes_unchanged":True,
                    "checks":["real Bash installer","English/color terminal","installed-model selection",
                              "invalid identifier recovery","real MCP diagnostics","actual UI model tool loop",
                              "launcher restart and selected-model persistence","unsupported-model error",
                              "backend/service PID reuse","native Kali model/API/MCP transcript",
                              "NO_COLOR exit","EOF cancellation","unavailable service","declined installation"]}
            (OUTPUT/"acceptance.json").write_text(json.dumps(result,indent=2),encoding="utf8")
            print("KALI UAT PASS:",json.dumps(result),flush=True)
        finally:
            for session in sessions:
                try:session.close()
                except OSError:pass
            # Include launcher-created backend PIDs even when a failure occurs before bind.
            from test_ollama_linux_bridge import capture_started_backends
            owned.update(capture_started_backends(work,ROOT,port,started))
            if pidfile.exists():
                for line in pidfile.read_text().splitlines():
                    record=json.loads(line)
                    try:
                        process=psutil.Process(record["pid"])
                        if process.create_time()==record["created"] and identity(process,"ollama"):
                            owned[process.pid]=record["created"]
                    except (psutil.NoSuchProcess,psutil.AccessDenied):pass
            for pid in list(owned):
                try:stop_owned(pid)
                except psutil.NoSuchProcess:pass

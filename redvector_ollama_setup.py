#!/usr/bin/env python3
"""English-only local Ollama wizard. Existing RedVector integrations are untouched."""
import argparse
import asyncio
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
from redvector_ollama_storage import StorageInfo, StorageError, detect_storage, filesystem_path, model_path

# Keep shared exception identities when the wizard is executed as a script.
if __name__ == "__main__":
    sys.modules.setdefault("redvector_ollama_setup", sys.modules[__name__])

ROOT = Path(__file__).resolve().parent
PRESETS = [
    ("Qwen3 8B", "qwen3:8b", 5.2, "Tool Calling"),
    ("Qwen3-Coder 30B", "qwen3-coder:30b", 19.0, "Agentic coding"),
    ("GPT-OSS 20B", "gpt-oss:20b", 14.0, "Reasoning and analysis"),
]
INSTALL_URL = "https://ollama.com/install.sh"

class SetupError(RuntimeError):
    pass

def model_id(value):
    if not isinstance(value,str) or len(value)>160 or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]*(?:/[A-Za-z0-9][A-Za-z0-9_.-]*)?(?::[A-Za-z0-9][A-Za-z0-9_.-]*)?",value):
        raise SetupError("Invalid model identifier. Use name:tag or namespace/name:tag.")
    return value

def config_path():
    return Path(os.environ.get("XDG_CONFIG_HOME",Path.home()/".config"))/"redvector-ollama"/"config.json"

def load_model(path=None):
    path=Path(path) if path else config_path()
    if not path.exists():return None
    try:return model_id(json.loads(path.read_text(encoding="utf8"))["model"])
    except (OSError,ValueError,KeyError,TypeError) as exc:
        raise SetupError("Invalid Ollama configuration; choose a model again.") from exc

def save_model(model,path=None):
    model_id(model)
    path=Path(path) if path else config_path()
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,temp=tempfile.mkstemp(prefix=".model-",dir=path.parent)
    try:
        with os.fdopen(fd,"w",encoding="utf8") as out:
            json.dump({"model":model},out);out.write("\n");out.flush();os.fsync(out.fileno())
        os.chmod(temp,0o600)
        os.replace(temp,path)
    finally:
        if os.path.exists(temp):os.unlink(temp)

def plain(value):
    value=re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|$))","",str(value))
    return "".join(c for c in value if c in "\n\t" or (ord(c)>=32 and not 127<=ord(c)<=159))

class Terminal:
    def __init__(self,stream=None):
        self.stream=stream or sys.stdout
        self.color=bool(self.stream.isatty() and os.environ.get("TERM","") not in ("","dumb") and "NO_COLOR" not in os.environ)
    def write(self,value=""):print(value,file=self.stream,flush=True)
    def message(self,kind,text):
        colors={"success":"92","warning":"33","error":"91","info":"38;5;196"}
        value=plain(text)
        self.write(("\033["+colors.get(kind,"0")+"m"+value+"\033[0m") if self.color else value)
    def box(self,title,lines):
        self.message("info","+"+"-"*70+"+")
        self.message("info","| "+title)
        self.message("info","+"+"-"*70+"+")
        for line in lines:self.write("  "+plain(line))
        self.message("info","+"+"-"*70+"+")
    def banner(self):
        from redvector_banner import render_banner
        artwork=render_banner()
        self.write(artwork if self.color else plain(artwork))
        self.box("LOCAL OLLAMA / MCP",["Local models. Existing RedVector backend. Verified tool responses."])

@contextmanager
def local_lock(name):
    import fcntl
    directory=config_path().parent
    directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    with open(directory/name,"a",encoding="utf8") as handle:
        os.chmod(handle.name,0o600)
        try:fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:raise SetupError("Another startup is in progress. Retry shortly.") from exc
        try:yield
        finally:fcntl.flock(handle,fcntl.LOCK_UN)

class Ollama:
    def __init__(self,url=None):
        from requests import Session
        url=url if url is not None else os.environ.get("OLLAMA_HOST","http://127.0.0.1:11434")
        if "://" not in url:url="http://"+url
        parsed=urlsplit(url)
        try:port=11434 if parsed.port is None else parsed.port
        except ValueError as exc:raise SetupError("Invalid local Ollama port.") from exc
        if (parsed.scheme!="http" or parsed.hostname not in {"127.0.0.1","localhost","::1"}
            or parsed.username or parsed.password or parsed.path not in ("","/")
            or parsed.query or parsed.fragment or not 1<=port<=65535):
            raise SetupError("Remote or non-local Ollama endpoints are disabled. Use a plain local HTTP endpoint; remote disk space cannot be checked here.")
        self.host="::1" if parsed.hostname=="::1" else "127.0.0.1"
        self.port=port
        self.url=f"http://{'[::1]' if self.host=='::1' else self.host}:{port}"
        self.session=Session();self.session.trust_env=False
        self.owned_models_path=None
        self.model_metadata={}
    def request(self,path,payload=None,timeout=15):
        from requests import RequestException
        try:
            with self.session.request("POST" if payload is not None else "GET",self.url+path,
                    json=payload,timeout=(3,timeout),allow_redirects=False,stream=True) as response:
                if response.status_code!=200:raise SetupError(f"Ollama {path}: HTTP {response.status_code}.")
                body=bytearray()
                for chunk in response.iter_content(8192):
                    body.extend(chunk)
                    if len(body)>2_000_000:raise SetupError("Ollama response exceeded the safety limit.")
                data=json.loads(body)
                if not isinstance(data,dict) or data.get("error"):raise SetupError("Ollama returned an invalid response or error.")
                return data
        except (RequestException,ValueError) as exc:raise SetupError(f"Ollama {path} is unavailable or returned invalid JSON.") from exc
    def healthy(self):
        try:return isinstance(self.request("/api/version").get("version"),str)
        except SetupError:return False
    def models(self):
        data=self.request("/api/tags").get("models")
        if not isinstance(data,list):raise SetupError("Ollama returned an invalid model list.")
        return data
    def show(self,model):
        model=model_id(model)
        data=self.request("/api/show",{"model":model})
        self.model_metadata[model]=data
        return data
    def chat_payload(self,model,messages,tools):
        model=model_id(model)
        payload={"model":model,"messages":messages,"tools":tools,"stream":False,
                 "options":{"temperature":0,"num_predict":2048}}
        thinking=self.model_metadata.get(model,{}).get("thinking",{})
        values=thinking.get("values",[]) if isinstance(thinking,dict) else []
        if any(value is False for value in values):
            payload["think"]=False
        return payload
    def chat(self,model,messages,tools):
        data=self.request("/api/chat",self.chat_payload(model,messages,tools),timeout=300)
        message=data.get("message")
        if not isinstance(message,dict) or message.get("role")!="assistant":raise SetupError("Ollama returned an invalid assistant message.")
        return message
    async def async_request(self,path,payload=None,timeout=15):
        import httpx
        async def fetch():
            async with httpx.AsyncClient(trust_env=False,follow_redirects=False,
                                         timeout=httpx.Timeout(timeout,connect=3)) as client:
                async with client.stream("POST" if payload is not None else "GET",
                                         self.url+path,json=payload) as response:
                    if response.status_code!=200:
                        raise SetupError(f"Ollama {path}: HTTP {response.status_code}.")
                    body=bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body)>2_000_000:raise SetupError("Ollama response exceeded the safety limit.")
                    data=json.loads(body)
                    if not isinstance(data,dict) or data.get("error"):
                        raise SetupError("Ollama returned an invalid response or error.")
                    return data
        try:return await asyncio.wait_for(fetch(),timeout=timeout)
        except (httpx.HTTPError,ValueError,asyncio.TimeoutError) as exc:
            raise SetupError(f"Ollama {path} is unavailable, timed out or returned invalid JSON.") from exc
    async def async_show(self,model):
        model=model_id(model)
        data=await self.async_request("/api/show",{"model":model})
        self.model_metadata[model]=data
        return data
    async def async_chat(self,model,messages,tools):
        data=await self.async_request("/api/chat",self.chat_payload(model,messages,tools),timeout=300)
        message=data.get("message")
        if not isinstance(message,dict) or message.get("role")!="assistant":
            raise SetupError("Ollama returned an invalid assistant message.")
        return message
    def pull(self,model):
        command=shutil.which("ollama")
        if not command:raise SetupError("The Ollama CLI is required for native download progress.")
        result=subprocess.run([command,"pull",model_id(model)],env=dict(os.environ,OLLAMA_HOST=self.url),check=False)
        if result.returncode:raise SetupError("Model download failed or was cancelled. Retry to resume.")
    def ensure_service(self):
        if self.healthy():return
        try:
            with socket.create_connection((self.host,self.port),timeout=1):
                raise SetupError("The local Ollama port is occupied but unhealthy. No process was stopped.")
        except (ConnectionRefusedError,TimeoutError,OSError):pass
        if sys.platform!="linux":raise SetupError("Start the local Ollama service manually, then retry.")
        with local_lock("ollama-start.lock"):
            if self.healthy():return
            try:
                with socket.create_connection((self.host,self.port),timeout=1):
                    raise SetupError("Ollama port is occupied but unhealthy.")
            except (ConnectionRefusedError,TimeoutError,OSError):pass
            command=shutil.which("ollama")
            if not command:raise SetupError("Ollama is not installed.")
            try:self.owned_models_path=model_path(dict(os.environ,HOME=os.environ.get("HOME") or str(Path.home())),os.getcwd())
            except StorageError as exc:raise SetupError("Cannot determine the new service model directory: "+str(exc)) from exc
            env=dict(os.environ,OLLAMA_HOST=self.url,OLLAMA_MODELS=str(self.owned_models_path))
            log=config_path().parent/"ollama-service.log"
            with open(log,"ab") as output:
                os.chmod(log,0o600)
                child=subprocess.Popen([command,"serve"],env=env,stdin=subprocess.DEVNULL,stdout=output,
                                       stderr=subprocess.STDOUT,start_new_session=True)
            try:
                for _ in range(30):
                    if child.poll() is not None:break
                    if self.healthy():return
                    time.sleep(1)
                raise SetupError(f"Ollama did not become healthy. Check {log}.")
            except BaseException:
                if child.poll() is None:
                    child.terminate()
                    try:child.wait(timeout=5)
                    except subprocess.TimeoutExpired:child.kill();child.wait()
                raise
    def manifest_size(self,model):
        import requests
        name=model_id(model)
        repository,_,tag=name.partition(":")
        if "/" not in repository:repository="library/"+repository
        try:
            with requests.get("https://registry.ollama.ai/v2/"+repository+"/manifests/"+(tag or "latest"),
                headers={"Accept":"application/vnd.docker.distribution.manifest.v2+json"},
                timeout=10,allow_redirects=False,stream=True) as response:
                if response.status_code!=200:return None
                body=bytearray()
                for chunk in response.iter_content(8192):
                    body.extend(chunk)
                    if len(body)>2_000_000:return None
                data=json.loads(body)
                sizes=[item["size"] for item in data.get("layers",[])]
                if not sizes or not all(isinstance(n,int) and not isinstance(n,bool) and n>0 for n in sizes):return None
                return sum(sizes)
        except (requests.RequestException,ValueError,KeyError,TypeError):return None

class Wizard:
    def __init__(self,api=None,terminal=None,read=None):
        self.api=api or Ollama()
        self.term=terminal or Terminal()
        self.read=read or input
    def ask(self,label):
        self.term.write(label)
        try:return self.read().strip()
        except (EOFError,KeyboardInterrupt,StopIteration):
            self.term.message("warning","Cancelled safely. Partial Ollama downloads can be resumed.")
            raise SystemExit(0)
    def confirm(self,label):return self.ask(label+" [y/N]").lower()=="y"
    def install_ollama(self):
        if shutil.which("ollama") or self.api.healthy():
            self.term.message("success","Ollama detected.");return True
        self.term.box("STEP 1 / OLLAMA INSTALLATION",["Install Ollama?","1. Yes, install Ollama","2. No, skip","3. Exit installer"])
        choice=self.ask("Choose 1-3:")
        if choice=="2":return False
        if choice=="3":raise SystemExit(0)
        if choice!="1":raise SetupError("Choose 1, 2 or 3.")
        if sys.platform!="linux":raise SetupError("The automatic installer supports Linux only.")
        curl=shutil.which("curl")
        if not curl:raise SetupError("Install curl using your system package manager, then retry.")
        self.term.message("warning",f"Official source: {INSTALL_URL}. This script may request sudo and configure a system service.")
        with tempfile.TemporaryDirectory(prefix="redvector-ollama-") as directory:
            path=Path(directory)/"install.sh"
            result=subprocess.run([curl,"--proto","=https","--tlsv1.2","--fail","--show-error","--progress-bar",
                "--max-time","120","--output",str(path),INSTALL_URL],check=False)
            if result.returncode or not path.exists() or path.stat().st_size==0:raise SetupError("Official installer download failed.")
            content=path.read_bytes()
            self.term.write(f"Downloaded: {path}\nSHA256: {hashlib.sha256(content).hexdigest()}")
            self.term.message("warning","Review this file before executing it. Its hash identifies the download; it is not a signature.")
            if self.confirm("Display the downloaded installer?"):self.term.write(plain(content.decode("utf8",errors="replace")))
            if self.ask("Type INSTALL to execute this downloaded official script, or anything else to cancel:")!="INSTALL":return False
            if subprocess.run(["/bin/bash",str(path)],check=False).returncode:raise SetupError("Ollama installation failed. Review the error and retry.")
        if not shutil.which("ollama"):raise SetupError("Installation completed but Ollama is not on PATH.")
        return True

    def storage_path(self):
        info=detect_storage(self.api.host,self.api.port)
        if info.path is None:
            self.term.message("warning","Automatic model storage detection: "+info.reason)
            if not info.manual_allowed:raise SetupError(info.reason)
            raw=self.ask("Enter the actual local Ollama service model directory (blank cancels):")
            if not raw:raise SetupError("Model storage check cancelled. No download was started.")
            info=StorageInfo(Path(raw),"operator-specified local service directory")
        self.term.write("Ollama model directory: "+str(info.path)+" ("+info.source+")")
        try:return filesystem_path(info)
        except StorageError as exc:raise SetupError(str(exc)) from exc

    def resource_budget(self,model,approx_gb=None):
        import psutil
        size=self.api.manifest_size(model)
        if size:self.term.write(f"Official manifest download: approximately {size/1e9:.2f} GB.")
        else:
            if approx_gb:self.term.write(f"Catalog estimate: approximately {approx_gb:g} GB; exact size is unavailable.")
            self.term.message("warning","Reliable size metadata is unavailable. Choose a conservative storage budget.")
            try:
                gb=float(self.ask("Maximum expected download size in GB (blank cancels):"))
                if not math.isfinite(gb) or gb<=0:raise ValueError()
                size=int(gb*1e9)
                if approx_gb and size<int(approx_gb*1e9):raise SetupError("Budget is below the catalog estimate.")
            except (ValueError,OverflowError) as exc:raise SetupError("A positive storage budget is required.") from exc
        path=self.storage_path()
        try:free=shutil.disk_usage(path).free
        except OSError as exc:raise SetupError("Cannot access model filesystem free space; no download was started.") from exc
        required=int(size*1.15)+1_000_000_000
        self.term.write(f"Storage filesystem: {path}\nFree: {free/1e9:.1f} GB | Required with headroom: {required/1e9:.1f} GB")
        if free<required:raise SetupError("Insufficient storage. No download was started.")
        ram=psutil.virtual_memory()
        self.term.write(f"RAM: {ram.total/1e9:.1f} GB total, {ram.available/1e9:.1f} GB available.")
        if ram.available<size:
            self.term.message("warning","Available RAM is below the model download size; verify GPU offloading/swap and expect memory pressure.")
        gpu=shutil.which("nvidia-smi")
        if gpu:
            try:
                result=subprocess.run([gpu,"--query-gpu=name,memory.total","--format=csv,noheader"],
                    capture_output=True,text=True,timeout=5,check=False)
                self.term.write("NVIDIA GPU: "+plain(result.stdout[:2000]) if result.returncode==0 else "GPU resource detection unavailable.")
            except (OSError,subprocess.TimeoutExpired):self.term.write("GPU resource detection unavailable.")
        else:self.term.write("GPU resources unavailable to detection. Ollama may use CPU, AMD or another supported runtime.")
        self.term.message("warning","Download size is not a guaranteed RAM/VRAM requirement; context and runtime overhead need extra memory.")
        if not self.confirm("Proceed with this model download?"):raise SetupError("Download cancelled before it started.")

    def select_model(self):
        self.term.box("STEP 2 / MODEL SELECTION",
            [f"{i}. {label} | Approx. {size:g} GB | {purpose}" for i,(label,_,size,purpose) in enumerate(PRESETS,1)]
            +["4. Choose your own model","5. Use an already installed model","6. Back","7. Exit"])
        choice=self.ask("Choose 1-7:")
        if choice=="6":return None
        if choice=="7":raise SystemExit(0)
        models=self.api.models()
        approx=None
        if choice in ("1","2","3"):_,model,approx,_=PRESETS[int(choice)-1]
        elif choice=="4":model=model_id(self.ask("Ollama model identifier:"))
        elif choice=="5":
            if not models:raise SetupError("No local models are installed.")
            for i,item in enumerate(models,1):self.term.write(f"{i}. {plain(item.get('name','unknown'))}")
            index=self.ask("Choose an installed model number:")
            if not index.isdecimal() or not 1<=int(index)<=len(models):raise SetupError("Invalid model selection.")
            model=model_id(models[int(index)-1]["name"])
        else:raise SetupError("Choose a numbered model option.")
        normalized=model if ":" in model else model+":latest"
        if not any(item.get("name")==normalized for item in models):
            self.resource_budget(model,approx)
            self.api.pull(model)
        else:self.term.message("success",f"Reusing installed model: {model}")
        metadata=self.api.show(model)
        if isinstance(metadata,dict) and "tools" not in metadata.get("capabilities",[]):
            self.term.message("warning","Model verified locally, but tool calling is not advertised. Agent mode will remain disabled for this model.")
        return model

    def status(self,model):
        self.term.box("SYSTEM STATUS",[f"Ollama endpoint: {self.api.url}",
            f"Ollama: {'healthy' if self.api.healthy() else 'unavailable'}",
            f"Selected model: {model or 'none'}","MCP tool count: run Test MCP connection for live discovery."])

    def run(self,install=False):
        self.term.banner()
        model=None
        try:model=load_model()
        except SetupError as exc:self.term.message("warning",str(exc))
        if install:
            while True:
                try:
                    if not self.install_ollama():
                        self.term.message("warning","Installation skipped. Returning to startup menu.");break
                    self.api.ensure_service()
                    selected=self.select_model()
                    if selected:save_model(selected);model=selected
                    break
                except SetupError as exc:
                    self.term.message("error",str(exc))
                    if not self.confirm("Retry installation/model selection?"):break
        while True:
            self.term.box("REDVECTOR AI / STARTUP",[
                "1. Start RedVector AI with selected model","2. Change AI model","3. Check system status",
                "4. List installed models","5. Test MCP connection","6. Exit"])
            choice=self.ask("Choose 1-6:")
            try:
                if choice=="6":return
                if choice=="3":self.status(model);continue
                if choice=="5":
                    from redvector_ollama_agent import connection_test
                    asyncio.run(connection_test(self.term));continue
                self.api.ensure_service()
                if choice=="4":
                    for item in self.api.models():self.term.write(plain(item.get("name","unknown")))
                elif choice=="2":
                    selected=self.select_model()
                    if selected:save_model(selected);model=selected
                elif choice=="1":
                    if not model:
                        model=self.select_model()
                        if not model:continue
                        save_model(model)
                    self.api.show(model)
                    from redvector_ollama_agent import interactive
                    asyncio.run(interactive(self.api,model,self))
                else:self.term.message("warning","Choose a numbered startup option.")
            except (SetupError,ValueError,OSError) as exc:self.term.message("error",str(exc))
            except KeyboardInterrupt:self.term.message("warning","Session cancelled. Returning to startup menu.")

def main():
    parser=argparse.ArgumentParser(description="Automatic local RedVector Ollama integration")
    parser.add_argument("--install",action="store_true")
    args=parser.parse_args()
    if not sys.platform.startswith("linux"):
        print("Run this installer inside Kali, Debian or Ubuntu Linux.",file=sys.stderr);return 1
    try:Wizard().run(install=args.install);return 0
    except (KeyboardInterrupt,EOFError):
        print("\nCancelled safely. Existing configurations are unchanged.");return 0
    except (SetupError,OSError,ImportError) as exc:
        print("Error: "+plain(exc),file=sys.stderr);return 1

if __name__=="__main__":raise SystemExit(main())

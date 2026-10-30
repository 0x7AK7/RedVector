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
from redvector_ollama_results import ResultsStore
from redvector_ollama_models import canonical_model, model_id_value, inspect_model, registry_metadata, api_capabilities
from redvector_ollama_storage import StorageInfo, StorageError, detect_storage, filesystem_path, model_path
from redvector_ollama_capacity import CapacityAssessment, current_identity, probe_storage, service_probe_command

# Keep shared exception identities when the wizard is executed as a script.
if __name__ == "__main__":
    sys.modules.setdefault("redvector_ollama_setup", sys.modules[__name__])

ROOT = Path(__file__).resolve().parent
PRESETS = [
    ("Qwen3 8B", "qwen3:8b", 5.2, "Tool Calling"),
    ("Qwen3-Coder 30B", "qwen3-coder:30b", 19.0, "Agentic Coding"),
    ("GPT-OSS 20B", "gpt-oss:20b", 14.0, "Reasoning"),
]
INSTALL_URL = "https://ollama.com/install.sh"

class SetupError(RuntimeError):
    pass

class OllamaFailure(SetupError):
    category="model-error"

class OllamaTimeout(OllamaFailure):
    category="timeout"

class OllamaContextError(OllamaFailure):
    category="context-overflow"

class OllamaHTTPError(OllamaFailure):
    category="http-error"

class OllamaConnectionError(OllamaFailure):
    category="connection-error"

class OllamaProtocolError(OllamaFailure):
    category="invalid-response"

def inference_setting(name,default,low,high):
    raw=os.environ.get(name,str(default))
    if not raw.isdecimal() or not low<=int(raw)<=high:
        raise SetupError(f"{name} must be an integer between {low} and {high}.")
    return int(raw)

def ollama_response(path,status,body):
    try:data=json.loads(body)
    except (ValueError,UnicodeError) as exc:
        if status!=200:
            error=OllamaHTTPError(f"Ollama {path}: HTTP {status}.");error.http_status=status
            raise error from exc
        raise OllamaProtocolError("Ollama returned invalid JSON.") from exc
    error=data.get("error") if isinstance(data,dict) else None
    if isinstance(error,str) and re.search(r"(?i)context.*(?:exceed|length|window|limit|full)|(?:exceed|too long).*context",error):
        raise OllamaContextError("Ollama rejected the request because its context window was exceeded.")
    if status!=200:
        error=OllamaHTTPError(f"Ollama {path}: HTTP {status}.");error.http_status=status
        raise error
    if error:raise OllamaFailure("Ollama returned a model error; inspect private diagnostics.")
    if not isinstance(data,dict):raise OllamaProtocolError("Ollama returned an invalid response object.")
    return data

class DownloadCancelled(SetupError):
    pass

def model_id(value):
    try:return model_id_value(value)
    except ValueError as exc:raise SetupError(str(exc)) from exc


def config_path():
    configured=os.environ.get("XDG_CONFIG_HOME")
    if configured:return Path(configured)/"redvector-ollama"/"config.json"
    home=os.environ.get("HOME") or current_identity().home
    if not home:raise SetupError("Current home is unavailable. Set an absolute XDG_CONFIG_HOME; no home directory was guessed.")
    return Path(home)/".config"/"redvector-ollama"/"config.json"

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
    def prompt(self,readline=False):
        if not self.color or not sys.stdin.isatty():return "redvector> "
        start="\033[1;91m";reset="\033[0m"
        if readline:start="\001"+start+"\002";reset="\001"+reset+"\002"
        return start+"redvector>"+reset+" "
    def message(self,kind,text):
        # Dark-terminal severity palette: green success, red critical/error, orange high, yellow
        # medium/warning, cyan informational/low, gray secondary. Colors convey evidence confidence,
        # not only a CVSS label. NO_COLOR / non-TTY output stays plain (self.color gate below).
        colors={"success":"92","warning":"33","error":"91","info":"36",
                "critical":"91","high":"38;5;208","medium":"33","low":"36","meta":"38;5;245"}
        value=plain(text)
        self.write(("\033["+colors.get(kind,"0")+"m"+value+"\033[0m") if self.color else value)
    def box(self,title,lines):
        from redvector_ollama_panels import Panel
        Panel(self).section(title,lines)
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
        url=(url if url is not None else os.environ.get("OLLAMA_HOST","")).strip() or "http://127.0.0.1:11434"
        if "://" not in url:
            if url in ("::","::1"):url="http://["+url+"]"
            elif url.startswith(":") and url.count(":")==1:url="http://127.0.0.1"+url
            else:url="http://"+url
        try:
            parsed=urlsplit(url)
            port=11434 if parsed.port is None else parsed.port
        except ValueError as exc:raise SetupError("Invalid local Ollama endpoint or port.") from exc
        if (parsed.scheme!="http" or parsed.hostname not in {"127.0.0.1","localhost","::1","0.0.0.0","::"}
            or parsed.username or parsed.password or parsed.path not in ("","/")
            or parsed.query or parsed.fragment or not 1<=port<=65535):
            raise SetupError("Remote or non-local Ollama endpoints are disabled. Use a plain local HTTP endpoint; remote disk space cannot be checked here.")
        self.host="::1" if parsed.hostname in ("::1","::") else "127.0.0.1"
        self.port=port
        self.url=f"http://{'[::1]' if self.host=='::1' else self.host}:{port}"
        self.session=Session();self.session.trust_env=False
        self.owned_models_path=None
        self.model_metadata={}
        self.registry_metadata={}
    def request(self,path,payload=None,timeout=15):
        from requests import RequestException
        try:
            with self.session.request("POST" if payload is not None else "GET",self.url+path,
                    json=payload,timeout=(3,timeout),allow_redirects=False,stream=True) as response:
                body=bytearray()
                for chunk in response.iter_content(8192):
                    body.extend(chunk)
                    if len(body)>2_000_000:raise SetupError("Ollama response exceeded the safety limit.")
                return ollama_response(path,response.status_code,body)
        except __import__("requests").Timeout as exc:raise OllamaTimeout("Ollama response deadline exceeded.") from exc
        except RequestException as exc:raise OllamaConnectionError("Ollama connection failed.") from exc
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
    def chat_timeout(self):
        return inference_setting("REDVECTOR_OLLAMA_TIMEOUT",600,1,3600)
    def context_limit(self):
        return inference_setting("REDVECTOR_OLLAMA_CONTEXT",4096,1024,32768)
    def chat_payload(self,model,messages,tools):
        model=model_id(model)
        payload={"model":model,"messages":messages,"tools":tools,"stream":False,
                 "options":{"temperature":0,"num_ctx":self.context_limit(),
                            "num_predict":inference_setting("REDVECTOR_OLLAMA_PREDICT",512,64,min(2048,self.context_limit()//2))}}
        thinking=self.model_metadata.get(model,{}).get("thinking",{})
        values=thinking.get("values",[]) if isinstance(thinking,dict) else []
        if any(value is False for value in values):
            payload["think"]=False
        return payload
    def chat(self,model,messages,tools):
        data=self.request("/api/chat",self.chat_payload(model,messages,tools),timeout=self.chat_timeout())
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
                    body=bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body)>2_000_000:raise SetupError("Ollama response exceeded the safety limit.")
                    return ollama_response(path,response.status_code,body)
        try:return await asyncio.wait_for(fetch(),timeout=timeout)
        except (httpx.TimeoutException,asyncio.TimeoutError) as exc:
            error=OllamaTimeout("Ollama response deadline exceeded.")
            error.timeout_stage=("connect" if isinstance(exc,httpx.ConnectTimeout) else
                                 "read" if isinstance(exc,httpx.ReadTimeout) else
                                 "write" if isinstance(exc,httpx.WriteTimeout) else
                                 "pool" if isinstance(exc,httpx.PoolTimeout) else "total-deadline")
            raise error from exc
        except httpx.HTTPError as exc:
            raise OllamaConnectionError("Ollama connection failed.") from exc
    async def async_show(self,model):
        model=model_id(model)
        data=await self.async_request("/api/show",{"model":model})
        self.model_metadata[model]=data
        return data
    async def async_chat(self,model,messages,tools,response_schema=None):
        started=time.monotonic()
        payload=self.chat_payload(model,messages,tools)
        if response_schema is not None:
            if tools or not isinstance(response_schema,dict) or len(json.dumps(response_schema))>16000:
                raise SetupError("Saved-analysis schema requires a bounded object and no tools.")
            payload["format"]=response_schema
        metrics={"prompt_bytes":len(json.dumps(messages,ensure_ascii=True).encode()),
                 "context_limit":payload["options"]["num_ctx"],"response_limit":payload["options"]["num_predict"],
                 "timeout_seconds":self.chat_timeout()}
        try:
            data=await self.async_request("/api/chat",payload,timeout=metrics["timeout_seconds"])
            message=data.get("message")
            if not isinstance(message,dict) or message.get("role")!="assistant":
                raise OllamaProtocolError("Ollama returned an invalid assistant message.")
            for key in ("prompt_eval_count","eval_count","total_duration","load_duration","eval_duration"):
                if type(data.get(key)) is int:metrics[key]=data[key]
            self.last_chat_metrics=dict(metrics,elapsed_seconds=round(time.monotonic()-started,3))
            if data.get("done_reason")=="length":
                error=OllamaFailure("Ollama exhausted the configured response-token limit.")
                error.category="response-limit"
                raise error
            return message
        except Exception as exc:
            from redvector_ollama_errors import record_error
            metrics["elapsed_seconds"]=round(time.monotonic()-started,3)
            for key,value in metrics.items():setattr(exc,key,value)
            record_error("Ollama inference",exc)
            raise
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
            home=os.environ.get("HOME") or current_identity().home
            context=dict(os.environ)
            if home:context["HOME"]=str(home)
            try:self.owned_models_path=model_path(context,os.getcwd())
            except StorageError as exc:raise SetupError("Cannot determine the new service model directory: "+str(exc)) from exc
            env=dict(context,OLLAMA_HOST=self.url,OLLAMA_MODELS=str(self.owned_models_path))
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
    def registry_info(self,model,refresh=False):
        name=canonical_model(model)
        if refresh or name not in self.registry_metadata:
            self.registry_metadata[name]=registry_metadata(name)
        return self.registry_metadata[name]
    def manifest_size(self,model):
        return self.registry_info(model).estimated_bytes

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
    def command(self):
        try:
            if self.read is input:
                try:
                    import readline
                    invisible=True
                except ImportError:invisible=False
                if invisible and sys.stdin.isatty() and self.term.stream.isatty():
                    from redvector_ollama_completion import command_completion
                    with command_completion():
                        return self.read(self.term.prompt(readline=True)).strip()
                return self.read(self.term.prompt(readline=invisible)).strip()
            self.term.stream.write(self.term.prompt());self.term.stream.flush()
            return self.read().strip()
        except (EOFError,KeyboardInterrupt,StopIteration):
            self.term.message("warning","Session cancelled safely.")
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

    def storage_location(self):
        info=detect_storage(self.api.host,self.api.port)
        if info.path is None:
            self.term.message("warning","Automatic model storage detection: "+info.reason)
            if not info.manual_allowed:raise SetupError(info.reason)
            if info.pid is not None:return info
            raw=self.ask("Enter the actual local model directory, UNKNOWN to leave it unverified, or blank to cancel:")
            if not raw:raise DownloadCancelled("Model storage check cancelled. No download was started.")
            if raw=="UNKNOWN":return info
            path=Path(raw)
            if not path.is_absolute() or any(ord(c)<32 for c in raw):
                raise SetupError("Use an absolute local model directory without control characters.")
            info=StorageInfo(path,"operator-specified local service directory")
        self.term.write("Model storage configuration: "+str(info.path)+" ("+info.source+")")
        return info

    def storage_path(self):
        # Compatibility path resolver; download capacity uses pinned descriptors,
        # not directory file-access or ACL checks.
        info=self.storage_location()
        try:return filesystem_path(info)
        except StorageError as exc:raise SetupError(str(exc)) from exc

    def preflight(self,model,size,info,capacity,installed=False,metadata=None):
        path=capacity.model_path or info.path
        known=capacity.complete
        available=(f"{capacity.blobs.available_bytes/1e9:.2f} GB" if capacity.blobs.verified else "Unknown")
        required="None (already installed)" if installed else f"Approx. {size/1e9:.2f} GB"
        tools="To be verified after download"
        if installed:
            tools=("Advertised; agent verifies native tool calls" if api_capabilities(model,metadata).state=="SUPPORTED"
                   else "Not advertised; agent mode disabled")
        local=self.api.host in ("127.0.0.1","localhost","::1")
        engine=("Local process detected" if local and capacity.instance_verified else
                "API responding; engine location unverified")
        self.term.box("OLLAMA PREFLIGHT CHECK",[
            "Ollama engine:     "+engine,
            "Ollama API:        Connected",
            f"Model:             {model}",
            "Required download: "+required,
            "Model storage:     "+(str(path) if path else "Unverified"),
            "Storage source:    "+("Runtime process verified at the API endpoint" if capacity.instance_verified else info.source),
            "Storage check:     "+("Verified filesystem capacity" if known else "Unverified"),
            "Available space:   "+available,
            "Blob filesystem:   "+(str(capacity.blobs.checked_path) if capacity.blobs.verified else "Unverified"),
            "Manifest storage:  "+(f"{capacity.manifests.available_bytes/1e9:.2f} GB available" if capacity.manifests.verified else "Unverified"),
            "Manifest v2:       "+(f"{capacity.manifests_v2.available_bytes/1e9:.2f} GB available" if capacity.manifests_v2 is not None and capacity.manifests_v2.verified else "Unverified" if capacity.manifests_v2 is not None else "Not part of this assessment"),
            "Account quotas:    Unverified; reservations, project limits and future usage may differ",
            "Tool calling:      "+tools])
        if not installed:self.term.write(f"Required with temporary/operational headroom: {(int(size*1.15)+1_000_000_000)/1e9:.2f} GB for blobs; 16 MiB per manifest directory.")
        for name,item in (("Blob",capacity.blobs),("Manifest",capacity.manifests),("Manifest v2",capacity.manifests_v2)):
            if item is None:continue
            if not item.verified and item.reason:self.term.message("warning",name+" capacity: "+item.reason)

    def check_capacity(self,capacity,required):
        destinations=[("blob",capacity.blobs,required),("manifest",capacity.manifests,16*1024*1024)]
        if capacity.manifests_v2 is not None:destinations.append(("manifest v2",capacity.manifests_v2,16*1024*1024))
        pools={}
        for name,item,minimum in destinations:
            if item.status=="error":raise SetupError(item.reason)
            if item.verified and item.read_only:
                raise SetupError(f"The verified {name} filesystem is read-only. No download was started.")
            if item.verified and item.available_bytes<minimum:
                raise SetupError(f"Insufficient storage on the verified {name} filesystem: {item.available_bytes} bytes available, {minimum} required. No download was started.")
            if item.verified and item.device:pools.setdefault(item.device,[]).append((item,minimum))
        for pool in pools.values():
            if len(pool)<2:continue
            combined=sum(minimum for _,minimum in pool)
            available=min(item.available_bytes for item,_ in pool)
            if available<combined:
                raise SetupError(f"Insufficient storage on a shared model filesystem: {available} bytes available, {combined} required. No download was started.")

    def confirm_unknown_capacity(self,model,size,info,capacity,required):
        attempted=False
        while not capacity.complete:
            self.check_capacity(capacity,required)
            command=None
            if not attempted:
                try:command=service_probe_command(info)
                except (ValueError,OSError):pass
            options=[
                "No successful capacity check exists for every required storage filesystem.",
                "Ollama may reject the pull or run out of storage; no available space is being assumed."]
            if command:
                options+=[f"1. Run a limited read-only check as detected service UID {info.uid} using sudo.",
                          f"   Trusted tools: {command[0]} and {command[4]}. No files, permissions or services are changed."]
            options+=["Type UNVERIFIED to consent to a download without full capacity verification.",
                      "Any other answer cancels this download and returns to the startup menu."]
            self.term.box("STORAGE CAPACITY UNVERIFIED",options)
            choice=self.ask("Choose a read-only check, UNVERIFIED, or cancel [default]:")
            if choice=="1" and command:
                attempted=True
                measured=probe_storage(info,as_service=True)
                self.check_capacity(measured,required)
                if not measured.complete:
                    reasons={item.reason for item in (measured.blobs,measured.manifests,measured.manifests_v2)
                             if item is not None and not item.verified and item.reason}
                    self.term.message("warning","The read-only check did not verify all storage: "+"; ".join(sorted(reasons)))
                if (capacity.model_path is not None and measured.model_path is not None
                    and capacity.model_path!=measured.model_path):
                    raise SetupError("The server model directory changed during preflight. Start the check again.")
                capacity=CapacityAssessment(
                    measured.blobs if measured.blobs.verified else capacity.blobs,
                    measured.manifests if measured.manifests.verified else capacity.manifests,
                    measured.model_path or capacity.model_path,
                    measured.manifests_v2 if measured.manifests_v2 is not None and measured.manifests_v2.verified else capacity.manifests_v2,
                    measured.instance_verified or capacity.instance_verified)
                self.preflight(model,size,info,capacity)
                continue
            if choice=="UNVERIFIED":return capacity
            raise DownloadCancelled("Download cancelled; capacity was not verified. No installation changes were made.")
        return capacity

    def resource_budget(self,model,approx_gb=None):
        import psutil
        if not self.api.healthy():raise SetupError("Ollama API is unavailable. Storage and download checks were not started.")
        size=self.api.manifest_size(model)
        if size:self.term.write(f"Official manifest download: approximately {size/1e9:.2f} GB.")
        else:
            if approx_gb:self.term.write(f"Catalog estimate: approximately {approx_gb:g} GB; exact size is unavailable.")
            self.term.message("warning","Reliable size metadata is unavailable. Choose a conservative storage budget.")
            raw=self.ask("Maximum expected download size in GB (blank cancels):")
            if not raw:raise DownloadCancelled("Download cancelled before storage checks.")
            try:
                gb=float(raw)
                if not math.isfinite(gb) or gb<=0:raise ValueError()
                size=int(gb*1e9)
                if approx_gb and size<int(approx_gb*1e9):raise SetupError("Budget is below the catalog estimate.")
            except (ValueError,OverflowError) as exc:raise SetupError("A positive storage budget is required.") from exc
        info=self.storage_location()
        capacity=probe_storage(info)
        required=int(size*1.15)+1_000_000_000
        self.preflight(model,size,info,capacity)
        self.check_capacity(capacity,required)
        capacity=self.confirm_unknown_capacity(model,size,info,capacity,required)
        self.check_capacity(capacity,required)
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
        self.term.message("warning","Measured free space is an estimate, not a guarantee. Model memory and quota limits are independent.")
        if not self.confirm("Proceed with download?"):raise DownloadCancelled("Download cancelled before it started.")

    def verify_model(self,model):
        from redvector_ollama_model_check import verify_selected_model
        self.model_evidence=asyncio.run(verify_selected_model(self.api,model,self.term))
        return self.model_evidence

    def model_recovery(self,title,reason):
        self.term.box(title,[reason,
            "MCP agent mode cannot use this selection. Previous selection remains unchanged.",
            "No models were deleted or selected automatically.",
            "1. Choose another model","2. Back","3. Exit"])
        while True:
            choice=self.ask("Choose 1-3:")
            if choice=="1":return True
            if choice=="2":return False
            if choice=="3":raise SystemExit(0)
            self.term.message("warning","Choose 1, 2 or 3.")

    def select_model(self):
        while True:
            self.term.box("REDVECTOR AI / OLLAMA MODEL SELECTION",
                [f"{i}. {label:<17} | Approx. {size:g} GB | {purpose}" for i,(label,_,size,purpose) in enumerate(PRESETS,1)]
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
            normalized=canonical_model(model)
            matches=[]
            for item in models:
                try:
                    if canonical_model(item.get("name"))==normalized:matches.append(item)
                except (ValueError,AttributeError):continue
            installed=bool(matches)
            if installed:self.term.message("success",f"Reusing installed model: {model}")
            info=inspect_model(self.api,model,installed)
            size=info.estimated_bytes
            if installed:
                local_size=matches[0].get("size")
                size=local_size if isinstance(local_size,int) and not isinstance(local_size,bool) and local_size>0 else None
            self.term.box("REDVECTOR AI / MODEL COMPATIBILITY",[
                "Selected model:    "+model,
                "Tool Calling:      "+info.state.title(),
                "Download Required: "+("No" if installed else "Yes"),
                "Estimated Size:    "+(f"{size/1e9:.2f} GB (installed size)" if installed and size else
                                         f"{size/1e9:.2f} GB (official manifest)" if size else "Unknown"),
                "Compatibility:     "+info.reason,
                "Evidence source:   "+info.source])
            if info.state=="UNSUPPORTED":
                if self.model_recovery("MODEL NOT COMPATIBLE",
                    "This model does not support native tool calling required by the RedVector MCP agent. No download was started."):
                    continue
                return None
            if not installed:
                if info.state=="UNVERIFIED":
                    self.term.message("warning","Compatibility cannot be guaranteed until the exact model is installed and tested. No model weights were downloaded for this check.")
                    if self.ask("Type DOWNLOAD UNVERIFIED to consent to downloading an unverified model, or anything else to cancel:")!="DOWNLOAD UNVERIFIED":
                        raise DownloadCancelled("Compatibility consent declined. No download was started.")
                self.resource_budget(model,approx)
                self.api.pull(model)
            try:
                metadata=self.api.show(model)
                if installed and self.api.healthy():
                    storage=detect_storage(self.api.host,self.api.port)
                    self.preflight(model,0,storage,probe_storage(storage),installed=True,metadata=metadata)
                self.verify_model(model)
            except SetupError as exc:
                if self.model_recovery("MODEL VERIFICATION FAILED",plain(exc)):continue
                return None
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
                except DownloadCancelled as exc:
                    self.term.message("warning",str(exc));break
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

def saved_result_mode(args):
    from redvector_ollama_presentation import render_result
    from redvector_ollama_analysis import summarize
    term=Terminal()
    try:
        store=ResultsStore()
        mode=next(name for name in ("results","raw","export","summary") if getattr(args,name,None) is not None)
        ident=getattr(args,mode)
        if ident=="latest":ident=None
        record=store.load(ident)
        if mode=="results":render_result(term,record)
        elif mode=="raw":term.write(plain(json.dumps(record["wire"],ensure_ascii=True)))
        elif mode=="export":term.message("success","Exported private evidence: "+str(store.export(record["id"])))
        else:
            model=load_model()
            if not model:raise SetupError("Choose a model first. Saved results remain available without it.")
            api=Ollama();api.show(model)
            result=asyncio.run(summarize(api,model,record,args.page))
            term.message("info",result.get("text","AI summary unavailable: "+result.get("reason","unknown"))+" No network scan was executed.")
            if result["state"]!="verified":return 1
        return 0
    except (SetupError,ValueError,OSError,KeyError,StopIteration):
        term.message("error","Saved-result request could not be completed. Check result ID, private storage and local model availability. No network scan was executed.")
        return 1

def main():
    parser=argparse.ArgumentParser(description="Automatic local RedVector Ollama integration")
    parser.add_argument("--install",action="store_true")
    saved=parser.add_mutually_exclusive_group()
    for name in ("results","raw","export","summary"):
        saved.add_argument("--"+name,nargs="?",const="latest")
    parser.add_argument("--page",type=int,default=1)
    args=parser.parse_args()
    if not sys.platform.startswith("linux"):
        print("Run this installer inside Kali, Debian or Ubuntu Linux.",file=sys.stderr);return 1
    if any(getattr(args,name) is not None for name in ("results","raw","export","summary")):
        return saved_result_mode(args)
    try:Wizard().run(install=args.install);return 0
    except (KeyboardInterrupt,EOFError):
        print("\nCancelled safely. Existing configurations are unchanged.");return 0
    except (SetupError,OSError,ImportError) as exc:
        print("Error: "+plain(exc),file=sys.stderr);return 1

if __name__=="__main__":raise SystemExit(main())

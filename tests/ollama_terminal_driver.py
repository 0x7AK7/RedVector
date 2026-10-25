"""Drive the real Bash/Python terminal UI under a Linux PTY; no boundary stubs."""
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import subprocess
import termios
import time

ANSI=re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
def plain(data):
    return ANSI.sub("",data.decode("utf8",errors="replace")).replace("\r\n","\n")

class TerminalSession:
    def __init__(self,command,env,cwd,output,name):
        self.master,slave=pty.openpty()
        fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack("HHHH",50,160,0,0))
        self.process=subprocess.Popen(command,cwd=cwd,env=env,stdin=slave,stdout=slave,
                                      stderr=slave,start_new_session=True)
        os.close(slave)
        self.raw=bytearray();self.cursor=0;self.events=[]
        self.output=Path(output);self.name=name
        self.command=command
    def read(self,wait=.2):
        ready,_,_=select.select([self.master],[],[],wait)
        if ready:
            try:self.raw.extend(os.read(self.master,65536))
            except OSError:pass
    def expect(self,pattern,timeout=40):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            text=plain(self.raw)
            match=re.search(pattern,text[self.cursor:],re.DOTALL)
            if match:
                self.cursor+=match.end()
                return match
            if self.process.poll() is not None:
                self.read(0)
                raise AssertionError(f"{self.name}: exited {self.process.returncode} before {pattern!r}\n"+plain(self.raw)[-4000:])
            self.read()
        raise AssertionError(f"{self.name}: timed out before {pattern!r}\n"+plain(self.raw)[-4000:])
    def send(self,value):
        self.events.append({"input":value,"time":time.time()})
        os.write(self.master,(value+"\n").encode())
    def finish(self,timeout=15):
        end=time.monotonic()+timeout
        while self.process.poll() is None and time.monotonic()<end:self.read()
        if self.process.poll() is None:raise AssertionError(self.name+": did not exit")
        for _ in range(4):self.read(0)
        if self.process.returncode!=0:
            raise AssertionError(f"{self.name}: exit {self.process.returncode}\n"+plain(self.raw)[-3000:])
        self.save()
        return plain(self.raw)
    def save(self):
        self.output.mkdir(parents=True,exist_ok=True)
        (self.output/(self.name+".ansi")).write_bytes(self.raw)
        (self.output/(self.name+".txt")).write_text(plain(self.raw),encoding="utf8")
        (self.output/(self.name+"-inputs.json")).write_text(
            json.dumps({"command":self.command,"inputs":self.events},indent=2),encoding="utf8")
    def close(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid,signal.SIGTERM)
            try:self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:os.killpg(self.process.pid,signal.SIGKILL);self.process.wait()
        self.save()
        os.close(self.master)

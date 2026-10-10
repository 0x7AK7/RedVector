"""Operating-system / architecture / distribution detection.

Injectable (system, machine, os-release reader) so tests are deterministic and
never read the real machine. Distinguishes Debian-family (incl. Kali) without
asserting vendor "official support"; that honesty lives in vendors.py.
"""
from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from typing import Callable, Dict, Optional


@dataclass
class PlatformInfo:
    system: str          # "Linux" | "Windows" | "Darwin"
    machine: str         # normalized arch: x86_64 | arm64 | ...
    distro_id: str       # "kali" | "ubuntu" | "debian" | "fedora" | "" ...
    distro_like: str     # ID_LIKE, e.g. "debian"
    distro_name: str     # pretty name

    @property
    def is_linux(self) -> bool:
        return self.system == "Linux"

    @property
    def is_windows(self) -> bool:
        return self.system == "Windows"

    @property
    def is_macos(self) -> bool:
        return self.system == "Darwin"

    @property
    def is_debian_family(self) -> bool:
        ids = {self.distro_id} | set(self.distro_like.split())
        return bool(ids & {"debian", "ubuntu", "kali"})

    @property
    def is_kali(self) -> bool:
        return self.distro_id == "kali"

    @property
    def is_fedora_family(self) -> bool:
        ids = {self.distro_id} | set(self.distro_like.split())
        return bool(ids & {"fedora", "rhel", "centos"})

    def to_dict(self) -> Dict[str, object]:
        return {"system": self.system, "machine": self.machine, "distro_id": self.distro_id,
                "distro_like": self.distro_like, "distro_name": self.distro_name,
                "debian_family": self.is_debian_family, "kali": self.is_kali,
                "fedora_family": self.is_fedora_family}


_ARCH_NORMALIZE = {
    "amd64": "x86_64", "x86_64": "x86_64", "x64": "x86_64",
    "aarch64": "arm64", "arm64": "arm64",
    "i386": "x86", "i686": "x86", "x86": "x86",
}


def _default_os_release_reader() -> str:
    for p in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            if os.path.isfile(p):
                return open(p, encoding="utf-8", errors="replace").read()
        except Exception:
            pass
    return ""


def _parse_os_release(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


class PlatformProbe:
    def __init__(self, system: Optional[Callable[[], str]] = None,
                 machine: Optional[Callable[[], str]] = None,
                 os_release_reader: Optional[Callable[[], str]] = None) -> None:
        self._system = system or platform.system
        self._machine = machine or platform.machine
        self._os_release = os_release_reader or _default_os_release_reader

    def detect(self) -> PlatformInfo:
        system = self._system() or ""
        machine = (self._machine() or "").lower()
        arch = _ARCH_NORMALIZE.get(machine, machine or "unknown")
        distro_id = distro_like = distro_name = ""
        if system == "Linux":
            rel = _parse_os_release(self._os_release())
            distro_id = (rel.get("ID", "") or "").lower()
            distro_like = (rel.get("ID_LIKE", "") or "").lower()
            distro_name = rel.get("PRETTY_NAME", "") or rel.get("NAME", "") or distro_id
        return PlatformInfo(system=system, machine=arch, distro_id=distro_id,
                            distro_like=distro_like, distro_name=distro_name)

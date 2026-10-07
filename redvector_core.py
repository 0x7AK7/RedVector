#!/usr/bin/env python3
"""
RedVector AI - Core infrastructure engine (Phase 1 Item 6).

Independent, dependency-injected decomposition of three legacy monolith
classes that previously lived in ``redvector_server.py``:

    FileOperationsManager  -> FileOperationService      (+ PathResolver, FilesystemBackend)
    HTTPTestingFramework   -> HTTPTestingService        (+ RequestPolicy, ResponseNormalizer, HTTPVulnerabilityAnalyzer, HTTPClientAdapter)
    BrowserAgent           -> BrowserAgentService       (+ BrowserSessionManager, BrowserExtractionService, BrowserSecurityAnalyzer)

Design goals for this phase (architecture-only, no capability change):
  * cleaner separation of responsibilities (composition over god-classes)
  * explicit, injectable boundaries for the filesystem, the HTTP transport
    and the Selenium driver, so behavior is deterministically testable with
    fakes and never needs a live network / real browser / destructive FS writes
  * typed request/result domain models where they do not alter the existing
    externally-observable dict schemas
  * zero change to externally-observable behavior: every method reproduces the
    original logic verbatim, including pre-existing quirks (documented inline)

IMPORTANT: this module never imports ``redvector_server`` (that would be a
circular import). Everything the original code read from server-module globals
-- the logger, the ``ModernVisualEngine`` formatter, and the ``_is_safe_target``
SSRF guard -- is INJECTED by the thin compatibility adapters in the server.
Sensible, self-contained defaults are provided so the core can also be unit
tested in isolation.
"""

from __future__ import annotations

import collections
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

import requests

try:  # bs4 is stubbed in the test environment; import defensively like the server
    from bs4 import BeautifulSoup
except Exception:  # pragma: no cover
    BeautifulSoup = None  # type: ignore

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
except Exception:  # pragma: no cover
    webdriver = None  # type: ignore
    Options = None  # type: ignore
    By = None  # type: ignore


# ============================================================================
# Injected-dependency defaults
# ============================================================================

_DEFAULT_LOGGER = logging.getLogger("redvector_core")
if not _DEFAULT_LOGGER.handlers:
    _DEFAULT_LOGGER.addHandler(logging.NullHandler())


class _PlainVisual:
    """Fallback for the server's ModernVisualEngine: produces plain strings so
    core can run standalone. The adapters inject the real engine so production
    log output is byte-identical to before."""

    @staticmethod
    def format_error_card(*args: Any, **kwargs: Any) -> str:
        return " ".join(str(a) for a in args)

    @staticmethod
    def format_tool_status(*args: Any, **kwargs: Any) -> str:
        return " ".join(str(a) for a in args)

    @staticmethod
    def format_command_execution(*args: Any, **kwargs: Any) -> str:
        return " ".join(str(a) for a in args)


def default_is_safe_target(url_or_host: str) -> bool:
    """Self-contained copy of the server's SSRF guard, used only when the
    adapter does not inject the real one. Logically identical to
    ``redvector_server._is_safe_target``."""
    try:
        parsed = urlparse(url_or_host) if '://' in url_or_host else urlparse(f'http://{url_or_host}')
        hostname = parsed.hostname or url_or_host
        resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in resolved:
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                return False
        return True
    except Exception:
        return False


@dataclass
class CoreDependencies:
    """Bundle of injectable cross-cutting dependencies."""
    logger: Any = _DEFAULT_LOGGER
    visual: Any = field(default_factory=_PlainVisual)
    is_safe_target: Callable[[str], bool] = default_is_safe_target


# ============================================================================
# FILE OPERATIONS
# ============================================================================

class FilesystemBackend(Protocol):
    """Seam over the real filesystem so file operations are mockable."""
    def resolve(self, path: Path) -> Path: ...
    def mkdir(self, path: Path, parents: bool = False, exist_ok: bool = False) -> None: ...
    def exists(self, path: Path) -> bool: ...
    def is_dir(self, path: Path) -> bool: ...
    def is_file(self, path: Path) -> bool: ...
    def open(self, path: Path, mode: str): ...
    def stat_size(self, path: Path) -> int: ...
    def stat_mtime(self, path: Path) -> float: ...
    def iterdir(self, path: Path) -> List[Path]: ...
    def unlink(self, path: Path) -> None: ...
    def rmtree(self, path: Path) -> None: ...


class LocalFilesystemBackend:
    """Default backend backed by ``pathlib`` / ``os`` / ``shutil`` -- identical
    primitives to the original FileOperationsManager."""

    def resolve(self, path: Path) -> Path:
        return path.resolve()

    def mkdir(self, path: Path, parents: bool = False, exist_ok: bool = False) -> None:
        path.mkdir(parents=parents, exist_ok=exist_ok)

    def exists(self, path: Path) -> bool:
        return path.exists()

    def is_dir(self, path: Path) -> bool:
        return path.is_dir()

    def is_file(self, path: Path) -> bool:
        return path.is_file()

    def open(self, path: Path, mode: str):
        return open(path, mode)

    def stat_size(self, path: Path) -> int:
        return path.stat().st_size

    def stat_mtime(self, path: Path) -> float:
        return path.stat().st_mtime

    def iterdir(self, path: Path) -> List[Path]:
        return list(path.iterdir())

    def unlink(self, path: Path) -> None:
        path.unlink()

    def rmtree(self, path: Path) -> None:
        shutil.rmtree(path)


class PathResolver:
    """Owns base-dir anchoring and path-traversal prevention (the original
    ``_safe_path``)."""

    def __init__(self, base_dir: Path, backend: FilesystemBackend):
        self.base_dir = base_dir
        self._backend = backend

    def safe_path(self, filename: str) -> Path:
        resolved = self._backend.resolve(self.base_dir / filename)
        base_resolved = self._backend.resolve(self.base_dir)
        if not str(resolved).startswith(str(base_resolved) + os.sep) and resolved != base_resolved:
            raise ValueError(f"Path traversal detected: {filename}")
        return resolved


class FileOperationService:
    """Create/modify/delete/list operations. Returns the exact legacy dict
    schemas. ``max_file_size`` default and the ``size = len(content)`` (char
    count, not byte count) quirk are preserved."""

    def __init__(self, base_dir: str = "/tmp/redvector_files",
                 backend: Optional[FilesystemBackend] = None,
                 deps: Optional[CoreDependencies] = None):
        self._deps = deps or CoreDependencies()
        self._backend = backend or LocalFilesystemBackend()
        self.base_dir = Path(base_dir)
        self._backend.mkdir(self.base_dir, exist_ok=True)
        self.max_file_size = 100 * 1024 * 1024  # 100MB
        self._resolver = PathResolver(self.base_dir, self._backend)

    @property
    def _logger(self):
        return self._deps.logger

    def safe_path(self, filename: str) -> Path:
        return self._resolver.safe_path(filename)

    def create_file(self, filename: str, content: str, binary: bool = False) -> Dict[str, Any]:
        try:
            file_path = self.safe_path(filename)
            self._backend.mkdir(file_path.parent, parents=True, exist_ok=True)

            if len(content.encode()) > self.max_file_size:
                return {"success": False, "error": f"File size exceeds {self.max_file_size} bytes"}

            mode = "wb" if binary else "w"
            with self._backend.open(file_path, mode) as f:
                if binary:
                    f.write(content.encode() if isinstance(content, str) else content)
                else:
                    f.write(content)

            self._logger.info(f"📄 Created file: {filename} ({len(content)} bytes)")
            return {"success": True, "path": str(file_path), "size": len(content)}

        except Exception as e:
            self._logger.error(f"❌ Error creating file {filename}: {e}")
            return {"success": False, "error": str(e)}

    def modify_file(self, filename: str, content: str, append: bool = False) -> Dict[str, Any]:
        try:
            file_path = self.safe_path(filename)
            if not self._backend.exists(file_path):
                return {"success": False, "error": "File does not exist"}

            mode = "a" if append else "w"
            with self._backend.open(file_path, mode) as f:
                f.write(content)

            self._logger.info(f"✏️  Modified file: {filename}")
            return {"success": True, "path": str(file_path)}

        except Exception as e:
            self._logger.error(f"❌ Error modifying file {filename}: {e}")
            return {"success": False, "error": str(e)}

    def delete_file(self, filename: str) -> Dict[str, Any]:
        try:
            file_path = self.safe_path(filename)
            if not self._backend.exists(file_path):
                return {"success": False, "error": "File does not exist"}

            if self._backend.is_dir(file_path):
                self._backend.rmtree(file_path)
            else:
                self._backend.unlink(file_path)

            self._logger.info(f"🗑️  Deleted: {filename}")
            return {"success": True}

        except Exception as e:
            self._logger.error(f"❌ Error deleting {filename}: {e}")
            return {"success": False, "error": str(e)}

    def list_files(self, directory: str = ".") -> Dict[str, Any]:
        try:
            dir_path = self.safe_path(directory)
            if not self._backend.exists(dir_path):
                return {"success": False, "error": "Directory does not exist"}

            files = []
            for item in self._backend.iterdir(dir_path):
                files.append({
                    "name": item.name,
                    "type": "directory" if self._backend.is_dir(item) else "file",
                    "size": self._backend.stat_size(item) if self._backend.is_file(item) else 0,
                    "modified": datetime.fromtimestamp(self._backend.stat_mtime(item)).isoformat()
                })

            return {"success": True, "files": files}

        except Exception as e:
            self._logger.error(f"❌ Error listing files in {directory}: {e}")
            return {"success": False, "error": str(e)}


# ============================================================================
# HTTP TESTING
# ============================================================================

class HTTPClientAdapter(Protocol):
    """Transport seam. Default wraps a ``requests.Session``."""
    def request(self, method: str, url: str, **kwargs): ...
    @property
    def headers(self) -> dict: ...
    @property
    def cookies(self): ...
    @property
    def proxies(self) -> dict: ...
    @proxies.setter
    def proxies(self, value: dict) -> None: ...


class RequestsHTTPClientAdapter:
    """Default HTTP client: a thin pass-through to ``requests.Session`` that
    preserves the exact per-method call surface the original used."""

    def __init__(self, session=None):
        self.session = session if session is not None else requests.Session()

    @property
    def headers(self):
        return self.session.headers

    @property
    def cookies(self):
        return self.session.cookies

    @property
    def proxies(self):
        return self.session.proxies

    @proxies.setter
    def proxies(self, value):
        self.session.proxies = value

    def get(self, url, **kw):
        return self.session.get(url, **kw)

    def post(self, url, **kw):
        return self.session.post(url, **kw)

    def put(self, url, **kw):
        return self.session.put(url, **kw)

    def delete(self, url, **kw):
        return self.session.delete(url, **kw)

    def request(self, method, url, **kw):
        return self.session.request(method, url, **kw)


class RequestPolicy:
    """Scope restriction + match/replace rewriting (the original ``scope`` /
    ``match_replace_rules`` logic). Holds no transport state."""

    def __init__(self, deps: CoreDependencies):
        self._deps = deps
        self.match_replace_rules: list = []
        self.scope = None  # {'host': ..., 'include_subdomains': bool}

    def set_match_replace_rules(self, rules: list):
        self.match_replace_rules = rules or []

    def set_scope(self, host: str, include_subdomains: bool = True):
        self.scope = {'host': host, 'include_subdomains': include_subdomains}

    def in_scope(self, url: str) -> bool:
        if not self.scope:
            return True
        try:
            h = urlparse(url).hostname or ''
            target = self.scope.get('host', '')
            if not h or not target:
                return True
            if h == target:
                return True
            if self.scope.get('include_subdomains') and h.endswith('.' + target):
                return True
        except Exception:
            return True
        return False

    def apply_match_replace(self, url: str, data, headers: dict):
        original_url = url
        out_headers = dict(headers)
        out_data = data
        for rule in self.match_replace_rules:
            where = (rule.get('where') or 'url').lower()
            pattern = rule.get('pattern') or ''
            repl = rule.get('replacement') or ''
            try:
                if where == 'url':
                    url = re.sub(pattern, repl, url)
                elif where == 'query':
                    pr = urlparse(url)
                    qs = parse_qsl(pr.query, keep_blank_values=True)
                    new_qs = []
                    for k, v in qs:
                        nk = re.sub(pattern, repl, k)
                        nv = re.sub(pattern, repl, v)
                        new_qs.append((nk, nv))
                    url = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, urlencode(new_qs), pr.fragment))
                elif where == 'headers':
                    out_headers = {re.sub(pattern, repl, k): re.sub(pattern, repl, str(v)) for k, v in out_headers.items()}
                elif where == 'body':
                    if isinstance(out_data, dict):
                        out_data = {re.sub(pattern, repl, k): re.sub(pattern, repl, str(v)) for k, v in out_data.items()}
                    elif isinstance(out_data, str):
                        out_data = re.sub(pattern, repl, out_data)
            except Exception:
                continue
        if not self.in_scope(url):
            self._deps.logger.warning(
                f"{self._deps.visual.format_tool_status('HTTP-Framework', 'SKIPPED', f'Out of scope: {url}')}")
            return original_url, data, headers
        return url, out_data, out_headers


class HTTPVulnerabilityAnalyzer:
    """Passive response analysis (the original ``_analyze_response_for_vulns``)
    plus the recent-vulns accessor. Appends into a shared ``vulnerabilities``
    list owned by the service."""

    def __init__(self, vulnerabilities: list):
        self.vulnerabilities = vulnerabilities

    def analyze(self, url: str, response):
        vulns = []
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-Content-Type-Options': 'MIME type sniffing protection missing',
            'X-XSS-Protection': 'XSS protection missing',
            'Strict-Transport-Security': 'HTTPS enforcement missing',
            'Content-Security-Policy': 'Content Security Policy missing'
        }
        for header, description in security_headers.items():
            if header not in response.headers:
                vulns.append({
                    'type': 'missing_security_header',
                    'severity': 'medium',
                    'description': description,
                    'url': url,
                    'header': header
                })

        sensitive_patterns = [
            (r'password\s*[:=]\s*["\']?([^"\'\s]+)', 'Password disclosure'),
            (r'api[_-]?key\s*[:=]\s*["\']?([^"\'\s]+)', 'API key disclosure'),
            (r'secret\s*[:=]\s*["\']?([^"\'\s]+)', 'Secret disclosure'),
            (r'token\s*[:=]\s*["\']?([^"\'\s]+)', 'Token disclosure')
        ]
        for pattern, description in sensitive_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                vulns.append({
                    'type': 'information_disclosure',
                    'severity': 'high',
                    'description': description,
                    'url': url,
                    'matches': matches[:5]
                })

        sql_errors = [
            'SQL syntax error',
            'mysql_fetch_array',
            'ORA-01756',
            'Microsoft OLE DB Provider',
            'PostgreSQL query failed'
        ]
        for error in sql_errors:
            if error.lower() in response.text.lower():
                vulns.append({
                    'type': 'sql_injection_indicator',
                    'severity': 'high',
                    'description': f'Potential SQL injection: {error}',
                    'url': url
                })

        self.vulnerabilities.extend(vulns)

    def recent(self, limit: int = 10):
        return self.vulnerabilities[-limit:] if self.vulnerabilities else []


class ResponseNormalizer:
    """Builds the request/response domain dicts (the original inline
    ``request_data`` / ``response_data`` shapes)."""

    @staticmethod
    def request_data(req_id: int, url: str, method: str, response, data) -> dict:
        return {
            'id': req_id,
            'url': url,
            'method': method,
            'headers': dict(response.request.headers),
            'data': data,
            'timestamp': datetime.now().isoformat()
        }

    @staticmethod
    def response_data(response) -> dict:
        return {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content': response.text[:10000],
            'size': len(response.content),
            'time': response.elapsed.total_seconds()
        }


class HTTPTestingService:
    """Advanced HTTP testing framework as Burp Suite alternative.

    Orchestrates the HTTP client, request policy, response normalization and
    vulnerability analysis. Owns the proxy history, vulnerability list and the
    request-id counter. Behavior reproduces the original verbatim, including the
    (dead-but-preserved) initial ``send_headers`` computation in
    ``intercept_request``."""

    def __init__(self, client: Optional[RequestsHTTPClientAdapter] = None,
                 deps: Optional[CoreDependencies] = None):
        self._deps = deps or CoreDependencies()
        self._client = client or RequestsHTTPClientAdapter()
        self._client.headers.update({
            'User-Agent': 'RedVector-HTTP-Framework/1.0 (Advanced Security Testing)'
        })
        self.proxy_history = collections.deque(maxlen=1000)
        self.vulnerabilities = []
        self._policy = RequestPolicy(self._deps)
        self._analyzer = HTTPVulnerabilityAnalyzer(self.vulnerabilities)
        self._normalizer = ResponseNormalizer()
        self._req_id = 0
        self._lock = threading.Lock()

    # ---- compatibility views over composed state ----
    @property
    def session(self):
        return self._client.session

    @session.setter
    def session(self, value):
        self._client.session = value

    @property
    def match_replace_rules(self):
        return self._policy.match_replace_rules

    @match_replace_rules.setter
    def match_replace_rules(self, value):
        self._policy.match_replace_rules = value

    @property
    def scope(self):
        return self._policy.scope

    @scope.setter
    def scope(self, value):
        self._policy.scope = value

    def setup_proxy(self, proxy_port: int = 8080):
        self._client.proxies = {
            'http': f'http://127.0.0.1:{proxy_port}',
            'https': f'http://127.0.0.1:{proxy_port}'
        }

    def intercept_request(self, url: str, method: str = 'GET', data: dict = None,
                          headers: dict = None, cookies: dict = None) -> dict:
        if not self._deps.is_safe_target(url):
            return {'error': 'Target URL points to internal/private network', 'blocked': True}
        try:
            # Use per-request headers/cookies to prevent leakage across requests
            send_headers = dict(self._client.headers)
            if headers:
                send_headers.update(headers)
            req_cookies = cookies or {}

            # Apply match/replace rules prior to sending
            url, data, send_headers = self._policy.apply_match_replace(url, data, dict(self._client.headers))
            if headers:
                send_headers.update(headers)

            if method.upper() == 'GET':
                response = self._client.get(url, params=data, headers=send_headers, cookies=req_cookies, timeout=30)
            elif method.upper() == 'POST':
                response = self._client.post(url, data=data, headers=send_headers, cookies=req_cookies, timeout=30)
            elif method.upper() == 'PUT':
                response = self._client.put(url, data=data, headers=send_headers, cookies=req_cookies, timeout=30)
            elif method.upper() == 'DELETE':
                response = self._client.delete(url, headers=send_headers, cookies=req_cookies, timeout=30)
            else:
                response = self._client.request(method, url, data=data, headers=send_headers, cookies=req_cookies, timeout=30)

            with self._lock:
                self._req_id += 1
                req_id = self._req_id
            request_data = self._normalizer.request_data(req_id, url, method, response, data)
            response_data = self._normalizer.response_data(response)

            self.proxy_history.append({
                'request': request_data,
                'response': response_data
            })

            self._analyzer.analyze(url, response)

            return {
                'success': True,
                'request': request_data,
                'response': response_data,
                'vulnerabilities': self._get_recent_vulns()
            }

        except Exception as e:
            self._deps.logger.error(
                f"{self._deps.visual.format_error_card('ERROR', 'HTTP-Framework', str(e))}")
            return {'success': False, 'error': str(e)}

    # ---- Match & Replace and Scope (delegate to policy) ----
    def set_match_replace_rules(self, rules: list):
        self._policy.set_match_replace_rules(rules)

    def set_scope(self, host: str, include_subdomains: bool = True):
        self._policy.set_scope(host, include_subdomains)

    def _in_scope(self, url: str) -> bool:
        return self._policy.in_scope(url)

    def _apply_match_replace(self, url: str, data, headers: dict):
        return self._policy.apply_match_replace(url, data, headers)

    # ---- Repeater ----
    def send_custom_request(self, request_spec: dict) -> dict:
        url = request_spec.get('url', '')
        method = request_spec.get('method', 'GET')
        headers = request_spec.get('headers') or {}
        cookies = request_spec.get('cookies') or {}
        data = request_spec.get('data')
        return self.intercept_request(url, method, data, headers, cookies)

    # ---- Intruder (Sniper mode) ----
    def intruder_sniper(self, url: str, method: str = 'GET', location: str = 'query',
                        params: list = None, payloads: list = None, base_data: dict = None,
                        max_requests: int = 100) -> dict:
        params = params or []
        payloads = payloads or ["'\"<>`, ${7*7}"]
        base_data = base_data or {}
        interesting = []
        total = 0
        baseline = self.intercept_request(url, method, base_data)
        base_status = baseline.get('response', {}).get('status_code') if baseline.get('success') else None
        base_len = baseline.get('response', {}).get('size') if baseline.get('success') else None
        for p in params:
            for pay in payloads:
                if total >= max_requests:
                    break
                m_url = url
                m_data = dict(base_data)
                m_headers = {}
                if location == 'query':
                    pr = urlparse(url)
                    q = dict(parse_qsl(pr.query, keep_blank_values=True))
                    q[p] = pay
                    m_url = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, urlencode(q), pr.fragment))
                elif location == 'body':
                    m_data[p] = pay
                elif location == 'headers':
                    m_headers[p] = pay
                elif location == 'cookie':
                    self._client.cookies.set(p, pay)
                resp = self.intercept_request(m_url, method, m_data, m_headers)
                total += 1
                if not resp.get('success'):
                    continue
                r = resp['response']
                changed = (base_status is not None and r.get('status_code') != base_status) or (base_len is not None and abs(r.get('size', 0) - base_len) > 150)
                reflected = pay in (r.get('content') or '')
                if changed or reflected:
                    interesting.append({
                        'param': p,
                        'payload': pay,
                        'status_code': r.get('status_code'),
                        'size': r.get('size'),
                        'reflected': reflected
                    })
        return {
            'success': True,
            'tested': total,
            'interesting': interesting[:50]
        }

    def _analyze_response_for_vulns(self, url: str, response):
        self._analyzer.analyze(url, response)

    def _get_recent_vulns(self, limit: int = 10):
        return self._analyzer.recent(limit)

    def spider_website(self, base_url: str, max_depth: int = 3, max_pages: int = 100) -> dict:
        try:
            discovered_urls = set()
            forms = []
            to_visit = [(base_url, 0)]
            visited = set()

            while to_visit and len(discovered_urls) < max_pages:
                current_url, depth = to_visit.pop(0)

                if current_url in visited or depth > max_depth:
                    continue

                visited.add(current_url)

                try:
                    response = self._client.get(current_url, timeout=10)
                    if response.status_code == 200:
                        discovered_urls.add(current_url)

                        soup = BeautifulSoup(response.text, 'html.parser')

                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            full_url = urljoin(current_url, href)

                            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                                if full_url not in visited and depth < max_depth:
                                    to_visit.append((full_url, depth + 1))

                        for form in soup.find_all('form'):
                            form_data = {
                                'url': current_url,
                                'action': urljoin(current_url, form.get('action', '')),
                                'method': form.get('method', 'GET').upper(),
                                'inputs': []
                            }

                            for input_tag in form.find_all(['input', 'textarea', 'select']):
                                form_data['inputs'].append({
                                    'name': input_tag.get('name', ''),
                                    'type': input_tag.get('type', 'text'),
                                    'value': input_tag.get('value', '')
                                })

                            forms.append(form_data)

                except Exception as e:
                    self._deps.logger.warning(f"Error spidering {current_url}: {str(e)}")
                    continue

            return {
                'success': True,
                'discovered_urls': list(discovered_urls),
                'forms': forms,
                'total_pages': len(discovered_urls),
                'vulnerabilities': self._get_recent_vulns()
            }

        except Exception as e:
            self._deps.logger.error(
                f"{self._deps.visual.format_error_card('ERROR', 'Spider', str(e))}")
            return {'success': False, 'error': str(e)}


# ============================================================================
# BROWSER AGENT
# ============================================================================

def default_driver_factory(headless: bool = True, proxy_port: int = None):
    """Build a Chrome driver with the exact options the original used."""
    chrome_options = Options()
    if headless:
        chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--window-size=1920,1080')
    chrome_options.add_argument('--user-agent=RedVector-BrowserAgent/1.0 (Security Testing)')
    chrome_options.add_argument('--enable-logging')
    chrome_options.add_argument('--log-level=0')
    chrome_options.add_argument('--disable-web-security')
    chrome_options.add_argument('--allow-running-insecure-content')
    chrome_options.add_argument('--ignore-certificate-errors')
    chrome_options.add_argument('--ignore-ssl-errors')
    if proxy_port:
        chrome_options.add_argument(f'--proxy-server=http://127.0.0.1:{proxy_port}')
    chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
    driver = webdriver.Chrome(options=chrome_options)
    driver.set_page_load_timeout(30)
    return driver


class BrowserSessionManager:
    """Owns the driver lifecycle and the per-request artifact deques (the
    original ``driver``/``screenshots``/``page_sources``/``network_logs`` +
    ``reset_state``/``setup_browser``/``close_browser``)."""

    def __init__(self, deps: CoreDependencies, driver_factory: Optional[Callable] = None):
        self._deps = deps
        self._driver_factory = driver_factory or default_driver_factory
        self.driver = None
        self.screenshots = collections.deque(maxlen=50)
        self.page_sources = collections.deque(maxlen=10)
        self.network_logs = collections.deque(maxlen=200)
        self._lock = threading.Lock()

    def reset_state(self):
        with self._lock:
            self.screenshots.clear()
            self.page_sources.clear()
            self.network_logs.clear()

    def setup_browser(self, headless: bool = True, proxy_port: int = None):
        try:
            self.reset_state()
            self.driver = self._driver_factory(headless=headless, proxy_port=proxy_port)
            self._deps.logger.info(
                f"{self._deps.visual.format_tool_status('BrowserAgent', 'RUNNING', 'Chrome Browser Initialized')}")
            return True
        except Exception as e:
            self._deps.logger.error(
                f"{self._deps.visual.format_error_card('ERROR', 'BrowserAgent', str(e))}")
            return False

    def close_browser(self):
        if self.driver:
            self.driver.quit()
            self.driver = None
        self.reset_state()
        self._deps.logger.info(
            f"{self._deps.visual.format_tool_status('BrowserAgent', 'SUCCESS', 'Browser Closed')}")


class BrowserExtractionService:
    """DOM / storage / logs extraction helpers (the original ``_extract_*`` and
    ``_get_*`` helpers). Driven entirely through the injected driver."""

    def __init__(self, session: BrowserSessionManager):
        self._s = session

    @property
    def driver(self):
        return self._s.driver

    def get_console_errors(self) -> list:
        try:
            logs = self.driver.get_log('browser')
            out = []
            for entry in logs[-100:]:
                lvl = entry.get('level', '')
                if lvl in ('SEVERE', 'WARNING'):
                    out.append({'level': lvl, 'message': entry.get('message', '')[:500]})
            return out
        except Exception:
            return []

    def get_local_storage(self) -> dict:
        try:
            return self.driver.execute_script("""
                var storage = {};
                for (var i = 0; i < localStorage.length; i++) {
                    var key = localStorage.key(i);
                    storage[key] = localStorage.getItem(key);
                }
                return storage;
            """)
        except Exception:
            return {}

    def get_session_storage(self) -> dict:
        try:
            return self.driver.execute_script("""
                var storage = {};
                for (var i = 0; i < sessionStorage.length; i++) {
                    var key = sessionStorage.key(i);
                    storage[key] = sessionStorage.getItem(key);
                }
                return storage;
            """)
        except Exception:
            return {}

    def extract_forms(self) -> list:
        forms = []
        try:
            form_elements = self.driver.find_elements(By.TAG_NAME, 'form')
            for form in form_elements:
                form_data = {
                    'action': form.get_attribute('action') or '',
                    'method': form.get_attribute('method') or 'GET',
                    'inputs': []
                }
                inputs = form.find_elements(By.TAG_NAME, 'input')
                for input_elem in inputs:
                    form_data['inputs'].append({
                        'name': input_elem.get_attribute('name') or '',
                        'type': input_elem.get_attribute('type') or 'text',
                        'value': input_elem.get_attribute('value') or ''
                    })
                forms.append(form_data)
        except Exception:
            pass
        return forms

    def extract_links(self) -> list:
        links = []
        try:
            link_elements = self.driver.find_elements(By.TAG_NAME, 'a')
            for link in link_elements[:50]:
                href = link.get_attribute('href')
                if href:
                    links.append({
                        'href': href,
                        'text': link.text[:100]
                    })
        except Exception:
            pass
        return links

    def extract_inputs(self) -> list:
        inputs = []
        try:
            input_elements = self.driver.find_elements(By.TAG_NAME, 'input')
            for input_elem in input_elements:
                inputs.append({
                    'name': input_elem.get_attribute('name') or '',
                    'type': input_elem.get_attribute('type') or 'text',
                    'id': input_elem.get_attribute('id') or '',
                    'placeholder': input_elem.get_attribute('placeholder') or ''
                })
        except Exception:
            pass
        return inputs

    def extract_scripts(self) -> list:
        scripts = []
        try:
            script_elements = self.driver.find_elements(By.TAG_NAME, 'script')
            for script in script_elements[:20]:
                src = script.get_attribute('src')
                if src:
                    scripts.append({'type': 'external', 'src': src})
                else:
                    content = script.get_attribute('innerHTML')
                    if content and len(content) > 10:
                        scripts.append({
                            'type': 'inline',
                            'content': content[:1000]
                        })
        except Exception:
            pass
        return scripts

    def get_network_logs(self) -> list:
        try:
            logs = self.driver.get_log('performance')
            network_requests = []
            for log in logs[-50:]:
                message = json.loads(log['message'])
                if message['message']['method'] == 'Network.responseReceived':
                    response = message['message']['params']['response']
                    network_requests.append({
                        'url': response['url'],
                        'status': response['status'],
                        'mimeType': response['mimeType'],
                        'headers': response.get('headers', {})
                    })
            return network_requests
        except Exception:
            return []


class BrowserSecurityAnalyzer:
    """Passive/active security analysis helpers (the original
    ``_analyze_*``/``_detect_mixed_content``/``_extended_passive_analysis``/
    ``run_active_tests``)."""

    def __init__(self, deps: CoreDependencies):
        self._deps = deps

    def analyze_cookies(self, cookies: list) -> list:
        issues = []
        for ck in cookies:
            name = ck.get('name', '')
            if name.lower() in ('sessionid', 'phpseSSID', 'jsessionid') and len(ck.get('value', '')) < 16:
                issues.append({'type': 'weak_session_cookie', 'severity': 'medium', 'description': f'Session cookie {name} appears short'})
        return issues

    def analyze_security_headers(self, page_source: str, page_info: dict) -> list:
        issues = []
        try:
            page_url = page_info.get('url', '')
            if not self._deps.is_safe_target(page_url):
                return issues
            resp = requests.get(page_url, timeout=10)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            required = {
                'content-security-policy': 'CSP header missing (XSS mitigation)',
                'x-frame-options': 'X-Frame-Options missing (Clickjacking risk)',
                'x-content-type-options': 'X-Content-Type-Options missing (MIME sniffing risk)',
                'referrer-policy': 'Referrer-Policy missing (leaky referrers)',
                'strict-transport-security': 'HSTS missing (HTTPS downgrade risk)'
            }
            for key, desc in required.items():
                if key not in headers:
                    issues.append({'type': 'missing_security_header', 'severity': 'medium', 'description': desc, 'header': key})
            csp = headers.get('content-security-policy', '')
            if csp and "unsafe-inline" in csp:
                issues.append({'type': 'weak_csp', 'severity': 'low', 'description': 'CSP allows unsafe-inline scripts'})
        except Exception:
            pass
        return issues

    def detect_mixed_content(self, page_info: dict) -> list:
        issues = []
        try:
            page_url = page_info.get('url', '')
            if page_url.startswith('https://'):
                for req in page_info.get('network_requests', [])[:200]:
                    u = req.get('url', '')
                    if u.startswith('http://'):
                        issues.append({'type': 'mixed_content', 'severity': 'medium', 'description': f'HTTP resource loaded over HTTPS page: {u[:100]}'})
        except Exception:
            pass
        return issues

    def extended_passive_analysis(self, page_info: dict, page_source: str) -> dict:
        modules = []
        issues = []
        cookie_issues = self.analyze_cookies(page_info.get('cookies', []))
        if cookie_issues:
            issues.extend(cookie_issues); modules.append('cookie_analysis')
        header_issues = self.analyze_security_headers(page_source, page_info)
        if header_issues:
            issues.extend(header_issues); modules.append('security_headers')
        mixed = self.detect_mixed_content(page_info)
        if mixed:
            issues.extend(mixed); modules.append('mixed_content')
        if page_info.get('console_errors'):
            modules.append('console_log_capture')
        return {'issues': issues, 'modules': modules}

    def run_active_tests(self, page_info: dict, payload: str = '<redvectorXSSTest123>') -> dict:
        findings = []
        tested = 0
        for form in page_info.get('forms', []):
            if form.get('method', 'GET').upper() != 'GET':
                continue
            params = []
            for inp in form.get('inputs', [])[:3]:
                if inp.get('type', 'text') in ('text', 'search'):
                    params.append(f"{inp.get('name', 'param')}={payload}")
            if not params:
                continue
            action = form.get('action') or page_info.get('url', '')
            if action.startswith('/'):
                base = page_info.get('url', '')
                try:
                    action = urljoin(base, action)
                except Exception:
                    pass
            test_url = action + ('&' if '?' in action else '?') + '&'.join(params)
            try:
                if not self._deps.is_safe_target(test_url):
                    continue
                r = requests.get(test_url, timeout=8)
                tested += 1
                if payload in r.text:
                    findings.append({'type': 'reflected_xss', 'severity': 'high', 'description': 'Payload reflected in response', 'url': test_url})
            except Exception:
                continue
            if tested >= 5:
                break
        return {'active_findings': findings, 'tested_forms': tested}

    def analyze_page_security(self, page_source: str, page_info: dict) -> dict:
        issues = []
        for storage_type, storage_data in [('localStorage', page_info.get('local_storage', {})),
                                           ('sessionStorage', page_info.get('session_storage', {}))]:
            for key, value in storage_data.items():
                if any(sensitive in key.lower() for sensitive in ['password', 'token', 'secret', 'key']):
                    issues.append({
                        'type': 'sensitive_data_storage',
                        'severity': 'high',
                        'description': f'Sensitive data found in {storage_type}: {key}',
                        'location': storage_type
                    })
        for form in page_info.get('forms', []):
            has_csrf = any('csrf' in input_data['name'].lower() or 'token' in input_data['name'].lower()
                           for input_data in form['inputs'])
            if not has_csrf and form['method'].upper() == 'POST':
                issues.append({
                    'type': 'missing_csrf_protection',
                    'severity': 'medium',
                    'description': 'Form without CSRF protection detected',
                    'form_action': form['action']
                })
        inline_scripts = [s for s in page_info.get('scripts', []) if s['type'] == 'inline']
        if inline_scripts:
            issues.append({
                'type': 'inline_javascript',
                'severity': 'low',
                'description': f'Found {len(inline_scripts)} inline JavaScript blocks',
                'count': len(inline_scripts)
            })
        return {
            'total_issues': len(issues),
            'issues': issues,
            'security_score': max(0, 100 - (len(issues) * 10))
        }


class BrowserAgentService:
    """AI-powered browser agent for web application testing and inspection.

    Orchestrates the session manager, extraction service and security analyzer.
    ``navigate_and_inspect`` reproduces the original control flow verbatim."""

    def __init__(self, deps: Optional[CoreDependencies] = None,
                 driver_factory: Optional[Callable] = None):
        self._deps = deps or CoreDependencies()
        self._session = BrowserSessionManager(self._deps, driver_factory)
        self._extract = BrowserExtractionService(self._session)
        self._analyzer = BrowserSecurityAnalyzer(self._deps)

    # ---- compatibility views over composed state ----
    @property
    def driver(self):
        return self._session.driver

    @driver.setter
    def driver(self, value):
        self._session.driver = value

    @property
    def screenshots(self):
        return self._session.screenshots

    @property
    def page_sources(self):
        return self._session.page_sources

    @property
    def network_logs(self):
        return self._session.network_logs

    # ---- lifecycle (delegate to session manager) ----
    def reset_state(self):
        self._session.reset_state()

    def setup_browser(self, headless: bool = True, proxy_port: int = None):
        return self._session.setup_browser(headless=headless, proxy_port=proxy_port)

    def close_browser(self):
        self._session.close_browser()

    def navigate_and_inspect(self, url: str, wait_time: int = 5) -> dict:
        try:
            if not self._session.driver:
                if not self.setup_browser():
                    return {'success': False, 'error': 'Failed to setup browser'}

            nav_command = f'Navigate to {url}'
            self._deps.logger.info(
                f"{self._deps.visual.format_command_execution(nav_command, 'STARTING')}")

            self._session.driver.get(url)
            time.sleep(wait_time)

            screenshot_path = os.path.join(tempfile.gettempdir(), f"redvector_screenshot_{int(time.time())}.png")
            self._session.driver.save_screenshot(screenshot_path)
            self._session.screenshots.append(screenshot_path)

            page_source = self._session.driver.page_source
            self._session.page_sources.append({
                'url': url,
                'source': page_source[:50000],
                'timestamp': datetime.now().isoformat()
            })

            page_info = {
                'title': self._session.driver.title,
                'url': self._session.driver.current_url,
                'cookies': [{'name': c['name'], 'value': c['value'], 'domain': c['domain']}
                            for c in self._session.driver.get_cookies()],
                'local_storage': self._extract.get_local_storage(),
                'session_storage': self._extract.get_session_storage(),
                'forms': self._extract.extract_forms(),
                'links': self._extract.extract_links(),
                'inputs': self._extract.extract_inputs(),
                'scripts': self._extract.extract_scripts(),
                'network_requests': self._extract.get_network_logs(),
                'console_errors': self._extract.get_console_errors()
            }

            security_analysis = self._analyzer.analyze_page_security(page_source, page_info)
            extended_passive = self._analyzer.extended_passive_analysis(page_info, page_source)
            security_analysis['issues'].extend(extended_passive['issues'])
            security_analysis['total_issues'] = len(security_analysis['issues'])
            security_analysis['security_score'] = max(0, 100 - (security_analysis['total_issues'] * 5))
            security_analysis['passive_modules'] = extended_passive.get('modules', [])

            self._deps.logger.info(
                f"{self._deps.visual.format_tool_status('BrowserAgent', 'SUCCESS', url)}")

            return {
                'success': True,
                'page_info': page_info,
                'security_analysis': security_analysis,
                'screenshot': screenshot_path,
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            self._deps.logger.error(
                f"{self._deps.visual.format_error_card('ERROR', 'BrowserAgent', str(e))}")
            return {'success': False, 'error': str(e)}

    def run_active_tests(self, page_info: dict, payload: str = '<redvectorXSSTest123>') -> dict:
        return self._analyzer.run_active_tests(page_info, payload)

    # ---- externally/internally called helpers preserved as compatibility surface ----
    def _get_console_errors(self):
        return self._extract.get_console_errors()

    def _get_local_storage(self):
        return self._extract.get_local_storage()

    def _get_session_storage(self):
        return self._extract.get_session_storage()

    def _extract_forms(self):
        return self._extract.extract_forms()

    def _extract_links(self):
        return self._extract.extract_links()

    def _extract_inputs(self):
        return self._extract.extract_inputs()

    def _extract_scripts(self):
        return self._extract.extract_scripts()

    def _get_network_logs(self):
        return self._extract.get_network_logs()

    def _analyze_cookies(self, cookies: list):
        return self._analyzer.analyze_cookies(cookies)

    def _analyze_security_headers(self, page_source: str, page_info: dict):
        return self._analyzer.analyze_security_headers(page_source, page_info)

    def _detect_mixed_content(self, page_info: dict):
        return self._analyzer.detect_mixed_content(page_info)

    def _extended_passive_analysis(self, page_info: dict, page_source: str):
        return self._analyzer.extended_passive_analysis(page_info, page_source)

    def _analyze_page_security(self, page_source: str, page_info: dict):
        return self._analyzer.analyze_page_security(page_source, page_info)

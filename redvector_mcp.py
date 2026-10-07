#!/usr/bin/env python3
"""
RedVector AI MCP Client - Licensed Red Team Operations Platform

Commercial-grade adversary simulation and red team automation.
🎯 Red Team Operations | Adversary Simulation | Exploit Orchestration | Post-Exploitation

RECENT ENHANCEMENTS (v2.0):
✅ Complete color consistency with reddish hacker theme
✅ Enhanced visual output with consistent styling
✅ Improved error handling and recovery systems
✅ FastMCP integration for seamless AI communication
✅ 150+ security tools with intelligent parameter optimization
✅ Advanced logging with colored output and emojis
✅ Red team workflow orchestration and reporting

Architecture: MCP Client for AI agent communication with RedVector server
Framework: FastMCP integration for tool orchestration

LICENSE: Commercial - Authorized Red Team Use Only
"""

import sys
import os
import argparse
import json
import logging
from typing import Dict, Any, Optional
import urllib.parse
import requests
import time
from datetime import datetime

from mcp.server.fastmcp import FastMCP

import redvector_mcp_core as _mcp_core
import redvector_mcp_declarative as _mcp_decl  # Phase 2B: declarative registration

# Phase 2: central, inspectable registry of every registered MCP tool. Populated
# (in registration order) during setup_mcp_server. Phase 2B registers the
# provably-safe migration set from declarative specs (source of truth) and
# retains the remaining complex tools as explicit custom handlers.
MCP_TOOL_REGISTRY = _mcp_core.MCPToolRegistry()

SENSITIVE_KEYS = {
    "authorization", "api_key", "apikey", "password", "passwd", "secret",
    "token", "jwt_token", "cookie", "cookies"
}


def _redact_sensitive_mapping(data: Dict[str, Any]) -> Dict[str, Any]:
    """Redact sensitive values before logging request payloads."""
    redacted = {}
    for key, value in data.items():
        if key.lower() in SENSITIVE_KEYS and value:
            redacted[key] = "***REDACTED***"
        else:
            redacted[key] = value
    return redacted

class RedVectorColors:
    """Enhanced color palette matching the server's ModernVisualEngine.COLORS"""

    # Basic colors (for backward compatibility)
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'

    # Core enhanced colors
    MATRIX_GREEN = '\033[38;5;46m'
    NEON_BLUE = '\033[38;5;51m'
    ELECTRIC_PURPLE = '\033[38;5;129m'
    CYBER_ORANGE = '\033[38;5;208m'
    HACKER_RED = '\033[38;5;196m'
    TERMINAL_GRAY = '\033[38;5;240m'
    BRIGHT_WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    # Enhanced reddish tones and highlighting colors
    BLOOD_RED = '\033[38;5;124m'
    CRIMSON = '\033[38;5;160m'
    DARK_RED = '\033[38;5;88m'
    FIRE_RED = '\033[38;5;202m'
    ROSE_RED = '\033[38;5;167m'
    BURGUNDY = '\033[38;5;52m'
    SCARLET = '\033[38;5;197m'
    RUBY = '\033[38;5;161m'

    # Highlighting colors
    HIGHLIGHT_RED = '\033[48;5;196m\033[38;5;15m'  # Red background, white text
    HIGHLIGHT_YELLOW = '\033[48;5;226m\033[38;5;16m'  # Yellow background, black text
    HIGHLIGHT_GREEN = '\033[48;5;46m\033[38;5;16m'  # Green background, black text
    HIGHLIGHT_BLUE = '\033[48;5;51m\033[38;5;16m'  # Blue background, black text
    HIGHLIGHT_PURPLE = '\033[48;5;129m\033[38;5;15m'  # Purple background, white text

    # Status colors with reddish tones
    SUCCESS = '\033[38;5;46m'  # Bright green
    WARNING = '\033[38;5;208m'  # Orange
    ERROR = '\033[38;5;196m'  # Bright red
    CRITICAL = '\033[48;5;196m\033[38;5;15m\033[1m'  # Red background, white bold text
    INFO = '\033[38;5;51m'  # Cyan
    DEBUG = '\033[38;5;240m'  # Gray

    # Vulnerability severity colors
    VULN_CRITICAL = '\033[48;5;124m\033[38;5;15m\033[1m'  # Dark red background
    VULN_HIGH = '\033[38;5;196m\033[1m'  # Bright red bold
    VULN_MEDIUM = '\033[38;5;208m\033[1m'  # Orange bold
    VULN_LOW = '\033[38;5;226m'  # Yellow
    VULN_INFO = '\033[38;5;51m'  # Cyan

    # Tool status colors
    TOOL_RUNNING = '\033[38;5;46m\033[5m'  # Blinking green
    TOOL_SUCCESS = '\033[38;5;46m\033[1m'  # Bold green
    TOOL_FAILED = '\033[38;5;196m\033[1m'  # Bold red
    TOOL_TIMEOUT = '\033[38;5;208m\033[1m'  # Bold orange
    TOOL_RECOVERY = '\033[38;5;129m\033[1m'  # Bold purple

# Backward compatibility alias
Colors = RedVectorColors

class ColoredFormatter(logging.Formatter):
    """Enhanced formatter with colors and emojis for MCP client - matches server styling"""

    COLORS = {
        'DEBUG': RedVectorColors.DEBUG,
        'INFO': RedVectorColors.SUCCESS,
        'WARNING': RedVectorColors.WARNING,
        'ERROR': RedVectorColors.ERROR,
        'CRITICAL': RedVectorColors.CRITICAL
    }

    EMOJIS = {
        'DEBUG': '🔍',
        'INFO': '✅',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '🔥'
    }

    def format(self, record):
        emoji = self.EMOJIS.get(record.levelname, '📝')
        color = self.COLORS.get(record.levelname, RedVectorColors.BRIGHT_WHITE)

        # Add color and emoji to the message
        record.msg = f"{color}{emoji} {record.msg}{RedVectorColors.RESET}"
        return super().format(record)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[🔥 RedVector MCP] %(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr)
    ]
)

# Apply colored formatter
for handler in logging.getLogger().handlers:
    handler.setFormatter(ColoredFormatter(
        "[🔥 RedVector MCP] %(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

logger = logging.getLogger(__name__)

# Default configuration
import redvector_config as _config  # Phase 4: typed configuration + provenance
DEFAULT_REDVECTOR_SERVER = _config.MCP_DEFAULT_SERVER  # Default RedVector server URL
DEFAULT_REQUEST_TIMEOUT = _config.MCP_DEFAULT_TIMEOUT  # 5 minutes default timeout for API requests
MAX_RETRIES = _config.MCP_MAX_RETRIES  # Maximum number of retries for connection attempts

class RedVectorClient:
    """Enhanced client for communicating with the RedVector AI API Server"""

    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize the RedVector AI Client

        Args:
            server_url: URL of the RedVector AI API Server
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.api_token = _config.resolve_mcp().api_token  # Phase 4: typed config
        self.session.headers.update({"Authorization": f"Bearer {self.api_token}"})

        # Phase 2: centralized transport + error/result normalization. The
        # safe_* methods below are now thin compatibility adapters over this,
        # preserving their exact behavior (URL, json/params placement, timeout,
        # raise_for_status, debug logging with redaction, and error dicts).
        self._transport = _mcp_core.MCPTransportAdapter(
            session=self.session,
            server_url=self.server_url,
            timeout=self.timeout,
            logger=logger,
            redact=_redact_sensitive_mapping,
        )

        parsed_server = urllib.parse.urlparse(self.server_url)
        local_hosts = {"127.0.0.1", "localhost"}
        allow_insecure = _config.resolve_mcp().allow_insecure  # Phase 4: typed config
        if parsed_server.scheme != "https" and parsed_server.hostname not in local_hosts and not allow_insecure:
            raise ValueError("HTTPS is required for non-local RedVector server URLs")

        # Try to connect to server with retries
        connected = False
        for i in range(MAX_RETRIES):
            try:
                logger.info(f"🔗 Attempting to connect to RedVector AI API at {server_url} (attempt {i+1}/{MAX_RETRIES})")
                # First try a direct connection test before using the health endpoint
                try:
                    test_response = self.session.get(f"{self.server_url}/health", timeout=5)
                    test_response.raise_for_status()
                    health_check = test_response.json()
                    connected = True
                    logger.info(f"🎯 Successfully connected to RedVector AI API Server at {server_url}")
                    logger.info(f"🏥 Server health status: {health_check.get('status', 'unknown')}")
                    logger.info(f"📊 Server version: {health_check.get('version', 'unknown')}")
                    break
                except requests.exceptions.ConnectionError:
                    logger.warning(f"🔌 Connection refused to {server_url}. Make sure the RedVector AI server is running.")
                    time.sleep(2)  # Wait before retrying
                except Exception as e:
                    logger.warning(f"⚠️  Connection test failed: {str(e)}")
                    time.sleep(2)  # Wait before retrying
            except Exception as e:
                logger.warning(f"❌ Connection attempt {i+1} failed: {str(e)}")
                time.sleep(2)  # Wait before retrying

        if not connected:
            error_msg = f"Failed to establish connection to RedVector AI API Server at {server_url} after {MAX_RETRIES} attempts"
            logger.error(error_msg)
            # We'll continue anyway to allow the MCP server to start, but tools will likely fail

    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform a GET request with optional query parameters.

        Args:
            endpoint: API endpoint path (without leading slash)
            params: Optional query parameters

        Returns:
            Response data as dictionary
        """
        return self._transport.get(endpoint, params)

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a POST request with JSON data.

        Args:
            endpoint: API endpoint path (without leading slash)
            json_data: JSON data to send

        Returns:
            Response data as dictionary
        """
        return self._transport.post(endpoint, json_data)

    def safe_delete(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a DELETE request with JSON data.

        Args:
            endpoint: API endpoint path (without leading slash)
            json_data: JSON data to send

        Returns:
            Response data as dictionary
        """
        return self._transport.delete(endpoint, json_data)

    def execute_command(self, command: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Execute a generic command on the RedVector server

        Args:
            command: Command to execute
            use_cache: Whether to use caching for this command

        Returns:
            Command execution results
        """
        return self.safe_post("api/command", {"command": command, "use_cache": use_cache})

    def check_health(self) -> Dict[str, Any]:
        """
        Check the health of the RedVector AI API Server

        Returns:
            Health status information
        """
        return self.safe_get("health")

def setup_mcp_server(redvector_client: RedVectorClient) -> FastMCP:
    """
    Set up the MCP server with all enhanced tool functions

    Args:
        redvector_client: Initialized RedVectorClient

    Returns:
        Configured FastMCP instance
    """
    mcp = FastMCP("redvector-ai-mcp")

    # Phase 2B: register each @mcp.tool() in source order. Tools in the proven
    # migration set are generated from their declarative spec (source of truth,
    # handler_type="generic") and registered through the framework; the legacy
    # wrapper body for those is NOT also registered. All other tools register
    # exactly as before (handler_type="wrapper"). Registration order and the
    # one-registration-per-tool guarantee are preserved.
    MCP_TOOL_REGISTRY.clear()
    mcp = _mcp_decl.instrument_registration_declarative(
        mcp, MCP_TOOL_REGISTRY, _mcp_decl.TOOL_SPECS, _mcp_decl.MIGRATED_TOOLS,
        redvector_client, logger)

    # ============================================================================
    # CORE NETWORK SCANNING TOOLS
    # ============================================================================

    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute an enhanced Nmap scan against a target with real-time logging.

        Args:
            target: The IP address or hostname to scan
            scan_type: Scan type (e.g., -sV for version detection, -sC for scripts)
            ports: Comma-separated list of ports or port ranges
            additional_args: Additional Nmap arguments

        Returns:
            Scan results with enhanced telemetry
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": additional_args
        }
        logger.info(f"{RedVectorColors.FIRE_RED}🔍 Initiating Nmap scan: {target}{RedVectorColors.RESET}")

        # Use enhanced error handling by default
        data["use_recovery"] = True
        result = redvector_client.safe_post("api/tools/nmap", data)

        if result.get("success"):
            logger.info(f"{RedVectorColors.SUCCESS}✅ Nmap scan completed successfully for {target}{RedVectorColors.RESET}")

            # Check for recovery information
            if result.get("recovery_info", {}).get("recovery_applied"):
                recovery_info = result["recovery_info"]
                attempts = recovery_info.get("attempts_made", 1)
                logger.info(f"{RedVectorColors.HIGHLIGHT_YELLOW} Recovery applied: {attempts} attempts made {RedVectorColors.RESET}")
        else:
            logger.error(f"{RedVectorColors.ERROR}❌ Nmap scan failed for {target}{RedVectorColors.RESET}")

            # Check for human escalation
            if result.get("human_escalation"):
                logger.error(f"{RedVectorColors.CRITICAL} HUMAN ESCALATION REQUIRED {RedVectorColors.RESET}")

        return result

    @mcp.tool()
    def gobuster_scan(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Gobuster to find directories, DNS subdomains, or virtual hosts with enhanced logging.

        Args:
            url: The target URL
            mode: Scan mode (dir, dns, fuzz, vhost)
            wordlist: Path to wordlist file
            additional_args: Additional Gobuster arguments

        Returns:
            Scan results with enhanced telemetry
        """
        data = {
            "url": url,
            "mode": mode,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        logger.info(f"{RedVectorColors.CRIMSON}📁 Starting Gobuster {mode} scan: {url}{RedVectorColors.RESET}")

        # Use enhanced error handling by default
        data["use_recovery"] = True
        result = redvector_client.safe_post("api/tools/gobuster", data)

        if result.get("success"):
            logger.info(f"{RedVectorColors.SUCCESS}✅ Gobuster scan completed for {url}{RedVectorColors.RESET}")

            # Check for recovery information
            if result.get("recovery_info", {}).get("recovery_applied"):
                recovery_info = result["recovery_info"]
                attempts = recovery_info.get("attempts_made", 1)
                logger.info(f"{RedVectorColors.HIGHLIGHT_YELLOW} Recovery applied: {attempts} attempts made {RedVectorColors.RESET}")
        else:
            logger.error(f"{RedVectorColors.ERROR}❌ Gobuster scan failed for {url}{RedVectorColors.RESET}")

            # Check for alternative tool suggestion
            if result.get("alternative_tool_suggested"):
                alt_tool = result["alternative_tool_suggested"]
                logger.info(f"{RedVectorColors.HIGHLIGHT_BLUE} Alternative tool suggested: {alt_tool} {RedVectorColors.RESET}")

        return result

    @mcp.tool()
    def nuclei_scan(target: str, severity: str = "", tags: str = "", template: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nuclei vulnerability scanner with enhanced logging and real-time progress.

        Args:
            target: The target URL or IP
            severity: Filter by severity (critical,high,medium,low,info)
            tags: Filter by tags (e.g. cve,rce,lfi)
            template: Custom template path
            additional_args: Additional Nuclei arguments

        Returns:
            Scan results with discovered vulnerabilities and telemetry
        """
        data = {
            "target": target,
            "severity": severity,
            "tags": tags,
            "template": template,
            "additional_args": additional_args
        }
        logger.info(f"{RedVectorColors.BLOOD_RED}🔬 Starting Nuclei vulnerability scan: {target}{RedVectorColors.RESET}")

        # Use enhanced error handling by default
        data["use_recovery"] = True
        result = redvector_client.safe_post("api/tools/nuclei", data)

        if result.get("success"):
            logger.info(f"{RedVectorColors.SUCCESS}✅ Nuclei scan completed for {target}{RedVectorColors.RESET}")

            # Enhanced vulnerability reporting
            if result.get("stdout") and "CRITICAL" in result["stdout"]:
                logger.warning(f"{RedVectorColors.CRITICAL} CRITICAL vulnerabilities detected! {RedVectorColors.RESET}")
            elif result.get("stdout") and "HIGH" in result["stdout"]:
                logger.warning(f"{RedVectorColors.FIRE_RED} HIGH severity vulnerabilities found! {RedVectorColors.RESET}")

            # Check for recovery information
            if result.get("recovery_info", {}).get("recovery_applied"):
                recovery_info = result["recovery_info"]
                attempts = recovery_info.get("attempts_made", 1)
                logger.info(f"{RedVectorColors.HIGHLIGHT_YELLOW} Recovery applied: {attempts} attempts made {RedVectorColors.RESET}")
        else:
            logger.error(f"{RedVectorColors.ERROR}❌ Nuclei scan failed for {target}{RedVectorColors.RESET}")

        return result

    # ============================================================================
    # CLOUD SECURITY TOOLS
    # ============================================================================

    @mcp.tool()
    def prowler_scan(provider: str = "aws", profile: str = "default", region: str = "", checks: str = "", output_dir: str = "/tmp/prowler_output", output_format: str = "json", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Prowler for comprehensive cloud security assessment.

        Args:
            provider: Cloud provider (aws, azure, gcp)
            profile: AWS profile to use
            region: Specific region to scan
            checks: Specific checks to run
            output_dir: Directory to save results
            output_format: Output format (json, csv, html)
            additional_args: Additional Prowler arguments

        Returns:
            Cloud security assessment results
        """
        data = {
            "provider": provider,
            "profile": profile,
            "region": region,
            "checks": checks,
            "output_dir": output_dir,
            "output_format": output_format,
            "additional_args": additional_args
        }
        logger.info(f"☁️  Starting Prowler {provider} security assessment")
        result = redvector_client.safe_post("api/tools/prowler", data)
        if result.get("success"):
            logger.info(f"✅ Prowler assessment completed")
        else:
            logger.error(f"❌ Prowler assessment failed")
        return result

    @mcp.tool()
    def trivy_scan(scan_type: str = "image", target: str = "", output_format: str = "json", severity: str = "", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Trivy for container and filesystem vulnerability scanning.

        Args:
            scan_type: Type of scan (image, fs, repo, config)
            target: Target to scan (image name, directory, repository)
            output_format: Output format (json, table, sarif)
            severity: Severity filter (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL)
            output_file: File to save results
            additional_args: Additional Trivy arguments

        Returns:
            Vulnerability scan results
        """
        data = {
            "scan_type": scan_type,
            "target": target,
            "output_format": output_format,
            "severity": severity,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Trivy {scan_type} scan: {target}")
        result = redvector_client.safe_post("api/tools/trivy", data)
        if result.get("success"):
            logger.info(f"✅ Trivy scan completed for {target}")
        else:
            logger.error(f"❌ Trivy scan failed for {target}")
        return result

    # ============================================================================
    # ENHANCED CLOUD AND CONTAINER SECURITY TOOLS (v2.0)
    # ============================================================================

    @mcp.tool()
    def scout_suite_assessment(provider: str = "aws", profile: str = "default",
                              report_dir: str = "/tmp/scout-suite", services: str = "",
                              exceptions: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Scout Suite for multi-cloud security assessment.

        Args:
            provider: Cloud provider (aws, azure, gcp, aliyun, oci)
            profile: AWS profile to use
            report_dir: Directory to save reports
            services: Specific services to assess
            exceptions: Exceptions file path
            additional_args: Additional Scout Suite arguments

        Returns:
            Multi-cloud security assessment results
        """
        data = {
            "provider": provider,
            "profile": profile,
            "report_dir": report_dir,
            "services": services,
            "exceptions": exceptions,
            "additional_args": additional_args
        }
        logger.info(f"☁️  Starting Scout Suite {provider} assessment")
        result = redvector_client.safe_post("api/tools/scout-suite", data)
        if result.get("success"):
            logger.info(f"✅ Scout Suite assessment completed")
        else:
            logger.error(f"❌ Scout Suite assessment failed")
        return result

    @mcp.tool()
    def cloudmapper_analysis(action: str = "collect", account: str = "",
                            config: str = "config.json", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute CloudMapper for AWS network visualization and security analysis.

        Args:
            action: Action to perform (collect, prepare, webserver, find_admins, etc.)
            account: AWS account to analyze
            config: Configuration file path
            additional_args: Additional CloudMapper arguments

        Returns:
            AWS network visualization and security analysis results
        """
        data = {
            "action": action,
            "account": account,
            "config": config,
            "additional_args": additional_args
        }
        logger.info(f"☁️  Starting CloudMapper {action}")
        result = redvector_client.safe_post("api/tools/cloudmapper", data)
        if result.get("success"):
            logger.info(f"✅ CloudMapper {action} completed")
        else:
            logger.error(f"❌ CloudMapper {action} failed")
        return result

    @mcp.tool()
    def pacu_exploitation(session_name: str = "redvector_session", modules: str = "",
                         data_services: str = "", regions: str = "",
                         additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Pacu for AWS exploitation framework.

        Args:
            session_name: Pacu session name
            modules: Comma-separated list of modules to run
            data_services: Data services to enumerate
            regions: AWS regions to target
            additional_args: Additional Pacu arguments

        Returns:
            AWS exploitation framework results
        """
        data = {
            "session_name": session_name,
            "modules": modules,
            "data_services": data_services,
            "regions": regions,
            "additional_args": additional_args
        }
        logger.info(f"☁️  Starting Pacu AWS exploitation")
        result = redvector_client.safe_post("api/tools/pacu", data)
        if result.get("success"):
            logger.info(f"✅ Pacu exploitation completed")
        else:
            logger.error(f"❌ Pacu exploitation failed")
        return result

    @mcp.tool()
    def kube_hunter_scan(target: str = "", remote: str = "", cidr: str = "",
                        interface: str = "", active: bool = False, report: str = "json",
                        additional_args: str = "") -> Dict[str, Any]:
        """
        Execute kube-hunter for Kubernetes penetration testing.

        Args:
            target: Specific target to scan
            remote: Remote target to scan
            cidr: CIDR range to scan
            interface: Network interface to scan
            active: Enable active hunting (potentially harmful)
            report: Report format (json, yaml)
            additional_args: Additional kube-hunter arguments

        Returns:
            Kubernetes penetration testing results
        """
        data = {
            "target": target,
            "remote": remote,
            "cidr": cidr,
            "interface": interface,
            "active": active,
            "report": report,
            "additional_args": additional_args
        }
        logger.info(f"☁️  Starting kube-hunter Kubernetes scan")
        result = redvector_client.safe_post("api/tools/kube-hunter", data)
        if result.get("success"):
            logger.info(f"✅ kube-hunter scan completed")
        else:
            logger.error(f"❌ kube-hunter scan failed")
        return result

    @mcp.tool()
    def kube_bench_cis(targets: str = "", version: str = "", config_dir: str = "",
                      output_format: str = "json", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute kube-bench for CIS Kubernetes benchmark checks.

        Args:
            targets: Targets to check (master, node, etcd, policies)
            version: Kubernetes version
            config_dir: Configuration directory
            output_format: Output format (json, yaml)
            additional_args: Additional kube-bench arguments

        Returns:
            CIS Kubernetes benchmark results
        """
        data = {
            "targets": targets,
            "version": version,
            "config_dir": config_dir,
            "output_format": output_format,
            "additional_args": additional_args
        }
        logger.info(f"☁️  Starting kube-bench CIS benchmark")
        result = redvector_client.safe_post("api/tools/kube-bench", data)
        if result.get("success"):
            logger.info(f"✅ kube-bench benchmark completed")
        else:
            logger.error(f"❌ kube-bench benchmark failed")
        return result

    @mcp.tool()
    def docker_bench_security_scan(checks: str = "", exclude: str = "",
                                  output_file: str = "/tmp/docker-bench-results.json",
                                  additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Docker Bench for Security for Docker security assessment.

        Args:
            checks: Specific checks to run
            exclude: Checks to exclude
            output_file: Output file path
            additional_args: Additional Docker Bench arguments

        Returns:
            Docker security assessment results
        """
        data = {
            "checks": checks,
            "exclude": exclude,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🐳 Starting Docker Bench Security assessment")
        result = redvector_client.safe_post("api/tools/docker-bench-security", data)
        if result.get("success"):
            logger.info(f"✅ Docker Bench Security completed")
        else:
            logger.error(f"❌ Docker Bench Security failed")
        return result

    @mcp.tool()
    def clair_vulnerability_scan(image: str, config: str = "/etc/clair/config.yaml",
                                output_format: str = "json", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Clair for container vulnerability analysis.

        Args:
            image: Container image to scan
            config: Clair configuration file
            output_format: Output format (json, yaml)
            additional_args: Additional Clair arguments

        Returns:
            Container vulnerability analysis results
        """
        data = {
            "image": image,
            "config": config,
            "output_format": output_format,
            "additional_args": additional_args
        }
        logger.info(f"🐳 Starting Clair vulnerability scan: {image}")
        result = redvector_client.safe_post("api/tools/clair", data)
        if result.get("success"):
            logger.info(f"✅ Clair scan completed for {image}")
        else:
            logger.error(f"❌ Clair scan failed for {image}")
        return result

    @mcp.tool()
    def falco_runtime_monitoring(config_file: str = "/etc/falco/falco.yaml",
                                rules_file: str = "", output_format: str = "json",
                                duration: int = 60, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Falco for runtime security monitoring.

        Args:
            config_file: Falco configuration file
            rules_file: Custom rules file
            output_format: Output format (json, text)
            duration: Monitoring duration in seconds
            additional_args: Additional Falco arguments

        Returns:
            Runtime security monitoring results
        """
        data = {
            "config_file": config_file,
            "rules_file": rules_file,
            "output_format": output_format,
            "duration": duration,
            "additional_args": additional_args
        }
        logger.info(f"🛡️  Starting Falco runtime monitoring for {duration}s")
        result = redvector_client.safe_post("api/tools/falco", data)
        if result.get("success"):
            logger.info(f"✅ Falco monitoring completed")
        else:
            logger.error(f"❌ Falco monitoring failed")
        return result

    @mcp.tool()
    def checkov_iac_scan(directory: str = ".", framework: str = "", check: str = "",
                        skip_check: str = "", output_format: str = "json",
                        additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Checkov for infrastructure as code security scanning.

        Args:
            directory: Directory to scan
            framework: Framework to scan (terraform, cloudformation, kubernetes, etc.)
            check: Specific check to run
            skip_check: Check to skip
            output_format: Output format (json, yaml, cli)
            additional_args: Additional Checkov arguments

        Returns:
            Infrastructure as code security scanning results
        """
        data = {
            "directory": directory,
            "framework": framework,
            "check": check,
            "skip_check": skip_check,
            "output_format": output_format,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Checkov IaC scan: {directory}")
        result = redvector_client.safe_post("api/tools/checkov", data)
        if result.get("success"):
            logger.info(f"✅ Checkov scan completed")
        else:
            logger.error(f"❌ Checkov scan failed")
        return result

    @mcp.tool()
    def terrascan_iac_scan(scan_type: str = "all", iac_dir: str = ".",
                          policy_type: str = "", output_format: str = "json",
                          severity: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Terrascan for infrastructure as code security scanning.

        Args:
            scan_type: Type of scan (all, terraform, k8s, etc.)
            iac_dir: Infrastructure as code directory
            policy_type: Policy type to use
            output_format: Output format (json, yaml, xml)
            severity: Severity filter (high, medium, low)
            additional_args: Additional Terrascan arguments

        Returns:
            Infrastructure as code security scanning results
        """
        data = {
            "scan_type": scan_type,
            "iac_dir": iac_dir,
            "policy_type": policy_type,
            "output_format": output_format,
            "severity": severity,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Terrascan IaC scan: {iac_dir}")
        result = redvector_client.safe_post("api/tools/terrascan", data)
        if result.get("success"):
            logger.info(f"✅ Terrascan scan completed")
        else:
            logger.error(f"❌ Terrascan scan failed")
        return result

    # ============================================================================
    # FILE OPERATIONS & PAYLOAD GENERATION
    # ============================================================================

    @mcp.tool()
    def create_file(filename: str, content: str, binary: bool = False) -> Dict[str, Any]:
        """
        Create a file with specified content on the RedVector server.

        Args:
            filename: Name of the file to create
            content: Content to write to the file
            binary: Whether the content is binary data

        Returns:
            File creation results
        """
        data = {
            "filename": filename,
            "content": content,
            "binary": binary
        }
        logger.info(f"📄 Creating file: {filename}")
        result = redvector_client.safe_post("api/files/create", data)
        if result.get("success"):
            logger.info(f"✅ File created successfully: {filename}")
        else:
            logger.error(f"❌ Failed to create file: {filename}")
        return result

    @mcp.tool()
    def modify_file(filename: str, content: str, append: bool = False) -> Dict[str, Any]:
        """
        Modify an existing file on the RedVector server.

        Args:
            filename: Name of the file to modify
            content: Content to write or append
            append: Whether to append to the file (True) or overwrite (False)

        Returns:
            File modification results
        """
        data = {
            "filename": filename,
            "content": content,
            "append": append
        }
        logger.info(f"✏️  Modifying file: {filename}")
        result = redvector_client.safe_post("api/files/modify", data)
        if result.get("success"):
            logger.info(f"✅ File modified successfully: {filename}")
        else:
            logger.error(f"❌ Failed to modify file: {filename}")
        return result

    @mcp.tool()
    def delete_file(filename: str) -> Dict[str, Any]:
        """
        Delete a file or directory on the RedVector server.

        Args:
            filename: Name of the file or directory to delete

        Returns:
            File deletion results
        """
        data = {
            "filename": filename
        }
        logger.info(f"🗑️  Deleting file: {filename}")
        result = redvector_client.safe_delete("api/files/delete", data)
        if result.get("success"):
            logger.info(f"✅ File deleted successfully: {filename}")
        else:
            logger.error(f"❌ Failed to delete file: {filename}")
        return result

    @mcp.tool()
    def list_files(directory: str = ".") -> Dict[str, Any]:
        """
        List files in a directory on the RedVector server.

        Args:
            directory: Directory to list (relative to server's base directory)

        Returns:
            Directory listing results
        """
        logger.info(f"📂 Listing files in directory: {directory}")
        result = redvector_client.safe_get("api/files/list", {"directory": directory})
        if result.get("success"):
            file_count = len(result.get("files", []))
            logger.info(f"✅ Listed {file_count} files in {directory}")
        else:
            logger.error(f"❌ Failed to list files in {directory}")
        return result

    @mcp.tool()
    def generate_payload(payload_type: str = "buffer", size: int = 1024, pattern: str = "A", filename: str = "") -> Dict[str, Any]:
        """
        Generate large payloads for testing and exploitation.

        Args:
            payload_type: Type of payload (buffer, cyclic, random)
            size: Size of the payload in bytes
            pattern: Pattern to use for buffer payloads
            filename: Custom filename (auto-generated if empty)

        Returns:
            Payload generation results
        """
        data = {
            "type": payload_type,
            "size": size,
            "pattern": pattern
        }
        if filename:
            data["filename"] = filename

        logger.info(f"🎯 Generating {payload_type} payload: {size} bytes")
        result = redvector_client.safe_post("api/payloads/generate", data)
        if result.get("success"):
            logger.info(f"✅ Payload generated successfully")
        else:
            logger.error(f"❌ Failed to generate payload")
        return result

    # ============================================================================
    # PYTHON ENVIRONMENT MANAGEMENT
    # ============================================================================

    @mcp.tool()
    def install_python_package(package: str, env_name: str = "default") -> Dict[str, Any]:
        """
        Install a Python package in a virtual environment on the RedVector server.

        Args:
            package: Name of the Python package to install
            env_name: Name of the virtual environment

        Returns:
            Package installation results
        """
        data = {
            "package": package,
            "env_name": env_name
        }
        logger.info(f"📦 Installing Python package: {package} in env {env_name}")
        result = redvector_client.safe_post("api/python/install", data)
        if result.get("success"):
            logger.info(f"✅ Package {package} installed successfully")
        else:
            logger.error(f"❌ Failed to install package {package}")
        return result

    @mcp.tool()
    def execute_python_script(script: str, env_name: str = "default", filename: str = "") -> Dict[str, Any]:
        """
        Execute a Python script in a virtual environment on the RedVector server.

        Args:
            script: Python script content to execute
            env_name: Name of the virtual environment
            filename: Custom script filename (auto-generated if empty)

        Returns:
            Script execution results
        """
        data = {
            "script": script,
            "env_name": env_name
        }
        if filename:
            data["filename"] = filename

        logger.info(f"🐍 Executing Python script in env {env_name}")
        result = redvector_client.safe_post("api/python/execute", data)
        if result.get("success"):
            logger.info(f"✅ Python script executed successfully")
        else:
            logger.error(f"❌ Python script execution failed")
        return result

    # ============================================================================
    # ADDITIONAL SECURITY TOOLS FROM ORIGINAL IMPLEMENTATION
    # ============================================================================

    @mcp.tool()
    def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dirb for directory brute forcing with enhanced logging.

        Args:
            url: The target URL
            wordlist: Path to wordlist file
            additional_args: Additional Dirb arguments

        Returns:
            Scan results with enhanced telemetry
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        logger.info(f"📁 Starting Dirb scan: {url}")
        result = redvector_client.safe_post("api/tools/dirb", data)
        if result.get("success"):
            logger.info(f"✅ Dirb scan completed for {url}")
        else:
            logger.error(f"❌ Dirb scan failed for {url}")
        return result

    @mcp.tool()
    def nikto_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nikto web vulnerability scanner with enhanced logging.

        Args:
            target: The target URL or IP
            additional_args: Additional Nikto arguments

        Returns:
            Scan results with discovered vulnerabilities
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        logger.info(f"🔬 Starting Nikto scan: {target}")
        result = redvector_client.safe_post("api/tools/nikto", data)
        if result.get("success"):
            logger.info(f"✅ Nikto scan completed for {target}")
        else:
            logger.error(f"❌ Nikto scan failed for {target}")
        return result

    @mcp.tool()
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute SQLMap for SQL injection testing with enhanced logging.

        Args:
            url: The target URL
            data: POST data for testing
            additional_args: Additional SQLMap arguments

        Returns:
            SQL injection test results
        """
        data_payload = {
            "url": url,
            "data": data,
            "additional_args": additional_args
        }
        logger.info(f"💉 Starting SQLMap scan: {url}")
        result = redvector_client.safe_post("api/tools/sqlmap", data_payload)
        if result.get("success"):
            logger.info(f"✅ SQLMap scan completed for {url}")
        else:
            logger.error(f"❌ SQLMap scan failed for {url}")
        return result

    @mcp.tool()
    def metasploit_run(module: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute a Metasploit module with enhanced logging.

        Args:
            module: The Metasploit module to use
            options: Dictionary of module options

        Returns:
            Metasploit execution results
        """
        if options is None:
            options = {}
        data = {
            "module": module,
            "options": options
        }
        logger.info(f"🚀 Starting Metasploit module: {module}")
        result = redvector_client.safe_post("api/tools/metasploit", data)
        if result.get("success"):
            logger.info(f"✅ Metasploit module completed: {module}")
        else:
            logger.error(f"❌ Metasploit module failed: {module}")
        return result

    @mcp.tool()
    def hydra_attack(
        target: str,
        service: str,
        username: str = "",
        username_file: str = "",
        password: str = "",
        password_file: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Hydra for password brute forcing with enhanced logging.

        Args:
            target: The target IP or hostname
            service: The service to attack (ssh, ftp, http, etc.)
            username: Single username to test
            username_file: File containing usernames
            password: Single password to test
            password_file: File containing passwords
            additional_args: Additional Hydra arguments

        Returns:
            Brute force attack results
        """
        data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        logger.info(f"🔑 Starting Hydra attack: {target}:{service}")
        result = redvector_client.safe_post("api/tools/hydra", data)
        if result.get("success"):
            logger.info(f"✅ Hydra attack completed for {target}")
        else:
            logger.error(f"❌ Hydra attack failed for {target}")
        return result

    @mcp.tool()
    def john_crack(
        hash_file: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        format_type: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute John the Ripper for password cracking with enhanced logging.

        Args:
            hash_file: File containing password hashes
            wordlist: Wordlist file to use
            format_type: Hash format type
            additional_args: Additional John arguments

        Returns:
            Password cracking results
        """
        data = {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "format": format_type,
            "additional_args": additional_args
        }
        logger.info(f"🔐 Starting John the Ripper: {hash_file}")
        result = redvector_client.safe_post("api/tools/john", data)
        if result.get("success"):
            logger.info(f"✅ John the Ripper completed")
        else:
            logger.error(f"❌ John the Ripper failed")
        return result

    @mcp.tool()
    def wpscan_analyze(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute WPScan for WordPress vulnerability scanning with enhanced logging.

        Args:
            url: The WordPress site URL
            additional_args: Additional WPScan arguments

        Returns:
            WordPress vulnerability scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting WPScan: {url}")
        result = redvector_client.safe_post("api/tools/wpscan", data)
        if result.get("success"):
            logger.info(f"✅ WPScan completed for {url}")
        else:
            logger.error(f"❌ WPScan failed for {url}")
        return result

    @mcp.tool()
    def enum4linux_scan(target: str, additional_args: str = "-a") -> Dict[str, Any]:
        """
        Execute Enum4linux for SMB enumeration with enhanced logging.

        Args:
            target: The target IP address
            additional_args: Additional Enum4linux arguments

        Returns:
            SMB enumeration results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Enum4linux: {target}")
        result = redvector_client.safe_post("api/tools/enum4linux", data)
        if result.get("success"):
            logger.info(f"✅ Enum4linux completed for {target}")
        else:
            logger.error(f"❌ Enum4linux failed for {target}")
        return result

    @mcp.tool()
    def ffuf_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", mode: str = "directory", match_codes: str = "200,204,301,302,307,401,403", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute FFuf for web fuzzing with enhanced logging.

        Args:
            url: The target URL
            wordlist: Wordlist file to use
            mode: Fuzzing mode (directory, vhost, parameter)
            match_codes: HTTP status codes to match
            additional_args: Additional FFuf arguments

        Returns:
            Web fuzzing results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "mode": mode,
            "match_codes": match_codes,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting FFuf {mode} fuzzing: {url}")
        result = redvector_client.safe_post("api/tools/ffuf", data)
        if result.get("success"):
            logger.info(f"✅ FFuf fuzzing completed for {url}")
        else:
            logger.error(f"❌ FFuf fuzzing failed for {url}")
        return result

    @mcp.tool()
    def netexec_scan(target: str, protocol: str = "smb", username: str = "", password: str = "", hash_value: str = "", module: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute NetExec (formerly CrackMapExec) for network enumeration with enhanced logging.

        Args:
            target: The target IP or network
            protocol: Protocol to use (smb, ssh, winrm, etc.)
            username: Username for authentication
            password: Password for authentication
            hash_value: Hash for pass-the-hash attacks
            module: NetExec module to execute
            additional_args: Additional NetExec arguments

        Returns:
            Network enumeration results
        """
        data = {
            "target": target,
            "protocol": protocol,
            "username": username,
            "password": password,
            "hash": hash_value,
            "module": module,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting NetExec {protocol} scan: {target}")
        result = redvector_client.safe_post("api/tools/netexec", data)
        if result.get("success"):
            logger.info(f"✅ NetExec scan completed for {target}")
        else:
            logger.error(f"❌ NetExec scan failed for {target}")
        return result

    @mcp.tool()
    def amass_scan(domain: str, mode: str = "enum", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Amass for subdomain enumeration with enhanced logging.

        Args:
            domain: The target domain
            mode: Amass mode (enum, intel, viz)
            additional_args: Additional Amass arguments

        Returns:
            Subdomain enumeration results
        """
        data = {
            "domain": domain,
            "mode": mode,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Amass {mode}: {domain}")
        result = redvector_client.safe_post("api/tools/amass", data)
        if result.get("success"):
            logger.info(f"✅ Amass completed for {domain}")
        else:
            logger.error(f"❌ Amass failed for {domain}")
        return result

    @mcp.tool()
    def hashcat_crack(hash_file: str, hash_type: str, attack_mode: str = "0", wordlist: str = "/usr/share/wordlists/rockyou.txt", mask: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Hashcat for advanced password cracking with enhanced logging.

        Args:
            hash_file: File containing password hashes
            hash_type: Hash type number for Hashcat
            attack_mode: Attack mode (0=dict, 1=combo, 3=mask, etc.)
            wordlist: Wordlist file for dictionary attacks
            mask: Mask for mask attacks
            additional_args: Additional Hashcat arguments

        Returns:
            Password cracking results
        """
        data = {
            "hash_file": hash_file,
            "hash_type": hash_type,
            "attack_mode": attack_mode,
            "wordlist": wordlist,
            "mask": mask,
            "additional_args": additional_args
        }
        logger.info(f"🔐 Starting Hashcat attack: mode {attack_mode}")
        result = redvector_client.safe_post("api/tools/hashcat", data)
        if result.get("success"):
            logger.info(f"✅ Hashcat attack completed")
        else:
            logger.error(f"❌ Hashcat attack failed")
        return result

    @mcp.tool()
    def subfinder_scan(domain: str, silent: bool = True, all_sources: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Subfinder for passive subdomain enumeration with enhanced logging.

        Args:
            domain: The target domain
            silent: Run in silent mode
            all_sources: Use all sources
            additional_args: Additional Subfinder arguments

        Returns:
            Passive subdomain enumeration results
        """
        data = {
            "domain": domain,
            "silent": silent,
            "all_sources": all_sources,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Subfinder: {domain}")
        result = redvector_client.safe_post("api/tools/subfinder", data)
        if result.get("success"):
            logger.info(f"✅ Subfinder completed for {domain}")
        else:
            logger.error(f"❌ Subfinder failed for {domain}")
        return result

    @mcp.tool()
    def smbmap_scan(target: str, username: str = "", password: str = "", domain: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute SMBMap for SMB share enumeration with enhanced logging.

        Args:
            target: The target IP address
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication
            additional_args: Additional SMBMap arguments

        Returns:
            SMB share enumeration results
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting SMBMap: {target}")
        result = redvector_client.safe_post("api/tools/smbmap", data)
        if result.get("success"):
            logger.info(f"✅ SMBMap completed for {target}")
        else:
            logger.error(f"❌ SMBMap failed for {target}")
        return result

    # ============================================================================
    # ENHANCED NETWORK PENETRATION TESTING TOOLS (v2.0)
    # ============================================================================

    @mcp.tool()
    def rustscan_fast_scan(target: str, ports: str = "", ulimit: int = 5000,
                          batch_size: int = 4500, timeout: int = 1500,
                          scripts: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Rustscan for ultra-fast port scanning with enhanced logging.

        Args:
            target: The target IP address or hostname
            ports: Specific ports to scan (e.g., "22,80,443")
            ulimit: File descriptor limit
            batch_size: Batch size for scanning
            timeout: Timeout in milliseconds
            scripts: Run Nmap scripts on discovered ports
            additional_args: Additional Rustscan arguments

        Returns:
            Ultra-fast port scanning results
        """
        data = {
            "target": target,
            "ports": ports,
            "ulimit": ulimit,
            "batch_size": batch_size,
            "timeout": timeout,
            "scripts": scripts,
            "additional_args": additional_args
        }
        logger.info(f"⚡ Starting Rustscan: {target}")
        result = redvector_client.safe_post("api/tools/rustscan", data)
        if result.get("success"):
            logger.info(f"✅ Rustscan completed for {target}")
        else:
            logger.error(f"❌ Rustscan failed for {target}")
        return result

    @mcp.tool()
    def masscan_high_speed(target: str, ports: str = "1-65535", rate: int = 1000,
                          interface: str = "", router_mac: str = "", source_ip: str = "",
                          banners: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Masscan for high-speed Internet-scale port scanning with intelligent rate limiting.

        Args:
            target: The target IP address or CIDR range
            ports: Port range to scan
            rate: Packets per second rate
            interface: Network interface to use
            router_mac: Router MAC address
            source_ip: Source IP address
            banners: Enable banner grabbing
            additional_args: Additional Masscan arguments

        Returns:
            High-speed port scanning results with intelligent rate limiting
        """
        data = {
            "target": target,
            "ports": ports,
            "rate": rate,
            "interface": interface,
            "router_mac": router_mac,
            "source_ip": source_ip,
            "banners": banners,
            "additional_args": additional_args
        }
        logger.info(f"🚀 Starting Masscan: {target} at rate {rate}")
        result = redvector_client.safe_post("api/tools/masscan", data)
        if result.get("success"):
            logger.info(f"✅ Masscan completed for {target}")
        else:
            logger.error(f"❌ Masscan failed for {target}")
        return result

    @mcp.tool()
    def nmap_advanced_scan(target: str, scan_type: str = "-sS", ports: str = "",
                          timing: str = "T4", nse_scripts: str = "", os_detection: bool = False,
                          version_detection: bool = False, aggressive: bool = False,
                          stealth: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute advanced Nmap scans with custom NSE scripts and optimized timing.

        Args:
            target: The target IP address or hostname
            scan_type: Nmap scan type (e.g., -sS, -sT, -sU)
            ports: Specific ports to scan
            timing: Timing template (T0-T5)
            nse_scripts: Custom NSE scripts to run
            os_detection: Enable OS detection
            version_detection: Enable version detection
            aggressive: Enable aggressive scanning
            stealth: Enable stealth mode
            additional_args: Additional Nmap arguments

        Returns:
            Advanced Nmap scanning results with custom NSE scripts
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "timing": timing,
            "nse_scripts": nse_scripts,
            "os_detection": os_detection,
            "version_detection": version_detection,
            "aggressive": aggressive,
            "stealth": stealth,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Advanced Nmap: {target}")
        result = redvector_client.safe_post("api/tools/nmap-advanced", data)
        if result.get("success"):
            logger.info(f"✅ Advanced Nmap completed for {target}")
        else:
            logger.error(f"❌ Advanced Nmap failed for {target}")
        return result

    @mcp.tool()
    def enum4linux_ng_advanced(target: str, username: str = "", password: str = "",
                               domain: str = "", shares: bool = True, users: bool = True,
                               groups: bool = True, policy: bool = True,
                               additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Enum4linux-ng for advanced SMB enumeration with enhanced logging.

        Args:
            target: The target IP address
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication
            shares: Enumerate shares
            users: Enumerate users
            groups: Enumerate groups
            policy: Enumerate policies
            additional_args: Additional Enum4linux-ng arguments

        Returns:
            Advanced SMB enumeration results
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "shares": shares,
            "users": users,
            "groups": groups,
            "policy": policy,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Enum4linux-ng: {target}")
        result = redvector_client.safe_post("api/tools/enum4linux-ng", data)
        if result.get("success"):
            logger.info(f"✅ Enum4linux-ng completed for {target}")
        else:
            logger.error(f"❌ Enum4linux-ng failed for {target}")
        return result

    @mcp.tool()
    def rpcclient_enumeration(target: str, username: str = "", password: str = "",
                             domain: str = "", commands: str = "enumdomusers;enumdomgroups;querydominfo",
                             additional_args: str = "") -> Dict[str, Any]:
        """
        Execute rpcclient for RPC enumeration with enhanced logging.

        Args:
            target: The target IP address
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication
            commands: Semicolon-separated RPC commands
            additional_args: Additional rpcclient arguments

        Returns:
            RPC enumeration results
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "commands": commands,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting rpcclient: {target}")
        result = redvector_client.safe_post("api/tools/rpcclient", data)
        if result.get("success"):
            logger.info(f"✅ rpcclient completed for {target}")
        else:
            logger.error(f"❌ rpcclient failed for {target}")
        return result

    @mcp.tool()
    def nbtscan_netbios(target: str, verbose: bool = False, timeout: int = 2,
                       additional_args: str = "") -> Dict[str, Any]:
        """
        Execute nbtscan for NetBIOS name scanning with enhanced logging.

        Args:
            target: The target IP address or range
            verbose: Enable verbose output
            timeout: Timeout in seconds
            additional_args: Additional nbtscan arguments

        Returns:
            NetBIOS name scanning results
        """
        data = {
            "target": target,
            "verbose": verbose,
            "timeout": timeout,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting nbtscan: {target}")
        result = redvector_client.safe_post("api/tools/nbtscan", data)
        if result.get("success"):
            logger.info(f"✅ nbtscan completed for {target}")
        else:
            logger.error(f"❌ nbtscan failed for {target}")
        return result

    @mcp.tool()
    def arp_scan_discovery(target: str = "", interface: str = "", local_network: bool = False,
                          timeout: int = 500, retry: int = 3, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute arp-scan for network discovery with enhanced logging.

        Args:
            target: The target IP range (if not using local_network)
            interface: Network interface to use
            local_network: Scan local network
            timeout: Timeout in milliseconds
            retry: Number of retries
            additional_args: Additional arp-scan arguments

        Returns:
            Network discovery results via ARP scanning
        """
        data = {
            "target": target,
            "interface": interface,
            "local_network": local_network,
            "timeout": timeout,
            "retry": retry,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting arp-scan: {target if target else 'local network'}")
        result = redvector_client.safe_post("api/tools/arp-scan", data)
        if result.get("success"):
            logger.info(f"✅ arp-scan completed")
        else:
            logger.error(f"❌ arp-scan failed")
        return result

    @mcp.tool()
    def responder_credential_harvest(interface: str = "eth0", analyze: bool = False,
                                   wpad: bool = True, force_wpad_auth: bool = False,
                                   fingerprint: bool = False, duration: int = 300,
                                   additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Responder for credential harvesting with enhanced logging.

        Args:
            interface: Network interface to use
            analyze: Analyze mode only
            wpad: Enable WPAD rogue proxy
            force_wpad_auth: Force WPAD authentication
            fingerprint: Fingerprint mode
            duration: Duration to run in seconds
            additional_args: Additional Responder arguments

        Returns:
            Credential harvesting results
        """
        data = {
            "interface": interface,
            "analyze": analyze,
            "wpad": wpad,
            "force_wpad_auth": force_wpad_auth,
            "fingerprint": fingerprint,
            "duration": duration,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Responder on interface: {interface}")
        result = redvector_client.safe_post("api/tools/responder", data)
        if result.get("success"):
            logger.info(f"✅ Responder completed")
        else:
            logger.error(f"❌ Responder failed")
        return result

    @mcp.tool()
    def volatility_analyze(memory_file: str, plugin: str, profile: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Volatility for memory forensics analysis with enhanced logging.

        Args:
            memory_file: Path to memory dump file
            plugin: Volatility plugin to use
            profile: Memory profile to use
            additional_args: Additional Volatility arguments

        Returns:
            Memory forensics analysis results
        """
        data = {
            "memory_file": memory_file,
            "plugin": plugin,
            "profile": profile,
            "additional_args": additional_args
        }
        logger.info(f"🧠 Starting Volatility analysis: {plugin}")
        result = redvector_client.safe_post("api/tools/volatility", data)
        if result.get("success"):
            logger.info(f"✅ Volatility analysis completed")
        else:
            logger.error(f"❌ Volatility analysis failed")
        return result

    @mcp.tool()
    def msfvenom_generate(payload: str, format_type: str = "", output_file: str = "", encoder: str = "", iterations: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute MSFVenom for payload generation with enhanced logging.

        Args:
            payload: The payload to generate
            format_type: Output format (exe, elf, raw, etc.)
            output_file: Output file path
            encoder: Encoder to use
            iterations: Number of encoding iterations
            additional_args: Additional MSFVenom arguments

        Returns:
            Payload generation results
        """
        data = {
            "payload": payload,
            "format": format_type,
            "output_file": output_file,
            "encoder": encoder,
            "iterations": iterations,
            "additional_args": additional_args
        }
        logger.info(f"🚀 Starting MSFVenom payload generation: {payload}")
        result = redvector_client.safe_post("api/tools/msfvenom", data)
        if result.get("success"):
            logger.info(f"✅ MSFVenom payload generated")
        else:
            logger.error(f"❌ MSFVenom payload generation failed")
        return result

    # ============================================================================
    # BINARY ANALYSIS & REVERSE ENGINEERING TOOLS
    # ============================================================================

    @mcp.tool()
    def gdb_analyze(binary: str, commands: str = "", script_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute GDB for binary analysis and debugging with enhanced logging.

        Args:
            binary: Path to the binary file
            commands: GDB commands to execute
            script_file: Path to GDB script file
            additional_args: Additional GDB arguments

        Returns:
            Binary analysis results
        """
        data = {
            "binary": binary,
            "commands": commands,
            "script_file": script_file,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting GDB analysis: {binary}")
        result = redvector_client.safe_post("api/tools/gdb", data)
        if result.get("success"):
            logger.info(f"✅ GDB analysis completed for {binary}")
        else:
            logger.error(f"❌ GDB analysis failed for {binary}")
        return result

    @mcp.tool()
    def radare2_analyze(binary: str, commands: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Radare2 for binary analysis and reverse engineering with enhanced logging.

        Args:
            binary: Path to the binary file
            commands: Radare2 commands to execute
            additional_args: Additional Radare2 arguments

        Returns:
            Binary analysis results
        """
        data = {
            "binary": binary,
            "commands": commands,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting Radare2 analysis: {binary}")
        result = redvector_client.safe_post("api/tools/radare2", data)
        if result.get("success"):
            logger.info(f"✅ Radare2 analysis completed for {binary}")
        else:
            logger.error(f"❌ Radare2 analysis failed for {binary}")
        return result

    @mcp.tool()
    def binwalk_analyze(file_path: str, extract: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Binwalk for firmware and file analysis with enhanced logging.

        Args:
            file_path: Path to the file to analyze
            extract: Whether to extract discovered files
            additional_args: Additional Binwalk arguments

        Returns:
            Firmware analysis results
        """
        data = {
            "file_path": file_path,
            "extract": extract,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting Binwalk analysis: {file_path}")
        result = redvector_client.safe_post("api/tools/binwalk", data)
        if result.get("success"):
            logger.info(f"✅ Binwalk analysis completed for {file_path}")
        else:
            logger.error(f"❌ Binwalk analysis failed for {file_path}")
        return result

    @mcp.tool()
    def ropgadget_search(binary: str, gadget_type: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Search for ROP gadgets in a binary using ROPgadget with enhanced logging.

        Args:
            binary: Path to the binary file
            gadget_type: Type of gadgets to search for
            additional_args: Additional ROPgadget arguments

        Returns:
            ROP gadget search results
        """
        data = {
            "binary": binary,
            "gadget_type": gadget_type,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting ROPgadget search: {binary}")
        result = redvector_client.safe_post("api/tools/ropgadget", data)
        if result.get("success"):
            logger.info(f"✅ ROPgadget search completed for {binary}")
        else:
            logger.error(f"❌ ROPgadget search failed for {binary}")
        return result

    @mcp.tool()
    def checksec_analyze(binary: str) -> Dict[str, Any]:
        """
        Check security features of a binary with enhanced logging.

        Args:
            binary: Path to the binary file

        Returns:
            Security features analysis results
        """
        data = {
            "binary": binary
        }
        logger.info(f"🔧 Starting Checksec analysis: {binary}")
        result = redvector_client.safe_post("api/tools/checksec", data)
        if result.get("success"):
            logger.info(f"✅ Checksec analysis completed for {binary}")
        else:
            logger.error(f"❌ Checksec analysis failed for {binary}")
        return result

    @mcp.tool()
    def xxd_hexdump(file_path: str, offset: str = "0", length: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Create a hex dump of a file using xxd with enhanced logging.

        Args:
            file_path: Path to the file
            offset: Offset to start reading from
            length: Number of bytes to read
            additional_args: Additional xxd arguments

        Returns:
            Hex dump results
        """
        data = {
            "file_path": file_path,
            "offset": offset,
            "length": length,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting XXD hex dump: {file_path}")
        result = redvector_client.safe_post("api/tools/xxd", data)
        if result.get("success"):
            logger.info(f"✅ XXD hex dump completed for {file_path}")
        else:
            logger.error(f"❌ XXD hex dump failed for {file_path}")
        return result

    @mcp.tool()
    def strings_extract(file_path: str, min_len: int = 4, additional_args: str = "") -> Dict[str, Any]:
        """
        Extract strings from a binary file with enhanced logging.

        Args:
            file_path: Path to the file
            min_len: Minimum string length
            additional_args: Additional strings arguments

        Returns:
            String extraction results
        """
        data = {
            "file_path": file_path,
            "min_len": min_len,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting Strings extraction: {file_path}")
        result = redvector_client.safe_post("api/tools/strings", data)
        if result.get("success"):
            logger.info(f"✅ Strings extraction completed for {file_path}")
        else:
            logger.error(f"❌ Strings extraction failed for {file_path}")
        return result

    @mcp.tool()
    def objdump_analyze(binary: str, disassemble: bool = True, additional_args: str = "") -> Dict[str, Any]:
        """
        Analyze a binary using objdump with enhanced logging.

        Args:
            binary: Path to the binary file
            disassemble: Whether to disassemble the binary
            additional_args: Additional objdump arguments

        Returns:
            Binary analysis results
        """
        data = {
            "binary": binary,
            "disassemble": disassemble,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting Objdump analysis: {binary}")
        result = redvector_client.safe_post("api/tools/objdump", data)
        if result.get("success"):
            logger.info(f"✅ Objdump analysis completed for {binary}")
        else:
            logger.error(f"❌ Objdump analysis failed for {binary}")
        return result

    # ============================================================================
    # ENHANCED BINARY ANALYSIS AND EXPLOITATION FRAMEWORK (v2.0)
    # ============================================================================

    @mcp.tool()
    def ghidra_analysis(binary: str, project_name: str = "redvector_analysis",
                       script_file: str = "", analysis_timeout: int = 300,
                       output_format: str = "xml", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Ghidra for advanced binary analysis and reverse engineering.

        Args:
            binary: Path to the binary file
            project_name: Ghidra project name
            script_file: Custom Ghidra script to run
            analysis_timeout: Analysis timeout in seconds
            output_format: Output format (xml, json)
            additional_args: Additional Ghidra arguments

        Returns:
            Advanced binary analysis results from Ghidra
        """
        data = {
            "binary": binary,
            "project_name": project_name,
            "script_file": script_file,
            "analysis_timeout": analysis_timeout,
            "output_format": output_format,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting Ghidra analysis: {binary}")
        result = redvector_client.safe_post("api/tools/ghidra", data)
        if result.get("success"):
            logger.info(f"✅ Ghidra analysis completed for {binary}")
        else:
            logger.error(f"❌ Ghidra analysis failed for {binary}")
        return result

    @mcp.tool()
    def pwntools_exploit(script_content: str = "", target_binary: str = "",
                        target_host: str = "", target_port: int = 0,
                        exploit_type: str = "local", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Pwntools for exploit development and automation.

        Args:
            script_content: Python script content using pwntools
            target_binary: Local binary to exploit
            target_host: Remote host to connect to
            target_port: Remote port to connect to
            exploit_type: Type of exploit (local, remote, format_string, rop)
            additional_args: Additional arguments

        Returns:
            Exploit execution results
        """
        data = {
            "script_content": script_content,
            "target_binary": target_binary,
            "target_host": target_host,
            "target_port": target_port,
            "exploit_type": exploit_type,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting Pwntools exploit: {exploit_type}")
        result = redvector_client.safe_post("api/tools/pwntools", data)
        if result.get("success"):
            logger.info(f"✅ Pwntools exploit completed")
        else:
            logger.error(f"❌ Pwntools exploit failed")
        return result

    @mcp.tool()
    def one_gadget_search(libc_path: str, level: int = 1, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute one_gadget to find one-shot RCE gadgets in libc.

        Args:
            libc_path: Path to libc binary
            level: Constraint level (0, 1, 2)
            additional_args: Additional one_gadget arguments

        Returns:
            One-shot RCE gadget search results
        """
        data = {
            "libc_path": libc_path,
            "level": level,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting one_gadget analysis: {libc_path}")
        result = redvector_client.safe_post("api/tools/one-gadget", data)
        if result.get("success"):
            logger.info(f"✅ one_gadget analysis completed")
        else:
            logger.error(f"❌ one_gadget analysis failed")
        return result

    @mcp.tool()
    def libc_database_lookup(action: str = "find", symbols: str = "",
                            libc_id: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute libc-database for libc identification and offset lookup.

        Args:
            action: Action to perform (find, dump, download)
            symbols: Symbols with offsets for find action (format: "symbol1:offset1 symbol2:offset2")
            libc_id: Libc ID for dump/download actions
            additional_args: Additional arguments

        Returns:
            Libc database lookup results
        """
        data = {
            "action": action,
            "symbols": symbols,
            "libc_id": libc_id,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting libc-database {action}: {symbols or libc_id}")
        result = redvector_client.safe_post("api/tools/libc-database", data)
        if result.get("success"):
            logger.info(f"✅ libc-database {action} completed")
        else:
            logger.error(f"❌ libc-database {action} failed")
        return result

    @mcp.tool()
    def gdb_peda_debug(binary: str = "", commands: str = "", attach_pid: int = 0,
                      core_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute GDB with PEDA for enhanced debugging and exploitation.

        Args:
            binary: Binary to debug
            commands: GDB commands to execute
            attach_pid: Process ID to attach to
            core_file: Core dump file to analyze
            additional_args: Additional GDB arguments

        Returns:
            Enhanced debugging results with PEDA
        """
        data = {
            "binary": binary,
            "commands": commands,
            "attach_pid": attach_pid,
            "core_file": core_file,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting GDB-PEDA analysis: {binary or f'PID {attach_pid}' or core_file}")
        result = redvector_client.safe_post("api/tools/gdb-peda", data)
        if result.get("success"):
            logger.info(f"✅ GDB-PEDA analysis completed")
        else:
            logger.error(f"❌ GDB-PEDA analysis failed")
        return result

    @mcp.tool()
    def angr_symbolic_execution(binary: str, script_content: str = "",
                               find_address: str = "", avoid_addresses: str = "",
                               analysis_type: str = "symbolic", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute angr for symbolic execution and binary analysis.

        Args:
            binary: Binary to analyze
            script_content: Custom angr script content
            find_address: Address to find during symbolic execution
            avoid_addresses: Comma-separated addresses to avoid
            analysis_type: Type of analysis (symbolic, cfg, static)
            additional_args: Additional arguments

        Returns:
            Symbolic execution and binary analysis results
        """
        data = {
            "binary": binary,
            "script_content": script_content,
            "find_address": find_address,
            "avoid_addresses": avoid_addresses,
            "analysis_type": analysis_type,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting angr analysis: {binary}")
        result = redvector_client.safe_post("api/tools/angr", data)
        if result.get("success"):
            logger.info(f"✅ angr analysis completed")
        else:
            logger.error(f"❌ angr analysis failed")
        return result

    @mcp.tool()
    def ropper_gadget_search(binary: str, gadget_type: str = "rop", quality: int = 1,
                            arch: str = "", search_string: str = "",
                            additional_args: str = "") -> Dict[str, Any]:
        """
        Execute ropper for advanced ROP/JOP gadget searching.

        Args:
            binary: Binary to search for gadgets
            gadget_type: Type of gadgets (rop, jop, sys, all)
            quality: Gadget quality level (1-5)
            arch: Target architecture (x86, x86_64, arm, etc.)
            search_string: Specific gadget pattern to search for
            additional_args: Additional ropper arguments

        Returns:
            Advanced ROP/JOP gadget search results
        """
        data = {
            "binary": binary,
            "gadget_type": gadget_type,
            "quality": quality,
            "arch": arch,
            "search_string": search_string,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting ropper analysis: {binary}")
        result = redvector_client.safe_post("api/tools/ropper", data)
        if result.get("success"):
            logger.info(f"✅ ropper analysis completed")
        else:
            logger.error(f"❌ ropper analysis failed")
        return result

    @mcp.tool()
    def pwninit_setup(binary: str, libc: str = "", ld: str = "",
                     template_type: str = "python", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute pwninit for CTF binary exploitation setup.

        Args:
            binary: Binary file to set up
            libc: Libc file to use
            ld: Loader file to use
            template_type: Template type (python, c)
            additional_args: Additional pwninit arguments

        Returns:
            CTF binary exploitation setup results
        """
        data = {
            "binary": binary,
            "libc": libc,
            "ld": ld,
            "template_type": template_type,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting pwninit setup: {binary}")
        result = redvector_client.safe_post("api/tools/pwninit", data)
        if result.get("success"):
            logger.info(f"✅ pwninit setup completed")
        else:
            logger.error(f"❌ pwninit setup failed")
        return result

    @mcp.tool()
    def feroxbuster_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", threads: int = 10, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Feroxbuster for recursive content discovery with enhanced logging.

        Args:
            url: The target URL
            wordlist: Wordlist file to use
            threads: Number of threads
            additional_args: Additional Feroxbuster arguments

        Returns:
            Content discovery results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "threads": threads,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Feroxbuster scan: {url}")
        result = redvector_client.safe_post("api/tools/feroxbuster", data)
        if result.get("success"):
            logger.info(f"✅ Feroxbuster scan completed for {url}")
        else:
            logger.error(f"❌ Feroxbuster scan failed for {url}")
        return result

    @mcp.tool()
    def dotdotpwn_scan(target: str, module: str = "http", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute DotDotPwn for directory traversal testing with enhanced logging.

        Args:
            target: The target hostname or IP
            module: Module to use (http, ftp, tftp, etc.)
            additional_args: Additional DotDotPwn arguments

        Returns:
            Directory traversal test results
        """
        data = {
            "target": target,
            "module": module,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting DotDotPwn scan: {target}")
        result = redvector_client.safe_post("api/tools/dotdotpwn", data)
        if result.get("success"):
            logger.info(f"✅ DotDotPwn scan completed for {target}")
        else:
            logger.error(f"❌ DotDotPwn scan failed for {target}")
        return result

    @mcp.tool()
    def xsser_scan(url: str, params: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute XSSer for XSS vulnerability testing with enhanced logging.

        Args:
            url: The target URL
            params: Parameters to test
            additional_args: Additional XSSer arguments

        Returns:
            XSS vulnerability test results
        """
        data = {
            "url": url,
            "params": params,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting XSSer scan: {url}")
        result = redvector_client.safe_post("api/tools/xsser", data)
        if result.get("success"):
            logger.info(f"✅ XSSer scan completed for {url}")
        else:
            logger.error(f"❌ XSSer scan failed for {url}")
        return result

    @mcp.tool()
    def wfuzz_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Wfuzz for web application fuzzing with enhanced logging.

        Args:
            url: The target URL (use FUZZ where you want to inject payloads)
            wordlist: Wordlist file to use
            additional_args: Additional Wfuzz arguments

        Returns:
            Web application fuzzing results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Wfuzz scan: {url}")
        result = redvector_client.safe_post("api/tools/wfuzz", data)
        if result.get("success"):
            logger.info(f"✅ Wfuzz scan completed for {url}")
        else:
            logger.error(f"❌ Wfuzz scan failed for {url}")
        return result

    # ============================================================================
    # ENHANCED WEB APPLICATION SECURITY TOOLS (v2.0)
    # ============================================================================

    @mcp.tool()
    def dirsearch_scan(url: str, extensions: str = "php,html,js,txt,xml,json",
                      wordlist: str = "/usr/share/wordlists/dirsearch/common.txt",
                      threads: int = 30, recursive: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dirsearch for advanced directory and file discovery with enhanced logging.

        Args:
            url: The target URL
            extensions: File extensions to search for
            wordlist: Wordlist file to use
            threads: Number of threads to use
            recursive: Enable recursive scanning
            additional_args: Additional Dirsearch arguments

        Returns:
            Advanced directory discovery results
        """
        data = {
            "url": url,
            "extensions": extensions,
            "wordlist": wordlist,
            "threads": threads,
            "recursive": recursive,
            "additional_args": additional_args
        }
        logger.info(f"📁 Starting Dirsearch scan: {url}")
        result = redvector_client.safe_post("api/tools/dirsearch", data)
        if result.get("success"):
            logger.info(f"✅ Dirsearch scan completed for {url}")
        else:
            logger.error(f"❌ Dirsearch scan failed for {url}")
        return result

    @mcp.tool()
    def katana_crawl(url: str, depth: int = 3, js_crawl: bool = True,
                    form_extraction: bool = True, output_format: str = "json",
                    additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Katana for next-generation crawling and spidering with enhanced logging.

        Args:
            url: The target URL to crawl
            depth: Crawling depth
            js_crawl: Enable JavaScript crawling
            form_extraction: Enable form extraction
            output_format: Output format (json, txt)
            additional_args: Additional Katana arguments

        Returns:
            Advanced web crawling results with endpoints and forms
        """
        data = {
            "url": url,
            "depth": depth,
            "js_crawl": js_crawl,
            "form_extraction": form_extraction,
            "output_format": output_format,
            "additional_args": additional_args
        }
        logger.info(f"⚔️  Starting Katana crawl: {url}")
        result = redvector_client.safe_post("api/tools/katana", data)
        if result.get("success"):
            logger.info(f"✅ Katana crawl completed for {url}")
        else:
            logger.error(f"❌ Katana crawl failed for {url}")
        return result

    @mcp.tool()
    def gau_discovery(domain: str, providers: str = "wayback,commoncrawl,otx,urlscan",
                     include_subs: bool = True, blacklist: str = "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico",
                     additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Gau (Get All URLs) for URL discovery from multiple sources with enhanced logging.

        Args:
            domain: The target domain
            providers: Data providers to use
            include_subs: Include subdomains
            blacklist: File extensions to blacklist
            additional_args: Additional Gau arguments

        Returns:
            Comprehensive URL discovery results from multiple sources
        """
        data = {
            "domain": domain,
            "providers": providers,
            "include_subs": include_subs,
            "blacklist": blacklist,
            "additional_args": additional_args
        }
        logger.info(f"📡 Starting Gau URL discovery: {domain}")
        result = redvector_client.safe_post("api/tools/gau", data)
        if result.get("success"):
            logger.info(f"✅ Gau URL discovery completed for {domain}")
        else:
            logger.error(f"❌ Gau URL discovery failed for {domain}")
        return result

    @mcp.tool()
    def waybackurls_discovery(domain: str, get_versions: bool = False,
                             no_subs: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Waybackurls for historical URL discovery with enhanced logging.

        Args:
            domain: The target domain
            get_versions: Get all versions of URLs
            no_subs: Don't include subdomains
            additional_args: Additional Waybackurls arguments

        Returns:
            Historical URL discovery results from Wayback Machine
        """
        data = {
            "domain": domain,
            "get_versions": get_versions,
            "no_subs": no_subs,
            "additional_args": additional_args
        }
        logger.info(f"🕰️  Starting Waybackurls discovery: {domain}")
        result = redvector_client.safe_post("api/tools/waybackurls", data)
        if result.get("success"):
            logger.info(f"✅ Waybackurls discovery completed for {domain}")
        else:
            logger.error(f"❌ Waybackurls discovery failed for {domain}")
        return result

    @mcp.tool()
    def arjun_parameter_discovery(url: str, method: str = "GET", wordlist: str = "",
                                 delay: int = 0, threads: int = 25, stable: bool = False,
                                 additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Arjun for HTTP parameter discovery with enhanced logging.

        Args:
            url: The target URL
            method: HTTP method to use
            wordlist: Custom wordlist file
            delay: Delay between requests
            threads: Number of threads
            stable: Use stable mode
            additional_args: Additional Arjun arguments

        Returns:
            HTTP parameter discovery results
        """
        data = {
            "url": url,
            "method": method,
            "wordlist": wordlist,
            "delay": delay,
            "threads": threads,
            "stable": stable,
            "additional_args": additional_args
        }
        logger.info(f"🎯 Starting Arjun parameter discovery: {url}")
        result = redvector_client.safe_post("api/tools/arjun", data)
        if result.get("success"):
            logger.info(f"✅ Arjun parameter discovery completed for {url}")
        else:
            logger.error(f"❌ Arjun parameter discovery failed for {url}")
        return result

    @mcp.tool()
    def paramspider_mining(domain: str, level: int = 2,
                          exclude: str = "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico",
                          output: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute ParamSpider for parameter mining from web archives with enhanced logging.

        Args:
            domain: The target domain
            level: Mining level depth
            exclude: File extensions to exclude
            output: Output file path
            additional_args: Additional ParamSpider arguments

        Returns:
            Parameter mining results from web archives
        """
        data = {
            "domain": domain,
            "level": level,
            "exclude": exclude,
            "output": output,
            "additional_args": additional_args
        }
        logger.info(f"🕷️  Starting ParamSpider mining: {domain}")
        result = redvector_client.safe_post("api/tools/paramspider", data)
        if result.get("success"):
            logger.info(f"✅ ParamSpider mining completed for {domain}")
        else:
            logger.error(f"❌ ParamSpider mining failed for {domain}")
        return result

    @mcp.tool()
    def x8_parameter_discovery(url: str, wordlist: str = "/usr/share/wordlists/x8/params.txt",
                              method: str = "GET", body: str = "", headers: str = "",
                              additional_args: str = "") -> Dict[str, Any]:
        """
        Execute x8 for hidden parameter discovery with enhanced logging.

        Args:
            url: The target URL
            wordlist: Parameter wordlist
            method: HTTP method
            body: Request body
            headers: Custom headers
            additional_args: Additional x8 arguments

        Returns:
            Hidden parameter discovery results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "method": method,
            "body": body,
            "headers": headers,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting x8 parameter discovery: {url}")
        result = redvector_client.safe_post("api/tools/x8", data)
        if result.get("success"):
            logger.info(f"✅ x8 parameter discovery completed for {url}")
        else:
            logger.error(f"❌ x8 parameter discovery failed for {url}")
        return result

    @mcp.tool()
    def jaeles_vulnerability_scan(url: str, signatures: str = "", config: str = "",
                                 threads: int = 20, timeout: int = 20,
                                 additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Jaeles for advanced vulnerability scanning with custom signatures.

        Args:
            url: The target URL
            signatures: Custom signature path
            config: Configuration file
            threads: Number of threads
            timeout: Request timeout
            additional_args: Additional Jaeles arguments

        Returns:
            Advanced vulnerability scanning results with custom signatures
        """
        data = {
            "url": url,
            "signatures": signatures,
            "config": config,
            "threads": threads,
            "timeout": timeout,
            "additional_args": additional_args
        }
        logger.info(f"🔬 Starting Jaeles vulnerability scan: {url}")
        result = redvector_client.safe_post("api/tools/jaeles", data)
        if result.get("success"):
            logger.info(f"✅ Jaeles vulnerability scan completed for {url}")
        else:
            logger.error(f"❌ Jaeles vulnerability scan failed for {url}")
        return result

    @mcp.tool()
    def dalfox_xss_scan(url: str, pipe_mode: bool = False, blind: bool = False,
                       mining_dom: bool = True, mining_dict: bool = True,
                       custom_payload: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dalfox for advanced XSS vulnerability scanning with enhanced logging.

        Args:
            url: The target URL
            pipe_mode: Use pipe mode for input
            blind: Enable blind XSS testing
            mining_dom: Enable DOM mining
            mining_dict: Enable dictionary mining
            custom_payload: Custom XSS payload
            additional_args: Additional Dalfox arguments

        Returns:
            Advanced XSS vulnerability scanning results
        """
        data = {
            "url": url,
            "pipe_mode": pipe_mode,
            "blind": blind,
            "mining_dom": mining_dom,
            "mining_dict": mining_dict,
            "custom_payload": custom_payload,
            "additional_args": additional_args
        }
        logger.info(f"🎯 Starting Dalfox XSS scan: {url if url else 'pipe mode'}")
        result = redvector_client.safe_post("api/tools/dalfox", data)
        if result.get("success"):
            logger.info(f"✅ Dalfox XSS scan completed")
        else:
            logger.error(f"❌ Dalfox XSS scan failed")
        return result

    @mcp.tool()
    def httpx_probe(target: str, probe: bool = True, tech_detect: bool = False,
                   status_code: bool = False, content_length: bool = False,
                   title: bool = False, web_server: bool = False, threads: int = 50,
                   additional_args: str = "") -> Dict[str, Any]:
        """
        Execute httpx for fast HTTP probing and technology detection.

        Args:
            target: Target file or single URL
            probe: Enable probing
            tech_detect: Enable technology detection
            status_code: Show status codes
            content_length: Show content length
            title: Show page titles
            web_server: Show web server
            threads: Number of threads
            additional_args: Additional httpx arguments

        Returns:
            Fast HTTP probing results with technology detection
        """
        data = {
            "target": target,
            "probe": probe,
            "tech_detect": tech_detect,
            "status_code": status_code,
            "content_length": content_length,
            "title": title,
            "web_server": web_server,
            "threads": threads,
            "additional_args": additional_args
        }
        logger.info(f"🌍 Starting httpx probe: {target}")
        result = redvector_client.safe_post("api/tools/httpx", data)
        if result.get("success"):
            logger.info(f"✅ httpx probe completed for {target}")
        else:
            logger.error(f"❌ httpx probe failed for {target}")
        return result

    @mcp.tool()
    def anew_data_processing(input_data: str, output_file: str = "",
                            additional_args: str = "") -> Dict[str, Any]:
        """
        Execute anew for appending new lines to files (useful for data processing).

        Args:
            input_data: Input data to process
            output_file: Output file path
            additional_args: Additional anew arguments

        Returns:
            Data processing results with unique line filtering
        """
        data = {
            "input_data": input_data,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info("📝 Starting anew data processing")
        result = redvector_client.safe_post("api/tools/anew", data)
        if result.get("success"):
            logger.info("✅ anew data processing completed")
        else:
            logger.error("❌ anew data processing failed")
        return result

    @mcp.tool()
    def qsreplace_parameter_replacement(urls: str, replacement: str = "FUZZ",
                                       additional_args: str = "") -> Dict[str, Any]:
        """
        Execute qsreplace for query string parameter replacement.

        Args:
            urls: URLs to process
            replacement: Replacement string for parameters
            additional_args: Additional qsreplace arguments

        Returns:
            Parameter replacement results for fuzzing
        """
        data = {
            "urls": urls,
            "replacement": replacement,
            "additional_args": additional_args
        }
        logger.info("🔄 Starting qsreplace parameter replacement")
        result = redvector_client.safe_post("api/tools/qsreplace", data)
        if result.get("success"):
            logger.info("✅ qsreplace parameter replacement completed")
        else:
            logger.error("❌ qsreplace parameter replacement failed")
        return result

    @mcp.tool()
    def uro_url_filtering(urls: str, whitelist: str = "", blacklist: str = "",
                         additional_args: str = "") -> Dict[str, Any]:
        """
        Execute uro for filtering out similar URLs.

        Args:
            urls: URLs to filter
            whitelist: Whitelist patterns
            blacklist: Blacklist patterns
            additional_args: Additional uro arguments

        Returns:
            Filtered URL results with duplicates removed
        """
        data = {
            "urls": urls,
            "whitelist": whitelist,
            "blacklist": blacklist,
            "additional_args": additional_args
        }
        logger.info("🔍 Starting uro URL filtering")
        result = redvector_client.safe_post("api/tools/uro", data)
        if result.get("success"):
            logger.info("✅ uro URL filtering completed")
        else:
            logger.error("❌ uro URL filtering failed")
        return result

    # ============================================================================
    # AI-POWERED PAYLOAD GENERATION (v5.0 ENHANCEMENT)
    # ============================================================================

    @mcp.tool()
    def ai_generate_payload(attack_type: str, complexity: str = "basic", technology: str = "", url: str = "") -> Dict[str, Any]:
        """
        Generate AI-powered contextual payloads for security testing.

        Args:
            attack_type: Type of attack (xss, sqli, lfi, cmd_injection, ssti, xxe)
            complexity: Complexity level (basic, advanced, bypass)
            technology: Target technology (php, asp, jsp, python, nodejs)
            url: Target URL for context

        Returns:
            Contextual payloads with risk assessment and test cases
        """
        data = {
            "attack_type": attack_type,
            "complexity": complexity,
            "technology": technology,
            "url": url
        }
        logger.info(f"🤖 Generating AI payloads for {attack_type} attack")
        result = redvector_client.safe_post("api/ai/generate_payload", data)

        if result.get("success"):
            payload_data = result.get("ai_payload_generation", {})
            count = payload_data.get("payload_count", 0)
            logger.info(f"✅ Generated {count} contextual {attack_type} payloads")

            # Log some example payloads for user awareness
            payloads = payload_data.get("payloads", [])
            if payloads:
                logger.info("🎯 Sample payloads generated:")
                for i, payload_info in enumerate(payloads[:3]):  # Show first 3
                    risk = payload_info.get("risk_level", "UNKNOWN")
                    context = payload_info.get("context", "basic")
                    logger.info(f"   ├─ [{risk}] {context}: {payload_info['payload'][:50]}...")
        else:
            logger.error("❌ AI payload generation failed")

        return result

    @mcp.tool()
    def ai_test_payload(payload: str, target_url: str, method: str = "GET") -> Dict[str, Any]:
        """
        Test generated payload against target with AI analysis.

        Args:
            payload: The payload to test
            target_url: Target URL to test against
            method: HTTP method (GET, POST)

        Returns:
            Test results with AI analysis and vulnerability assessment
        """
        data = {
            "payload": payload,
            "target_url": target_url,
            "method": method
        }
        logger.info(f"🧪 Testing AI payload against {target_url}")
        result = redvector_client.safe_post("api/ai/test_payload", data)

        if result.get("success"):
            analysis = result.get("ai_analysis", {})
            potential_vuln = analysis.get("potential_vulnerability", False)
            logger.info(f"🔍 Payload test completed | Vulnerability detected: {potential_vuln}")

            if potential_vuln:
                logger.warning("⚠️  Potential vulnerability found! Review the response carefully.")
            else:
                logger.info("✅ No obvious vulnerability indicators detected")
        else:
            logger.error("❌ Payload testing failed")

        return result

    @mcp.tool()
    def ai_generate_attack_suite(target_url: str, attack_types: str = "xss,sqli,lfi") -> Dict[str, Any]:
        """
        Generate comprehensive attack suite with multiple payload types.

        Args:
            target_url: Target URL for testing
            attack_types: Comma-separated list of attack types

        Returns:
            Comprehensive attack suite with multiple payload types
        """
        attack_list = [attack.strip() for attack in attack_types.split(",")]
        results = {
            "target_url": target_url,
            "attack_types": attack_list,
            "payload_suites": {},
            "summary": {
                "total_payloads": 0,
                "high_risk_payloads": 0,
                "test_cases": 0
            }
        }

        logger.info(f"🚀 Generating comprehensive attack suite for {target_url}")
        logger.info(f"🎯 Attack types: {', '.join(attack_list)}")

        for attack_type in attack_list:
            logger.info(f"🤖 Generating {attack_type} payloads...")

            # Generate payloads for this attack type
            payload_result = ai_generate_payload(attack_type, "advanced", "", target_url)

            if payload_result.get("success"):
                payload_data = payload_result.get("ai_payload_generation", {})
                results["payload_suites"][attack_type] = payload_data

                # Update summary
                results["summary"]["total_payloads"] += payload_data.get("payload_count", 0)
                results["summary"]["test_cases"] += len(payload_data.get("test_cases", []))

                # Count high-risk payloads
                for payload_info in payload_data.get("payloads", []):
                    if payload_info.get("risk_level") == "HIGH":
                        results["summary"]["high_risk_payloads"] += 1

        logger.info(f"✅ Attack suite generated:")
        logger.info(f"   ├─ Total payloads: {results['summary']['total_payloads']}")
        logger.info(f"   ├─ High-risk payloads: {results['summary']['high_risk_payloads']}")
        logger.info(f"   └─ Test cases: {results['summary']['test_cases']}")

        return {
            "success": True,
            "attack_suite": results,
            "timestamp": time.time()
        }

    # ============================================================================
    # ADVANCED API TESTING TOOLS (v5.0 ENHANCEMENT)
    # ============================================================================

    @mcp.tool()
    def api_fuzzer(base_url: str, endpoints: str = "", methods: str = "GET,POST,PUT,DELETE", wordlist: str = "/usr/share/wordlists/api/api-endpoints.txt") -> Dict[str, Any]:
        """
        Advanced API endpoint fuzzing with intelligent parameter discovery.

        Args:
            base_url: Base URL of the API
            endpoints: Comma-separated list of specific endpoints to test
            methods: HTTP methods to test (comma-separated)
            wordlist: Wordlist for endpoint discovery

        Returns:
            API fuzzing results with endpoint discovery and vulnerability assessment
        """
        data = {
            "base_url": base_url,
            "endpoints": [e.strip() for e in endpoints.split(",") if e.strip()] if endpoints else [],
            "methods": [m.strip() for m in methods.split(",")],
            "wordlist": wordlist
        }

        logger.info(f"🔍 Starting API fuzzing: {base_url}")
        result = redvector_client.safe_post("api/tools/api_fuzzer", data)

        if result.get("success"):
            fuzzing_type = result.get("fuzzing_type", "unknown")
            if fuzzing_type == "endpoint_testing":
                endpoint_count = len(result.get("results", []))
                logger.info(f"✅ API endpoint testing completed: {endpoint_count} endpoints tested")
            else:
                logger.info(f"✅ API endpoint discovery completed")
        else:
            logger.error("❌ API fuzzing failed")

        return result

    @mcp.tool()
    def graphql_scanner(endpoint: str, introspection: bool = True, query_depth: int = 10, test_mutations: bool = True) -> Dict[str, Any]:
        """
        Advanced GraphQL security scanning and introspection.

        Args:
            endpoint: GraphQL endpoint URL
            introspection: Test introspection queries
            query_depth: Maximum query depth to test
            test_mutations: Test mutation operations

        Returns:
            GraphQL security scan results with vulnerability assessment
        """
        data = {
            "endpoint": endpoint,
            "introspection": introspection,
            "query_depth": query_depth,
            "test_mutations": test_mutations
        }

        logger.info(f"🔍 Starting GraphQL security scan: {endpoint}")
        result = redvector_client.safe_post("api/tools/graphql_scanner", data)

        if result.get("success"):
            scan_results = result.get("graphql_scan_results", {})
            vuln_count = len(scan_results.get("vulnerabilities", []))
            tests_count = len(scan_results.get("tests_performed", []))

            logger.info(f"✅ GraphQL scan completed: {tests_count} tests, {vuln_count} vulnerabilities")

            if vuln_count > 0:
                logger.warning(f"⚠️  Found {vuln_count} GraphQL vulnerabilities!")
                for vuln in scan_results.get("vulnerabilities", [])[:3]:  # Show first 3
                    severity = vuln.get("severity", "UNKNOWN")
                    vuln_type = vuln.get("type", "unknown")
                    logger.warning(f"   ├─ [{severity}] {vuln_type}")
        else:
            logger.error("❌ GraphQL scanning failed")

        return result

    @mcp.tool()
    def jwt_analyzer(jwt_token: str, target_url: str = "") -> Dict[str, Any]:
        """
        Advanced JWT token analysis and vulnerability testing.

        Args:
            jwt_token: JWT token to analyze
            target_url: Optional target URL for testing token manipulation

        Returns:
            JWT analysis results with vulnerability assessment and attack vectors
        """
        data = {
            "jwt_token": jwt_token,
            "target_url": target_url
        }

        logger.info(f"🔍 Starting JWT security analysis")
        result = redvector_client.safe_post("api/tools/jwt_analyzer", data)

        if result.get("success"):
            analysis = result.get("jwt_analysis_results", {})
            vuln_count = len(analysis.get("vulnerabilities", []))
            algorithm = analysis.get("token_info", {}).get("algorithm", "unknown")

            logger.info(f"✅ JWT analysis completed: {vuln_count} vulnerabilities found")
            logger.info(f"🔐 Token algorithm: {algorithm}")

            if vuln_count > 0:
                logger.warning(f"⚠️  Found {vuln_count} JWT vulnerabilities!")
                for vuln in analysis.get("vulnerabilities", [])[:3]:  # Show first 3
                    severity = vuln.get("severity", "UNKNOWN")
                    vuln_type = vuln.get("type", "unknown")
                    logger.warning(f"   ├─ [{severity}] {vuln_type}")
        else:
            logger.error("❌ JWT analysis failed")

        return result

    @mcp.tool()
    def api_schema_analyzer(schema_url: str, schema_type: str = "openapi") -> Dict[str, Any]:
        """
        Analyze API schemas and identify potential security issues.

        Args:
            schema_url: URL to the API schema (OpenAPI/Swagger/GraphQL)
            schema_type: Type of schema (openapi, swagger, graphql)

        Returns:
            Schema analysis results with security issues and recommendations
        """
        data = {
            "schema_url": schema_url,
            "schema_type": schema_type
        }

        logger.info(f"🔍 Starting API schema analysis: {schema_url}")
        result = redvector_client.safe_post("api/tools/api_schema_analyzer", data)

        if result.get("success"):
            analysis = result.get("schema_analysis_results", {})
            endpoint_count = len(analysis.get("endpoints_found", []))
            issue_count = len(analysis.get("security_issues", []))

            logger.info(f"✅ Schema analysis completed: {endpoint_count} endpoints, {issue_count} issues")

            if issue_count > 0:
                logger.warning(f"⚠️  Found {issue_count} security issues in schema!")
                for issue in analysis.get("security_issues", [])[:3]:  # Show first 3
                    severity = issue.get("severity", "UNKNOWN")
                    issue_type = issue.get("issue", "unknown")
                    logger.warning(f"   ├─ [{severity}] {issue_type}")

            if endpoint_count > 0:
                logger.info(f"📊 Discovered endpoints:")
                for endpoint in analysis.get("endpoints_found", [])[:5]:  # Show first 5
                    method = endpoint.get("method", "GET")
                    path = endpoint.get("path", "/")
                    logger.info(f"   ├─ {method} {path}")
        else:
            logger.error("❌ Schema analysis failed")

        return result

    @mcp.tool()
    def comprehensive_api_audit(base_url: str, schema_url: str = "", jwt_token: str = "", graphql_endpoint: str = "") -> Dict[str, Any]:
        """
        Comprehensive API security audit combining multiple testing techniques.

        Args:
            base_url: Base URL of the API
            schema_url: Optional API schema URL
            jwt_token: Optional JWT token for analysis
            graphql_endpoint: Optional GraphQL endpoint

        Returns:
            Comprehensive audit results with all API security tests
        """
        audit_results = {
            "base_url": base_url,
            "audit_timestamp": time.time(),
            "tests_performed": [],
            "total_vulnerabilities": 0,
            "summary": {},
            "recommendations": []
        }

        logger.info(f"🚀 Starting comprehensive API security audit: {base_url}")

        # 1. API Endpoint Fuzzing
        logger.info("🔍 Phase 1: API endpoint discovery and fuzzing")
        fuzz_result = api_fuzzer(base_url)
        if fuzz_result.get("success"):
            audit_results["tests_performed"].append("api_fuzzing")
            audit_results["api_fuzzing"] = fuzz_result

        # 2. Schema Analysis (if provided)
        if schema_url:
            logger.info("🔍 Phase 2: API schema analysis")
            schema_result = api_schema_analyzer(schema_url)
            if schema_result.get("success"):
                audit_results["tests_performed"].append("schema_analysis")
                audit_results["schema_analysis"] = schema_result

                schema_data = schema_result.get("schema_analysis_results", {})
                audit_results["total_vulnerabilities"] += len(schema_data.get("security_issues", []))

        # 3. JWT Analysis (if provided)
        if jwt_token:
            logger.info("🔍 Phase 3: JWT token analysis")
            jwt_result = jwt_analyzer(jwt_token, base_url)
            if jwt_result.get("success"):
                audit_results["tests_performed"].append("jwt_analysis")
                audit_results["jwt_analysis"] = jwt_result

                jwt_data = jwt_result.get("jwt_analysis_results", {})
                audit_results["total_vulnerabilities"] += len(jwt_data.get("vulnerabilities", []))

        # 4. GraphQL Testing (if provided)
        if graphql_endpoint:
            logger.info("🔍 Phase 4: GraphQL security scanning")
            graphql_result = graphql_scanner(graphql_endpoint)
            if graphql_result.get("success"):
                audit_results["tests_performed"].append("graphql_scanning")
                audit_results["graphql_scanning"] = graphql_result

                graphql_data = graphql_result.get("graphql_scan_results", {})
                audit_results["total_vulnerabilities"] += len(graphql_data.get("vulnerabilities", []))

        # Generate comprehensive recommendations
        audit_results["recommendations"] = [
            "Implement proper authentication and authorization",
            "Use HTTPS for all API communications",
            "Validate and sanitize all input parameters",
            "Implement rate limiting and request throttling",
            "Add comprehensive logging and monitoring",
            "Regular security testing and code reviews",
            "Keep API documentation updated and secure",
            "Implement proper error handling"
        ]

        # Summary
        audit_results["summary"] = {
            "tests_performed": len(audit_results["tests_performed"]),
            "total_vulnerabilities": audit_results["total_vulnerabilities"],
            "audit_coverage": "comprehensive" if len(audit_results["tests_performed"]) >= 3 else "partial"
        }

        logger.info(f"✅ Comprehensive API audit completed:")
        logger.info(f"   ├─ Tests performed: {audit_results['summary']['tests_performed']}")
        logger.info(f"   ├─ Total vulnerabilities: {audit_results['summary']['total_vulnerabilities']}")
        logger.info(f"   └─ Coverage: {audit_results['summary']['audit_coverage']}")

        return {
            "success": True,
            "comprehensive_audit": audit_results
        }

    # ============================================================================
    # ADVANCED CTF TOOLS (v5.0 ENHANCEMENT)
    # ============================================================================

    @mcp.tool()
    def volatility3_analyze(memory_file: str, plugin: str, output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Volatility3 for advanced memory forensics with enhanced logging.

        Args:
            memory_file: Path to memory dump file
            plugin: Volatility3 plugin to execute
            output_file: Output file path
            additional_args: Additional Volatility3 arguments

        Returns:
            Advanced memory forensics results
        """
        data = {
            "memory_file": memory_file,
            "plugin": plugin,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🧠 Starting Volatility3 analysis: {plugin}")
        result = redvector_client.safe_post("api/tools/volatility3", data)
        if result.get("success"):
            logger.info(f"✅ Volatility3 analysis completed")
        else:
            logger.error(f"❌ Volatility3 analysis failed")
        return result

    @mcp.tool()
    def foremost_carving(input_file: str, output_dir: str = "/tmp/foremost_output", file_types: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Foremost for file carving with enhanced logging.

        Args:
            input_file: Input file or device to carve
            output_dir: Output directory for carved files
            file_types: File types to carve (jpg,gif,png,etc.)
            additional_args: Additional Foremost arguments

        Returns:
            File carving results
        """
        data = {
            "input_file": input_file,
            "output_dir": output_dir,
            "file_types": file_types,
            "additional_args": additional_args
        }
        logger.info(f"📁 Starting Foremost file carving: {input_file}")
        result = redvector_client.safe_post("api/tools/foremost", data)
        if result.get("success"):
            logger.info(f"✅ Foremost carving completed")
        else:
            logger.error(f"❌ Foremost carving failed")
        return result

    @mcp.tool()
    def steghide_analysis(action: str, cover_file: str, embed_file: str = "", passphrase: str = "", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Steghide for steganography analysis with enhanced logging.

        Args:
            action: Action to perform (extract, embed, info)
            cover_file: Cover file for steganography
            embed_file: File to embed (for embed action)
            passphrase: Passphrase for steganography
            output_file: Output file path
            additional_args: Additional Steghide arguments

        Returns:
            Steganography analysis results
        """
        data = {
            "action": action,
            "cover_file": cover_file,
            "embed_file": embed_file,
            "passphrase": passphrase,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🖼️ Starting Steghide {action}: {cover_file}")
        result = redvector_client.safe_post("api/tools/steghide", data)
        if result.get("success"):
            logger.info(f"✅ Steghide {action} completed")
        else:
            logger.error(f"❌ Steghide {action} failed")
        return result

    @mcp.tool()
    def exiftool_extract(file_path: str, output_format: str = "", tags: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute ExifTool for metadata extraction with enhanced logging.

        Args:
            file_path: Path to file for metadata extraction
            output_format: Output format (json, xml, csv)
            tags: Specific tags to extract
            additional_args: Additional ExifTool arguments

        Returns:
            Metadata extraction results
        """
        data = {
            "file_path": file_path,
            "output_format": output_format,
            "tags": tags,
            "additional_args": additional_args
        }
        logger.info(f"📷 Starting ExifTool analysis: {file_path}")
        result = redvector_client.safe_post("api/tools/exiftool", data)
        if result.get("success"):
            logger.info(f"✅ ExifTool analysis completed")
        else:
            logger.error(f"❌ ExifTool analysis failed")
        return result

    @mcp.tool()
    def hashpump_attack(signature: str, data: str, key_length: str, append_data: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute HashPump for hash length extension attacks with enhanced logging.

        Args:
            signature: Original hash signature
            data: Original data
            key_length: Length of secret key
            append_data: Data to append
            additional_args: Additional HashPump arguments

        Returns:
            Hash length extension attack results
        """
        data_payload = {
            "signature": signature,
            "data": data,
            "key_length": key_length,
            "append_data": append_data,
            "additional_args": additional_args
        }
        logger.info(f"🔐 Starting HashPump attack")
        result = redvector_client.safe_post("api/tools/hashpump", data_payload)
        if result.get("success"):
            logger.info(f"✅ HashPump attack completed")
        else:
            logger.error(f"❌ HashPump attack failed")
        return result

    # ============================================================================
    # BUG BOUNTY RECONNAISSANCE TOOLS (v5.0 ENHANCEMENT)
    # ============================================================================

    @mcp.tool()
    def hakrawler_crawl(url: str, depth: int = 2, forms: bool = True, robots: bool = True, sitemap: bool = True, wayback: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Hakrawler for web endpoint discovery with enhanced logging.

        Note: Uses standard Kali Linux hakrawler (hakluke/hakrawler) with parameter mapping:
        - url: Piped via echo to stdin (not -url flag)
        - depth: Mapped to -d flag (not -depth)
        - forms: Mapped to -s flag for showing sources
        - robots/sitemap/wayback: Mapped to -subs for subdomain inclusion
        - Always includes -u for unique URLs

        Args:
            url: Target URL to crawl
            depth: Crawling depth (mapped to -d)
            forms: Include forms in crawling (mapped to -s)
            robots: Check robots.txt (mapped to -subs)
            sitemap: Check sitemap.xml (mapped to -subs)
            wayback: Use Wayback Machine (mapped to -subs)
            additional_args: Additional Hakrawler arguments

        Returns:
            Web endpoint discovery results
        """
        data = {
            "url": url,
            "depth": depth,
            "forms": forms,
            "robots": robots,
            "sitemap": sitemap,
            "wayback": wayback,
            "additional_args": additional_args
        }
        logger.info(f"🕷️ Starting Hakrawler crawling: {url}")
        result = redvector_client.safe_post("api/tools/hakrawler", data)
        if result.get("success"):
            logger.info(f"✅ Hakrawler crawling completed")
        else:
            logger.error(f"❌ Hakrawler crawling failed")
        return result

    # ============================================================================
    # ADVANCED WEB SECURITY TOOLS CONTINUED
    # ============================================================================

    @mcp.tool()
    def burpsuite_scan(project_file: str = "", config_file: str = "", target: str = "", headless: bool = False, scan_type: str = "", scan_config: str = "", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Burp Suite with enhanced logging.

        Args:
            project_file: Burp project file path
            config_file: Burp configuration file path
            target: Target URL
            headless: Run in headless mode
            scan_type: Type of scan to perform
            scan_config: Scan configuration
            output_file: Output file path
            additional_args: Additional Burp Suite arguments

        Returns:
            Burp Suite scan results
        """
        data = {
            "project_file": project_file,
            "config_file": config_file,
            "target": target,
            "headless": headless,
            "scan_type": scan_type,
            "scan_config": scan_config,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Burp Suite scan")
        result = redvector_client.safe_post("api/tools/burpsuite-alternative", data)
        if result.get("success"):
            logger.info(f"✅ Burp Suite scan completed")
        else:
            logger.error(f"❌ Burp Suite scan failed")
        return result

    @mcp.tool()
    def zap_scan(target: str = "", scan_type: str = "baseline", api_key: str = "", daemon: bool = False, port: str = "8090", host: str = "0.0.0.0", format_type: str = "xml", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute OWASP ZAP with enhanced logging.

        Args:
            target: Target URL
            scan_type: Type of scan (baseline, full, api)
            api_key: ZAP API key
            daemon: Run in daemon mode
            port: Port for ZAP daemon
            host: Host for ZAP daemon
            format_type: Output format (xml, json, html)
            output_file: Output file path
            additional_args: Additional ZAP arguments

        Returns:
            ZAP scan results
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "api_key": api_key,
            "daemon": daemon,
            "port": port,
            "host": host,
            "format": format_type,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting ZAP scan: {target}")
        result = redvector_client.safe_post("api/tools/zap", data)
        if result.get("success"):
            logger.info(f"✅ ZAP scan completed for {target}")
        else:
            logger.error(f"❌ ZAP scan failed for {target}")
        return result

    @mcp.tool()
    def wafw00f_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute wafw00f to identify and fingerprint WAF products with enhanced logging.

        Args:
            target: Target URL or IP
            additional_args: Additional wafw00f arguments

        Returns:
            WAF detection results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        logger.info(f"🛡️ Starting Wafw00f WAF detection: {target}")
        result = redvector_client.safe_post("api/tools/wafw00f", data)
        if result.get("success"):
            logger.info(f"✅ Wafw00f completed for {target}")
        else:
            logger.error(f"❌ Wafw00f failed for {target}")
        return result

    @mcp.tool()
    def fierce_scan(domain: str, dns_server: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute fierce for DNS reconnaissance with enhanced logging.

        Args:
            domain: Target domain
            dns_server: DNS server to use
            additional_args: Additional fierce arguments

        Returns:
            DNS reconnaissance results
        """
        data = {
            "domain": domain,
            "dns_server": dns_server,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Fierce DNS recon: {domain}")
        result = redvector_client.safe_post("api/tools/fierce", data)
        if result.get("success"):
            logger.info(f"✅ Fierce completed for {domain}")
        else:
            logger.error(f"❌ Fierce failed for {domain}")
        return result

    @mcp.tool()
    def dnsenum_scan(domain: str, dns_server: str = "", wordlist: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute dnsenum for DNS enumeration with enhanced logging.

        Args:
            domain: Target domain
            dns_server: DNS server to use
            wordlist: Wordlist for brute forcing
            additional_args: Additional dnsenum arguments

        Returns:
            DNS enumeration results
        """
        data = {
            "domain": domain,
            "dns_server": dns_server,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting DNSenum: {domain}")
        result = redvector_client.safe_post("api/tools/dnsenum", data)
        if result.get("success"):
            logger.info(f"✅ DNSenum completed for {domain}")
        else:
            logger.error(f"❌ DNSenum failed for {domain}")
        return result

    @mcp.tool()
    def autorecon_scan(
        target: str = "",
        target_file: str = "",
        ports: str = "",
        output_dir: str = "",
        max_scans: str = "",
        max_port_scans: str = "",
        heartbeat: str = "",
        timeout: str = "",
        target_timeout: str = "",
        config_file: str = "",
        global_file: str = "",
        plugins_dir: str = "",
        add_plugins_dir: str = "",
        tags: str = "",
        exclude_tags: str = "",
        port_scans: str = "",
        service_scans: str = "",
        reports: str = "",
        single_target: bool = False,
        only_scans_dir: bool = False,
        no_port_dirs: bool = False,
        nmap: str = "",
        nmap_append: str = "",
        proxychains: bool = False,
        disable_sanity_checks: bool = False,
        disable_keyboard_control: bool = False,
        force_services: str = "",
        accessible: bool = False,
        verbose: int = 0,
        curl_path: str = "",
        dirbuster_tool: str = "",
        dirbuster_wordlist: str = "",
        dirbuster_threads: str = "",
        dirbuster_ext: str = "",
        onesixtyone_community_strings: str = "",
        global_username_wordlist: str = "",
        global_password_wordlist: str = "",
        global_domain: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute AutoRecon for comprehensive target enumeration with full parameter support.

        Args:
            target: Single target to scan
            target_file: File containing multiple targets
            ports: Specific ports to scan
            output_dir: Output directory
            max_scans: Maximum number of concurrent scans
            max_port_scans: Maximum number of concurrent port scans
            heartbeat: Heartbeat interval
            timeout: Global timeout
            target_timeout: Per-target timeout
            config_file: Configuration file path
            global_file: Global configuration file
            plugins_dir: Plugins directory
            add_plugins_dir: Additional plugins directory
            tags: Plugin tags to include
            exclude_tags: Plugin tags to exclude
            port_scans: Port scan plugins to run
            service_scans: Service scan plugins to run
            reports: Report plugins to run
            single_target: Use single target directory structure
            only_scans_dir: Only create scans directory
            no_port_dirs: Don't create port directories
            nmap: Custom nmap command
            nmap_append: Arguments to append to nmap
            proxychains: Use proxychains
            disable_sanity_checks: Disable sanity checks
            disable_keyboard_control: Disable keyboard control
            force_services: Force service detection
            accessible: Enable accessible output
            verbose: Verbosity level (0-3)
            curl_path: Custom curl path
            dirbuster_tool: Directory busting tool
            dirbuster_wordlist: Directory busting wordlist
            dirbuster_threads: Directory busting threads
            dirbuster_ext: Directory busting extensions
            onesixtyone_community_strings: SNMP community strings
            global_username_wordlist: Global username wordlist
            global_password_wordlist: Global password wordlist
            global_domain: Global domain
            additional_args: Additional AutoRecon arguments

        Returns:
            Comprehensive enumeration results with full configurability
        """
        data = {
            "target": target,
            "target_file": target_file,
            "ports": ports,
            "output_dir": output_dir,
            "max_scans": max_scans,
            "max_port_scans": max_port_scans,
            "heartbeat": heartbeat,
            "timeout": timeout,
            "target_timeout": target_timeout,
            "config_file": config_file,
            "global_file": global_file,
            "plugins_dir": plugins_dir,
            "add_plugins_dir": add_plugins_dir,
            "tags": tags,
            "exclude_tags": exclude_tags,
            "port_scans": port_scans,
            "service_scans": service_scans,
            "reports": reports,
            "single_target": single_target,
            "only_scans_dir": only_scans_dir,
            "no_port_dirs": no_port_dirs,
            "nmap": nmap,
            "nmap_append": nmap_append,
            "proxychains": proxychains,
            "disable_sanity_checks": disable_sanity_checks,
            "disable_keyboard_control": disable_keyboard_control,
            "force_services": force_services,
            "accessible": accessible,
            "verbose": verbose,
            "curl_path": curl_path,
            "dirbuster_tool": dirbuster_tool,
            "dirbuster_wordlist": dirbuster_wordlist,
            "dirbuster_threads": dirbuster_threads,
            "dirbuster_ext": dirbuster_ext,
            "onesixtyone_community_strings": onesixtyone_community_strings,
            "global_username_wordlist": global_username_wordlist,
            "global_password_wordlist": global_password_wordlist,
            "global_domain": global_domain,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting AutoRecon comprehensive enumeration: {target}")
        result = redvector_client.safe_post("api/tools/autorecon", data)
        if result.get("success"):
            logger.info(f"✅ AutoRecon comprehensive enumeration completed for {target}")
        else:
            logger.error(f"❌ AutoRecon failed for {target}")
        return result

    # ============================================================================
    # SYSTEM MONITORING & TELEMETRY
    # ============================================================================

    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        Check the health status of the RedVector AI server.

        Returns:
            Server health information with tool availability and telemetry
        """
        logger.info(f"🏥 Checking RedVector AI server health")
        result = redvector_client.check_health()
        if result.get("status") == "healthy":
            logger.info(f"✅ Server is healthy - {result.get('total_tools_available', 0)} tools available")
        else:
            logger.warning(f"⚠️  Server health check returned: {result.get('status', 'unknown')}")
        return result

    @mcp.tool()
    def get_cache_stats() -> Dict[str, Any]:
        """
        Get cache statistics from the RedVector AI server.

        Returns:
            Cache performance statistics
        """
        logger.info(f"💾 Getting cache statistics")
        result = redvector_client.safe_get("api/cache/stats")
        if "hit_rate" in result:
            logger.info(f"📊 Cache hit rate: {result.get('hit_rate', 'unknown')}")
        return result

    @mcp.tool()
    def clear_cache() -> Dict[str, Any]:
        """
        Clear the cache on the RedVector AI server.

        Returns:
            Cache clear operation results
        """
        logger.info(f"🧹 Clearing server cache")
        result = redvector_client.safe_post("api/cache/clear", {})
        if result.get("success"):
            logger.info(f"✅ Cache cleared successfully")
        else:
            logger.error(f"❌ Failed to clear cache")
        return result

    @mcp.tool()
    def get_telemetry() -> Dict[str, Any]:
        """
        Get system telemetry from the RedVector AI server.

        Returns:
            System performance and usage telemetry
        """
        logger.info(f"📈 Getting system telemetry")
        result = redvector_client.safe_get("api/telemetry")
        if "commands_executed" in result:
            logger.info(f"📊 Commands executed: {result.get('commands_executed', 0)}")
        return result

    # ============================================================================
    # PROCESS MANAGEMENT TOOLS (v5.0 ENHANCEMENT)
    # ============================================================================

    @mcp.tool()
    def list_active_processes() -> Dict[str, Any]:
        """
        List all active processes on the RedVector AI server.

        Returns:
            List of active processes with their status and progress
        """
        logger.info("📊 Listing active processes")
        result = redvector_client.safe_get("api/processes/list")
        if result.get("success"):
            logger.info(f"✅ Found {result.get('total_count', 0)} active processes")
        else:
            logger.error("❌ Failed to list processes")
        return result

    @mcp.tool()
    def get_process_status(pid: int) -> Dict[str, Any]:
        """
        Get the status of a specific process.

        Args:
            pid: Process ID to check

        Returns:
            Process status information including progress and runtime
        """
        logger.info(f"🔍 Checking status of process {pid}")
        result = redvector_client.safe_get(f"api/processes/status/{pid}")
        if result.get("success"):
            logger.info(f"✅ Process {pid} status retrieved")
        else:
            logger.error(f"❌ Process {pid} not found or error occurred")
        return result

    @mcp.tool()
    def terminate_process(pid: int) -> Dict[str, Any]:
        """
        Terminate a specific running process.

        Args:
            pid: Process ID to terminate

        Returns:
            Success status of the termination operation
        """
        logger.info(f"🛑 Terminating process {pid}")
        result = redvector_client.safe_post(f"api/processes/terminate/{pid}", {})
        if result.get("success"):
            logger.info(f"✅ Process {pid} terminated successfully")
        else:
            logger.error(f"❌ Failed to terminate process {pid}")
        return result

    @mcp.tool()
    def pause_process(pid: int) -> Dict[str, Any]:
        """
        Pause a specific running process.

        Args:
            pid: Process ID to pause

        Returns:
            Success status of the pause operation
        """
        logger.info(f"⏸️ Pausing process {pid}")
        result = redvector_client.safe_post(f"api/processes/pause/{pid}", {})
        if result.get("success"):
            logger.info(f"✅ Process {pid} paused successfully")
        else:
            logger.error(f"❌ Failed to pause process {pid}")
        return result

    @mcp.tool()
    def resume_process(pid: int) -> Dict[str, Any]:
        """
        Resume a paused process.

        Args:
            pid: Process ID to resume

        Returns:
            Success status of the resume operation
        """
        logger.info(f"▶️ Resuming process {pid}")
        result = redvector_client.safe_post(f"api/processes/resume/{pid}", {})
        if result.get("success"):
            logger.info(f"✅ Process {pid} resumed successfully")
        else:
            logger.error(f"❌ Failed to resume process {pid}")
        return result

    @mcp.tool()
    def get_process_dashboard() -> Dict[str, Any]:
        """
        Get enhanced process dashboard with visual status indicators.

        Returns:
            Real-time dashboard with progress bars, system metrics, and process status
        """
        logger.info("📊 Getting process dashboard")
        result = redvector_client.safe_get("api/processes/dashboard")
        if result.get("success", True) and "total_processes" in result:
            total = result.get("total_processes", 0)
            logger.info(f"✅ Dashboard retrieved: {total} active processes")

            # Log visual summary for better UX
            if total > 0:
                logger.info("📈 Active Processes Summary:")
                for proc in result.get("processes", [])[:3]:  # Show first 3
                    logger.info(f"   ├─ PID {proc['pid']}: {proc['progress_bar']} {proc['progress_percent']}")
        else:
            logger.error("❌ Failed to get process dashboard")
        return result

    @mcp.tool()
    def execute_command(command: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Execute an arbitrary command on the RedVector AI server with enhanced logging.

        Args:
            command: The command to execute
            use_cache: Whether to use caching for this command

        Returns:
            Command execution results with enhanced telemetry
        """
        try:
            logger.info(f"⚡ Executing command: {command}")
            result = redvector_client.execute_command(command, use_cache)
            if "error" in result:
                logger.error(f"❌ Command failed: {result['error']}")
                return {
                    "success": False,
                    "error": result["error"],
                    "stdout": "",
                    "stderr": f"Error executing command: {result['error']}"
                }

            if result.get("success"):
                execution_time = result.get("execution_time", 0)
                logger.info(f"✅ Command completed successfully in {execution_time:.2f}s")
            else:
                logger.warning(f"⚠️  Command completed with errors")

            return result
        except Exception as e:
            logger.error(f"💥 Error executing command '{command}': {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "stdout": "",
                "stderr": f"Error executing command: {str(e)}"
            }

    # ============================================================================
    # ADVANCED VULNERABILITY INTELLIGENCE MCP TOOLS (v2.0 ENHANCEMENT)
    # ============================================================================

    @mcp.tool()
    def monitor_cve_feeds(hours: int = 24, severity_filter: str = "HIGH,CRITICAL", keywords: str = "") -> Dict[str, Any]:
        """
        Monitor CVE databases for new vulnerabilities with AI analysis.

        Args:
            hours: Hours to look back for new CVEs (default: 24)
            severity_filter: Filter by CVSS severity - comma-separated values (LOW,MEDIUM,HIGH,CRITICAL,ALL)
            keywords: Filter CVEs by keywords in description (comma-separated)

        Returns:
            Latest CVEs with exploitability analysis and threat intelligence

        Example:
            monitor_cve_feeds(48, "CRITICAL", "remote code execution")
        """
        data = {
            "hours": hours,
            "severity_filter": severity_filter,
            "keywords": keywords
        }
        logger.info(f"🔍 Monitoring CVE feeds for last {hours} hours | Severity: {severity_filter}")
        result = redvector_client.safe_post("api/vuln-intel/cve-monitor", data)

        if result.get("success"):
            cve_count = len(result.get("cve_monitoring", {}).get("cves", []))
            exploit_analysis_count = len(result.get("exploitability_analysis", []))
            logger.info(f"✅ Found {cve_count} CVEs with {exploit_analysis_count} exploitability analyses")

        return result

    @mcp.tool()
    def generate_exploit_from_cve(cve_id: str, target_os: str = "", target_arch: str = "x64", exploit_type: str = "poc", evasion_level: str = "none") -> Dict[str, Any]:
        """
        Generate working exploits from CVE information using AI-powered analysis.

        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
            target_os: Target operating system (windows, linux, macos, any)
            target_arch: Target architecture (x86, x64, arm, any)
            exploit_type: Type of exploit to generate (poc, weaponized, stealth)
            evasion_level: Evasion sophistication (none, basic, advanced)

        Returns:
            Generated exploit code with testing instructions and evasion techniques

        Example:
            generate_exploit_from_cve("CVE-2024-1234", "linux", "x64", "weaponized", "advanced")
        """
        data = {
            "cve_id": cve_id,
            "target_os": target_os,
            "target_arch": target_arch,
            "exploit_type": exploit_type,
            "evasion_level": evasion_level
        }
        logger.info(f"🤖 Generating {exploit_type} exploit for {cve_id} | Target: {target_os} {target_arch}")
        result = redvector_client.safe_post("api/vuln-intel/exploit-generate", data)

        if result.get("success"):
            cve_analysis = result.get("cve_analysis", {})
            exploit_gen = result.get("exploit_generation", {})
            exploitability = cve_analysis.get("exploitability_level", "UNKNOWN")
            exploit_success = exploit_gen.get("success", False)

            logger.info(f"📊 CVE Analysis: {exploitability} exploitability")
            logger.info(f"🎯 Exploit Generation: {'SUCCESS' if exploit_success else 'FAILED'}")

        return result

    @mcp.tool()
    def discover_attack_chains(target_software: str, attack_depth: int = 3, include_zero_days: bool = False) -> Dict[str, Any]:
        """
        Discover multi-stage attack chains for target software with vulnerability correlation.

        Args:
            target_software: Target software/system (e.g., "Apache HTTP Server", "Windows Server 2019")
            attack_depth: Maximum number of stages in attack chain (1-5)
            include_zero_days: Include potential zero-day vulnerabilities in analysis

        Returns:
            Attack chains with vulnerability combinations, success probabilities, and exploit availability

        Example:
            discover_attack_chains("Apache HTTP Server 2.4", 4, True)
        """
        data = {
            "target_software": target_software,
            "attack_depth": min(max(attack_depth, 1), 5),  # Clamp between 1-5
            "include_zero_days": include_zero_days
        }
        logger.info(f"🔗 Discovering attack chains for {target_software} | Depth: {attack_depth} | Zero-days: {include_zero_days}")
        result = redvector_client.safe_post("api/vuln-intel/attack-chains", data)

        if result.get("success"):
            chains = result.get("attack_chain_discovery", {}).get("attack_chains", [])
            enhanced_chains = result.get("attack_chain_discovery", {}).get("enhanced_chains", [])

            logger.info(f"📊 Found {len(chains)} attack chains")
            if enhanced_chains:
                logger.info(f"🎯 Enhanced {len(enhanced_chains)} chains with exploit analysis")

        return result

    @mcp.tool()
    def research_zero_day_opportunities(target_software: str, analysis_depth: str = "standard", source_code_url: str = "") -> Dict[str, Any]:
        """
        Automated zero-day vulnerability research using AI analysis and pattern recognition.

        Args:
            target_software: Software to research for vulnerabilities (e.g., "nginx", "OpenSSL")
            analysis_depth: Depth of analysis (quick, standard, comprehensive)
            source_code_url: URL to source code repository for enhanced analysis

        Returns:
            Potential vulnerability areas with exploitation feasibility and research recommendations

        Example:
            research_zero_day_opportunities("nginx 1.20", "comprehensive", "https://github.com/nginx/nginx")
        """
        if analysis_depth not in ["quick", "standard", "comprehensive"]:
            analysis_depth = "standard"

        data = {
            "target_software": target_software,
            "analysis_depth": analysis_depth,
            "source_code_url": source_code_url
        }
        logger.info(f"🔬 Researching zero-day opportunities in {target_software} | Depth: {analysis_depth}")
        result = redvector_client.safe_post("api/vuln-intel/zero-day-research", data)

        if result.get("success"):
            research = result.get("zero_day_research", {})
            potential_vulns = len(research.get("potential_vulnerabilities", []))
            risk_score = research.get("risk_assessment", {}).get("risk_score", 0)

            logger.info(f"📊 Found {potential_vulns} potential vulnerability areas")
            logger.info(f"🎯 Risk Score: {risk_score}/100")

        return result

    @mcp.tool()
    def correlate_threat_intelligence(indicators: str, timeframe: str = "30d", sources: str = "all") -> Dict[str, Any]:
        """
        Correlate threat intelligence across multiple sources with advanced analysis.

        Args:
            indicators: Comma-separated IOCs (IPs, domains, hashes, CVEs, etc.)
            timeframe: Time window for correlation (7d, 30d, 90d, 1y)
            sources: Intelligence sources to query (cve, exploit-db, github, twitter, all)

        Returns:
            Correlated threat intelligence with attribution, timeline, and threat scoring

        Example:
            correlate_threat_intelligence("CVE-2024-1234,192.168.1.100,malware.exe", "90d", "all")
        """
        # Validate timeframe
        valid_timeframes = ["7d", "30d", "90d", "1y"]
        if timeframe not in valid_timeframes:
            timeframe = "30d"

        # Parse indicators
        indicator_list = [i.strip() for i in indicators.split(",") if i.strip()]

        if not indicator_list:
            logger.error("❌ No valid indicators provided")
            return {"success": False, "error": "No valid indicators provided"}

        data = {
            "indicators": indicator_list,
            "timeframe": timeframe,
            "sources": sources
        }
        logger.info(f"🧠 Correlating threat intelligence for {len(indicator_list)} indicators | Timeframe: {timeframe}")
        result = redvector_client.safe_post("api/vuln-intel/threat-feeds", data)

        if result.get("success"):
            threat_intel = result.get("threat_intelligence", {})
            correlations = len(threat_intel.get("correlations", []))
            threat_score = threat_intel.get("threat_score", 0)

            logger.info(f"📊 Found {correlations} threat correlations")
            logger.info(f"🎯 Overall Threat Score: {threat_score:.1f}/100")

        return result

    @mcp.tool()
    def advanced_payload_generation(attack_type: str, target_context: str = "", evasion_level: str = "standard", custom_constraints: str = "") -> Dict[str, Any]:
        """
        Generate advanced payloads with AI-powered evasion techniques and contextual adaptation.

        Args:
            attack_type: Type of attack (rce, privilege_escalation, persistence, exfiltration, xss, sqli)
            target_context: Target environment details (OS, software versions, security controls)
            evasion_level: Evasion sophistication (basic, standard, advanced, nation-state)
            custom_constraints: Custom payload constraints (size limits, character restrictions, etc.)

        Returns:
            Advanced payloads with multiple evasion techniques and deployment instructions

        Example:
            advanced_payload_generation("rce", "Windows 11 + Defender + AppLocker", "nation-state", "max_size:256,no_quotes")
        """
        valid_attack_types = ["rce", "privilege_escalation", "persistence", "exfiltration", "xss", "sqli", "lfi", "ssrf"]
        valid_evasion_levels = ["basic", "standard", "advanced", "nation-state"]

        if attack_type not in valid_attack_types:
            attack_type = "rce"

        if evasion_level not in valid_evasion_levels:
            evasion_level = "standard"

        data = {
            "attack_type": attack_type,
            "target_context": target_context,
            "evasion_level": evasion_level,
            "custom_constraints": custom_constraints
        }
        logger.info(f"🎯 Generating advanced {attack_type} payload | Evasion: {evasion_level}")
        if target_context:
            logger.info(f"🎯 Target Context: {target_context}")

        result = redvector_client.safe_post("api/ai/advanced-payload-generation", data)

        if result.get("success"):
            payload_gen = result.get("advanced_payload_generation", {})
            payload_count = payload_gen.get("payload_count", 0)
            evasion_applied = payload_gen.get("evasion_level", "none")

            logger.info(f"📊 Generated {payload_count} advanced payloads")
            logger.info(f"🛡️ Evasion Level Applied: {evasion_applied}")

        return result

    @mcp.tool()
    def vulnerability_intelligence_dashboard() -> Dict[str, Any]:
        """
        Get a comprehensive vulnerability intelligence dashboard with latest threats and trends.

        Returns:
            Dashboard with latest CVEs, trending vulnerabilities, exploit availability, and threat landscape

        Example:
            vulnerability_intelligence_dashboard()
        """
        logger.info("📊 Generating vulnerability intelligence dashboard")

        # Get latest critical CVEs
        latest_cves = redvector_client.safe_post("api/vuln-intel/cve-monitor", {
            "hours": 24,
            "severity_filter": "CRITICAL",
            "keywords": ""
        })

        # Get trending attack types
        trending_research = redvector_client.safe_post("api/vuln-intel/zero-day-research", {
            "target_software": "web applications",
            "analysis_depth": "quick"
        })

        # Compile dashboard
        dashboard = {
            "timestamp": time.time(),
            "latest_critical_cves": latest_cves.get("cve_monitoring", {}).get("cves", [])[:5],
            "threat_landscape": {
                "high_risk_software": ["Apache HTTP Server", "Microsoft Exchange", "VMware vCenter", "Fortinet FortiOS"],
                "trending_attack_vectors": ["Supply chain attacks", "Cloud misconfigurations", "Zero-day exploits", "AI-powered attacks"],
                "active_threat_groups": ["APT29", "Lazarus Group", "FIN7", "REvil"],
            },
            "exploit_intelligence": {
                "new_public_exploits": "Simulated data - check exploit-db for real data",
                "weaponized_exploits": "Monitor threat intelligence feeds",
                "exploit_kits": "Track underground markets"
            },
            "recommendations": [
                "Prioritize patching for critical CVEs discovered in last 24h",
                "Monitor for zero-day activity in trending attack vectors",
                "Implement advanced threat detection for active threat groups",
                "Review security controls against nation-state level attacks"
            ]
        }

        logger.info("✅ Vulnerability intelligence dashboard generated")
        return {
            "success": True,
            "dashboard": dashboard
        }

    @mcp.tool()
    def threat_hunting_assistant(target_environment: str, threat_indicators: str = "", hunt_focus: str = "general") -> Dict[str, Any]:
        """
        AI-powered threat hunting assistant with vulnerability correlation and attack simulation.

        Args:
            target_environment: Environment to hunt in (e.g., "Windows Domain", "Cloud Infrastructure")
            threat_indicators: Known IOCs or suspicious indicators to investigate
            hunt_focus: Focus area (general, apt, ransomware, insider_threat, supply_chain)

        Returns:
            Threat hunting playbook with detection queries, IOCs, and investigation steps

        Example:
            threat_hunting_assistant("Windows Domain", "suspicious_process.exe,192.168.1.100", "apt")
        """
        valid_hunt_focus = ["general", "apt", "ransomware", "insider_threat", "supply_chain"]
        if hunt_focus not in valid_hunt_focus:
            hunt_focus = "general"

        logger.info(f"🔍 Generating threat hunting playbook for {target_environment} | Focus: {hunt_focus}")

        # Parse indicators if provided
        indicators = [i.strip() for i in threat_indicators.split(",") if i.strip()] if threat_indicators else []

        # Generate hunting playbook
        hunting_playbook = {
            "target_environment": target_environment,
            "hunt_focus": hunt_focus,
            "indicators_analyzed": indicators,
            "detection_queries": [],
            "investigation_steps": [],
            "threat_scenarios": [],
            "mitigation_strategies": []
        }

        # Environment-specific detection queries
        if "windows" in target_environment.lower():
            hunting_playbook["detection_queries"] = [
                "Get-WinEvent | Where-Object {$_.Id -eq 4688 -and $_.Message -like '*suspicious*'}",
                "Get-Process | Where-Object {$_.ProcessName -notin @('explorer.exe', 'svchost.exe')}",
                "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Get-NetTCPConnection | Where-Object {$_.State -eq 'Established' -and $_.RemoteAddress -notlike '10.*'}"
            ]
        elif "cloud" in target_environment.lower():
            hunting_playbook["detection_queries"] = [
                "CloudTrail logs for unusual API calls",
                "Failed authentication attempts from unknown IPs",
                "Privilege escalation events",
                "Data exfiltration indicators"
            ]

        # Focus-specific threat scenarios
        focus_scenarios = {
            "apt": [
                "Spear phishing with weaponized documents",
                "Living-off-the-land techniques",
                "Lateral movement via stolen credentials",
                "Data staging and exfiltration"
            ],
            "ransomware": [
                "Initial access via RDP/VPN",
                "Privilege escalation and persistence",
                "Shadow copy deletion",
                "Encryption and ransom note deployment"
            ],
            "insider_threat": [
                "Unusual data access patterns",
                "After-hours activity",
                "Large data downloads",
                "Access to sensitive systems"
            ],
            "supply_chain": [
                "Third-party dependency compromise",
                "Build pipeline tampering",
                "Upstream repository poisoning",
                "Software update hijacking"
            ],
            "general": [
                "Unauthorized access attempts",
                "Suspicious process execution",
                "Network anomalies",
                "Data access violations"
            ]
        }

        hunting_playbook["threat_scenarios"] = focus_scenarios.get(hunt_focus, [
            "Unauthorized access attempts",
            "Suspicious process execution",
            "Network anomalies",
            "Data access violations"
        ])

        # Investigation steps
        hunting_playbook["investigation_steps"] = [
            "1. Validate initial indicators and expand IOC list",
            "2. Run detection queries and analyze results",
            "3. Correlate events across multiple data sources",
            "4. Identify affected systems and user accounts",
            "5. Assess scope and impact of potential compromise",
            "6. Implement containment measures if threat confirmed",
            "7. Document findings and update detection rules"
        ]

        # Correlate with vulnerability intelligence if indicators provided
        if indicators:
            logger.info(f"🧠 Correlating {len(indicators)} indicators with threat intelligence")
            correlation_result = correlate_threat_intelligence(",".join(indicators), "30d", "all")

            if correlation_result.get("success"):
                hunting_playbook["threat_correlation"] = correlation_result.get("threat_intelligence", {})

        logger.info("✅ Threat hunting playbook generated")
        return {
            "success": True,
            "hunting_playbook": hunting_playbook
        }

    # ============================================================================
    # ENHANCED VISUAL OUTPUT TOOLS
    # ============================================================================

    @mcp.tool()
    def get_live_dashboard() -> Dict[str, Any]:
        """
        Get a beautiful live dashboard showing all active processes with enhanced visual formatting.

        Returns:
            Live dashboard with visual process monitoring and system metrics
        """
        logger.info("📊 Fetching live process dashboard")
        result = redvector_client.safe_get("api/processes/dashboard")
        if result.get("success", True):
            logger.info("✅ Live dashboard retrieved successfully")
        else:
            logger.error("❌ Failed to retrieve live dashboard")
        return result

    @mcp.tool()
    def create_vulnerability_report(vulnerabilities: str, target: str = "", scan_type: str = "comprehensive") -> Dict[str, Any]:
        """
        Create a beautiful vulnerability report with severity-based styling and visual indicators.

        Args:
            vulnerabilities: JSON string containing vulnerability data
            target: Target that was scanned
            scan_type: Type of scan performed

        Returns:
            Formatted vulnerability report with visual enhancements
        """

        try:
            # Parse vulnerabilities if provided as JSON string
            if isinstance(vulnerabilities, str):
                vuln_data = json.loads(vulnerabilities)
            else:
                vuln_data = vulnerabilities

            logger.info(f"📋 Creating vulnerability report for {len(vuln_data)} findings")

            # Create individual vulnerability cards
            vulnerability_cards = []
            for vuln in vuln_data:
                card_result = redvector_client.safe_post("api/visual/vulnerability-card", vuln)
                if card_result.get("success"):
                    vulnerability_cards.append(card_result.get("vulnerability_card", ""))

            # Create summary report
            summary_data = {
                "target": target,
                "vulnerabilities": vuln_data,
                "tools_used": [scan_type],
                "execution_time": 0
            }

            summary_result = redvector_client.safe_post("api/visual/summary-report", summary_data)

            logger.info("✅ Vulnerability report created successfully")
            return {
                "success": True,
                "vulnerability_cards": vulnerability_cards,
                "summary_report": summary_result.get("summary_report", ""),
                "total_vulnerabilities": len(vuln_data),
                "timestamp": summary_result.get("timestamp", "")
            }

        except Exception as e:
            logger.error(f"❌ Failed to create vulnerability report: {str(e)}")
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def format_tool_output_visual(tool_name: str, output: str, success: bool = True) -> Dict[str, Any]:
        """
        Format tool output with beautiful visual styling, syntax highlighting, and structure.

        Args:
            tool_name: Name of the security tool
            output: Raw output from the tool
            success: Whether the tool execution was successful

        Returns:
            Beautifully formatted tool output with visual enhancements
        """
        logger.info(f"🎨 Formatting output for {tool_name}")

        data = {
            "tool": tool_name,
            "output": output,
            "success": success
        }

        result = redvector_client.safe_post("api/visual/tool-output", data)
        if result.get("success"):
            logger.info(f"✅ Tool output formatted successfully for {tool_name}")
        else:
            logger.error(f"❌ Failed to format tool output for {tool_name}")

        return result

    @mcp.tool()
    def create_scan_summary(target: str, tools_used: str, vulnerabilities_found: int = 0,
                           execution_time: float = 0.0, findings: str = "") -> Dict[str, Any]:
        """
        Create a comprehensive scan summary report with beautiful visual formatting.

        Args:
            target: Target that was scanned
            tools_used: Comma-separated list of tools used
            vulnerabilities_found: Number of vulnerabilities discovered
            execution_time: Total execution time in seconds
            findings: Additional findings or notes

        Returns:
            Beautiful scan summary report with visual enhancements
        """
        logger.info(f"📊 Creating scan summary for {target}")

        tools_list = [tool.strip() for tool in tools_used.split(",")]

        summary_data = {
            "target": target,
            "tools_used": tools_list,
            "execution_time": execution_time,
            "vulnerabilities": [{"severity": "info"}] * vulnerabilities_found,  # Mock data for count
            "findings": findings
        }

        result = redvector_client.safe_post("api/visual/summary-report", summary_data)
        if result.get("success"):
            logger.info("✅ Scan summary created successfully")
        else:
            logger.error("❌ Failed to create scan summary")

        return result

    @mcp.tool()
    def display_system_metrics() -> Dict[str, Any]:
        """
        Display current system metrics and performance indicators with visual formatting.

        Returns:
            System metrics with beautiful visual presentation
        """
        logger.info("📈 Fetching system metrics")

        # Get telemetry data
        telemetry_result = redvector_client.safe_get("api/telemetry")

        if telemetry_result.get("success", True):
            logger.info("✅ System metrics retrieved successfully")

            # Format the metrics for better display
            metrics = telemetry_result.get("system_metrics", {})
            stats = {
                "cpu_percent": float(metrics.get("cpu_percent", 0) or 0),
                "memory_percent": float(metrics.get("memory_percent", 0) or 0),
                "disk_usage": float(metrics.get("disk_usage", 0) or 0),
                "uptime_seconds": float(telemetry_result.get("uptime_seconds", 0) or 0),
                "commands_executed": telemetry_result.get("commands_executed", 0),
                "success_rate": telemetry_result.get("success_rate", "0%")
            }

            return {
                "success": True,
                "metrics": stats,
                "formatted_display": f"""
🖥️  System Performance Metrics:
├─ CPU Usage: {stats['cpu_percent']:.1f}%
├─ Memory Usage: {stats['memory_percent']:.1f}%
├─ Disk Usage: {stats['disk_usage']:.1f}%
├─ Uptime: {stats['uptime_seconds']:.0f}s
├─ Commands Executed: {stats['commands_executed']}
└─ Success Rate: {stats['success_rate']}
""",
                "timestamp": telemetry_result.get("timestamp", "")
            }
        else:
            logger.error("❌ Failed to retrieve system metrics")
            return telemetry_result

    # ============================================================================
    # INTELLIGENT DECISION ENGINE TOOLS
    # ============================================================================

    @mcp.tool()
    def analyze_target_intelligence(target: str) -> Dict[str, Any]:
        """
        Analyze target using AI-powered intelligence to create comprehensive profile.

        Args:
            target: Target URL, IP address, or domain to analyze

        Returns:
            Comprehensive target profile with technology detection, risk assessment, and recommendations
        """
        logger.info(f"🧠 Analyzing target intelligence for: {target}")

        data = {"target": target}
        result = redvector_client.safe_post("api/intelligence/analyze-target", data)

        if result.get("success"):
            profile = result.get("target_profile", {})
            logger.info(f"✅ Target analysis completed - Type: {profile.get('target_type')}, Risk: {profile.get('risk_level')}")
        else:
            logger.error(f"❌ Target analysis failed for {target}")

        return result

    @mcp.tool()
    def select_optimal_tools_ai(target: str, objective: str = "comprehensive") -> Dict[str, Any]:
        """
        Use AI to select optimal security tools based on target analysis and testing objective.

        Args:
            target: Target to analyze
            objective: Testing objective - "comprehensive", "quick", or "stealth"

        Returns:
            AI-selected optimal tools with effectiveness ratings and target profile
        """
        logger.info(f"🎯 Selecting optimal tools for {target} with objective: {objective}")

        data = {
            "target": target,
            "objective": objective
        }
        result = redvector_client.safe_post("api/intelligence/select-tools", data)

        if result.get("success"):
            tools = result.get("selected_tools", [])
            logger.info(f"✅ AI selected {len(tools)} optimal tools: {', '.join(tools[:3])}{'...' if len(tools) > 3 else ''}")
        else:
            logger.error(f"❌ Tool selection failed for {target}")

        return result

    @mcp.tool()
    def optimize_tool_parameters_ai(target: str, tool: str, context: str = "{}") -> Dict[str, Any]:
        """
        Use AI to optimize tool parameters based on target profile and context.

        Args:
            target: Target to test
            tool: Security tool to optimize
            context: JSON string with additional context (stealth, aggressive, etc.)

        Returns:
            AI-optimized parameters for maximum effectiveness
        """

        logger.info(f"⚙️  Optimizing parameters for {tool} against {target}")

        try:
            context_dict = json.loads(context) if context != "{}" else {}
        except (json.JSONDecodeError, ValueError):
            context_dict = {}

        data = {
            "target": target,
            "tool": tool,
            "context": context_dict
        }
        result = redvector_client.safe_post("api/intelligence/optimize-parameters", data)

        if result.get("success"):
            params = result.get("optimized_parameters", {})
            logger.info(f"✅ Parameters optimized for {tool} - {len(params)} parameters configured")
        else:
            logger.error(f"❌ Parameter optimization failed for {tool}")

        return result

    @mcp.tool()
    def create_attack_chain_ai(target: str, objective: str = "comprehensive") -> Dict[str, Any]:
        """
        Create an intelligent attack chain using AI-driven tool sequencing and optimization.

        Args:
            target: Target for the attack chain
            objective: Attack objective - "comprehensive", "quick", or "stealth"

        Returns:
            AI-generated attack chain with success probability and time estimates
        """
        logger.info(f"⚔️  Creating AI-driven attack chain for {target}")

        data = {
            "target": target,
            "objective": objective
        }
        result = redvector_client.safe_post("api/intelligence/create-attack-chain", data)

        if result.get("success"):
            chain = result.get("attack_chain", {})
            steps = len(chain.get("steps", []))
            success_prob = chain.get("success_probability", 0)
            estimated_time = chain.get("estimated_time", 0)

            logger.info(f"✅ Attack chain created - {steps} steps, {success_prob:.2f} success probability, ~{estimated_time}s")
        else:
            logger.error(f"❌ Attack chain creation failed for {target}")

        return result

    @mcp.tool()
    def intelligent_smart_scan(target: str, objective: str = "comprehensive", max_tools: int = 5) -> Dict[str, Any]:
        """
        Execute an intelligent scan using AI-driven tool selection and parameter optimization.

        Args:
            target: Target to scan
            objective: Scanning objective - "comprehensive", "quick", or "stealth"
            max_tools: Maximum number of tools to use

        Returns:
            Results from AI-optimized scanning with tool execution summary
        """
        logger.info(f"{RedVectorColors.FIRE_RED}🚀 Starting intelligent smart scan for {target}{RedVectorColors.RESET}")

        data = {
            "target": target,
            "objective": objective,
            "max_tools": max_tools
        }
        result = redvector_client.safe_post("api/intelligence/smart-scan", data)

        if result.get("success"):
            scan_results = result.get("scan_results", {})
            tools_executed = scan_results.get("tools_executed", [])
            execution_summary = scan_results.get("execution_summary", {})

            # Enhanced logging with detailed results
            logger.info(f"{RedVectorColors.SUCCESS}✅ Intelligent scan completed for {target}{RedVectorColors.RESET}")
            logger.info(f"{RedVectorColors.CYBER_ORANGE}📊 Execution Summary:{RedVectorColors.RESET}")
            logger.info(f"   • Tools executed: {execution_summary.get('successful_tools', 0)}/{execution_summary.get('total_tools', 0)}")
            logger.info(f"   • Success rate: {execution_summary.get('success_rate', 0):.1f}%")
            logger.info(f"   • Total vulnerabilities: {scan_results.get('total_vulnerabilities', 0)}")
            logger.info(f"   • Execution time: {execution_summary.get('total_execution_time', 0):.2f}s")

            # Log successful tools
            successful_tools = [t['tool'] for t in tools_executed if t.get('success')]
            if successful_tools:
                logger.info(f"{RedVectorColors.HIGHLIGHT_GREEN} Successful tools: {', '.join(successful_tools)} {RedVectorColors.RESET}")

            # Log failed tools
            failed_tools = [t['tool'] for t in tools_executed if not t.get('success')]
            if failed_tools:
                logger.warning(f"{RedVectorColors.HIGHLIGHT_RED} Failed tools: {', '.join(failed_tools)} {RedVectorColors.RESET}")

            # Log vulnerabilities found
            if scan_results.get('total_vulnerabilities', 0) > 0:
                logger.warning(f"{RedVectorColors.VULN_HIGH}🚨 {scan_results['total_vulnerabilities']} vulnerabilities detected!{RedVectorColors.RESET}")
        else:
            logger.error(f"{RedVectorColors.ERROR}❌ Intelligent scan failed for {target}: {result.get('error', 'Unknown error')}{RedVectorColors.RESET}")

        return result

    @mcp.tool()
    def detect_technologies_ai(target: str) -> Dict[str, Any]:
        """
        Use AI to detect technologies and provide technology-specific testing recommendations.

        Args:
            target: Target to analyze for technology detection

        Returns:
            Detected technologies with AI-generated testing recommendations
        """
        logger.info(f"🔍 Detecting technologies for {target}")

        data = {"target": target}
        result = redvector_client.safe_post("api/intelligence/technology-detection", data)

        if result.get("success"):
            technologies = result.get("detected_technologies", [])
            cms = result.get("cms_type")
            recommendations = result.get("technology_recommendations", {})

            tech_info = f"Technologies: {', '.join(technologies)}"
            if cms:
                tech_info += f", CMS: {cms}"

            logger.info(f"✅ Technology detection completed - {tech_info}")
            logger.info(f"📋 Generated {len(recommendations)} technology-specific recommendations")
        else:
            logger.error(f"❌ Technology detection failed for {target}")

        return result

    @mcp.tool()
    def ai_reconnaissance_workflow(target: str, depth: str = "standard") -> Dict[str, Any]:
        """
        Execute AI-driven reconnaissance workflow with intelligent tool chaining.

        Args:
            target: Target for reconnaissance
            depth: Reconnaissance depth - "surface", "standard", or "deep"

        Returns:
            Comprehensive reconnaissance results with AI-driven insights
        """
        logger.info(f"🕵️  Starting AI reconnaissance workflow for {target} (depth: {depth})")

        # First analyze the target
        analysis_result = redvector_client.safe_post("api/intelligence/analyze-target", {"target": target})

        if not analysis_result.get("success"):
            return analysis_result

        # Create attack chain for reconnaissance
        objective = "comprehensive" if depth == "deep" else "quick" if depth == "surface" else "comprehensive"
        chain_result = redvector_client.safe_post("api/intelligence/create-attack-chain", {
            "target": target,
            "objective": objective
        })

        if not chain_result.get("success"):
            return chain_result

        # Execute the reconnaissance
        scan_result = redvector_client.safe_post("api/intelligence/smart-scan", {
            "target": target,
            "objective": objective,
            "max_tools": 8 if depth == "deep" else 3 if depth == "surface" else 5
        })

        logger.info(f"✅ AI reconnaissance workflow completed for {target}")

        return {
            "success": True,
            "target": target,
            "depth": depth,
            "target_analysis": analysis_result.get("target_profile", {}),
            "attack_chain": chain_result.get("attack_chain", {}),
            "scan_results": scan_result.get("scan_results", {}),
            "timestamp": datetime.now().isoformat()
        }

    @mcp.tool()
    def ai_vulnerability_assessment(target: str, focus_areas: str = "all") -> Dict[str, Any]:
        """
        Perform AI-driven vulnerability assessment with intelligent prioritization.

        Args:
            target: Target for vulnerability assessment
            focus_areas: Comma-separated focus areas - "web", "network", "api", "all"

        Returns:
            Prioritized vulnerability assessment results with AI insights
        """
        logger.info(f"🔬 Starting AI vulnerability assessment for {target}")

        # Analyze target first
        analysis_result = redvector_client.safe_post("api/intelligence/analyze-target", {"target": target})

        if not analysis_result.get("success"):
            return analysis_result

        profile = analysis_result.get("target_profile", {})
        target_type = profile.get("target_type", "unknown")

        # Select tools based on focus areas and target type
        if focus_areas == "all":
            objective = "comprehensive"
        elif "web" in focus_areas and target_type == "web_application":
            objective = "comprehensive"
        elif "network" in focus_areas and target_type == "network_host":
            objective = "comprehensive"
        else:
            objective = "quick"

        # Execute vulnerability assessment
        scan_result = redvector_client.safe_post("api/intelligence/smart-scan", {
            "target": target,
            "objective": objective,
            "max_tools": 6
        })

        logger.info(f"✅ AI vulnerability assessment completed for {target}")

        return {
            "success": True,
            "target": target,
            "focus_areas": focus_areas,
            "target_analysis": profile,
            "vulnerability_scan": scan_result.get("scan_results", {}),
            "risk_assessment": {
                "risk_level": profile.get("risk_level", "unknown"),
                "attack_surface_score": profile.get("attack_surface_score", 0),
                "confidence_score": profile.get("confidence_score", 0)
            },
            "timestamp": datetime.now().isoformat()
        }

    # ============================================================================
    # BUG BOUNTY HUNTING SPECIALIZED WORKFLOWS
    # ============================================================================

    @mcp.tool()
    def bugbounty_reconnaissance_workflow(domain: str, scope: str = "", out_of_scope: str = "",
                                        program_type: str = "web") -> Dict[str, Any]:
        """
        Create comprehensive reconnaissance workflow for bug bounty hunting.

        Args:
            domain: Target domain for bug bounty
            scope: Comma-separated list of in-scope domains/IPs
            out_of_scope: Comma-separated list of out-of-scope domains/IPs
            program_type: Type of program (web, api, mobile, iot)

        Returns:
            Comprehensive reconnaissance workflow with phases and tools
        """
        data = {
            "domain": domain,
            "scope": scope.split(",") if scope else [],
            "out_of_scope": out_of_scope.split(",") if out_of_scope else [],
            "program_type": program_type
        }

        logger.info(f"🎯 Creating reconnaissance workflow for {domain}")
        result = redvector_client.safe_post("api/bugbounty/reconnaissance-workflow", data)

        if result.get("success"):
            workflow = result.get("workflow", {})
            logger.info(f"✅ Reconnaissance workflow created - {workflow.get('tools_count', 0)} tools, ~{workflow.get('estimated_time', 0)}s")
        else:
            logger.error(f"❌ Failed to create reconnaissance workflow for {domain}")

        return result

    @mcp.tool()
    def bugbounty_vulnerability_hunting(domain: str, priority_vulns: str = "rce,sqli,xss,idor,ssrf",
                                       bounty_range: str = "unknown") -> Dict[str, Any]:
        """
        Create vulnerability hunting workflow prioritized by impact and bounty potential.

        Args:
            domain: Target domain for bug bounty
            priority_vulns: Comma-separated list of priority vulnerability types
            bounty_range: Expected bounty range (low, medium, high, critical)

        Returns:
            Vulnerability hunting workflow prioritized by impact
        """
        data = {
            "domain": domain,
            "priority_vulns": priority_vulns.split(",") if priority_vulns else [],
            "bounty_range": bounty_range
        }

        logger.info(f"🎯 Creating vulnerability hunting workflow for {domain}")
        result = redvector_client.safe_post("api/bugbounty/vulnerability-hunting-workflow", data)

        if result.get("success"):
            workflow = result.get("workflow", {})
            logger.info(f"✅ Vulnerability hunting workflow created - Priority score: {workflow.get('priority_score', 0)}")
        else:
            logger.error(f"❌ Failed to create vulnerability hunting workflow for {domain}")

        return result

    @mcp.tool()
    def bugbounty_business_logic_testing(domain: str, program_type: str = "web") -> Dict[str, Any]:
        """
        Create business logic testing workflow for advanced bug bounty hunting.

        Args:
            domain: Target domain for bug bounty
            program_type: Type of program (web, api, mobile)

        Returns:
            Business logic testing workflow with manual and automated tests
        """
        data = {
            "domain": domain,
            "program_type": program_type
        }

        logger.info(f"🎯 Creating business logic testing workflow for {domain}")
        result = redvector_client.safe_post("api/bugbounty/business-logic-workflow", data)

        if result.get("success"):
            workflow = result.get("workflow", {})
            test_count = sum(len(category.get("tests", [])) for category in workflow.get("business_logic_tests", []))
            logger.info(f"✅ Business logic testing workflow created - {test_count} tests")
        else:
            logger.error(f"❌ Failed to create business logic testing workflow for {domain}")

        return result

    @mcp.tool()
    def bugbounty_osint_gathering(domain: str) -> Dict[str, Any]:
        """
        Create OSINT (Open Source Intelligence) gathering workflow for bug bounty reconnaissance.

        Args:
            domain: Target domain for OSINT gathering

        Returns:
            OSINT gathering workflow with multiple intelligence phases
        """
        data = {"domain": domain}

        logger.info(f"🎯 Creating OSINT gathering workflow for {domain}")
        result = redvector_client.safe_post("api/bugbounty/osint-workflow", data)

        if result.get("success"):
            workflow = result.get("workflow", {})
            phases = len(workflow.get("osint_phases", []))
            logger.info(f"✅ OSINT workflow created - {phases} intelligence phases")
        else:
            logger.error(f"❌ Failed to create OSINT workflow for {domain}")

        return result

    @mcp.tool()
    def bugbounty_file_upload_testing(target_url: str) -> Dict[str, Any]:
        """
        Create file upload vulnerability testing workflow with bypass techniques.

        Args:
            target_url: Target URL with file upload functionality

        Returns:
            File upload testing workflow with malicious files and bypass techniques
        """
        data = {"target_url": target_url}

        logger.info(f"🎯 Creating file upload testing workflow for {target_url}")
        result = redvector_client.safe_post("api/bugbounty/file-upload-testing", data)

        if result.get("success"):
            workflow = result.get("workflow", {})
            phases = len(workflow.get("test_phases", []))
            logger.info(f"✅ File upload testing workflow created - {phases} test phases")
        else:
            logger.error(f"❌ Failed to create file upload testing workflow for {target_url}")

        return result

    @mcp.tool()
    def bugbounty_comprehensive_assessment(domain: str, scope: str = "",
                                         priority_vulns: str = "rce,sqli,xss,idor,ssrf",
                                         include_osint: bool = True,
                                         include_business_logic: bool = True) -> Dict[str, Any]:
        """
        Create comprehensive bug bounty assessment combining all specialized workflows.

        Args:
            domain: Target domain for bug bounty
            scope: Comma-separated list of in-scope domains/IPs
            priority_vulns: Comma-separated list of priority vulnerability types
            include_osint: Include OSINT gathering workflow
            include_business_logic: Include business logic testing workflow

        Returns:
            Comprehensive bug bounty assessment with all workflows and summary
        """
        data = {
            "domain": domain,
            "scope": scope.split(",") if scope else [],
            "priority_vulns": priority_vulns.split(",") if priority_vulns else [],
            "include_osint": include_osint,
            "include_business_logic": include_business_logic
        }

        logger.info(f"🎯 Creating comprehensive bug bounty assessment for {domain}")
        result = redvector_client.safe_post("api/bugbounty/comprehensive-assessment", data)

        if result.get("success"):
            assessment = result.get("assessment", {})
            summary = assessment.get("summary", {})
            logger.info(f"✅ Comprehensive assessment created - {summary.get('workflow_count', 0)} workflows, ~{summary.get('total_estimated_time', 0)}s")
        else:
            logger.error(f"❌ Failed to create comprehensive assessment for {domain}")

        return result

    @mcp.tool()
    def bugbounty_authentication_bypass_testing(target_url: str, auth_type: str = "form") -> Dict[str, Any]:
        """
        Create authentication bypass testing workflow for bug bounty hunting.

        Args:
            target_url: Target URL with authentication
            auth_type: Type of authentication (form, jwt, oauth, saml)

        Returns:
            Authentication bypass testing strategies and techniques
        """
        data = {"target_url": target_url, "auth_type": auth_type}
        logger.info(f"🎯 Starting authentication bypass testing for {target_url}")
        result = redvector_client.safe_post("api/bugbounty/authentication-bypass-testing", data)
        if result.get("success"):
            logger.info(f"✅ Authentication bypass testing completed for {target_url}")
        else:
            logger.error(f"❌ Authentication bypass testing failed for {target_url}")
        return result

    # ============================================================================
    # ENHANCED HTTP TESTING FRAMEWORK & BROWSER AGENT (BURP SUITE ALTERNATIVE)
    # ============================================================================

    @mcp.tool()
    def http_framework_test(url: str, method: str = "GET", data: Optional[dict] = None,
                           headers: Optional[dict] = None, cookies: Optional[dict] = None, action: str = "request") -> Dict[str, Any]:
        """
        Enhanced HTTP testing framework (Burp Suite alternative) for comprehensive web security testing.

        Args:
            url: Target URL to test
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            data: Request data/parameters
            headers: Custom headers
            cookies: Custom cookies
            action: Action to perform (request, spider, proxy_history, set_rules, set_scope, repeater, intruder)

        Returns:
            HTTP testing results with vulnerability analysis
        """
        data_payload = {
            "url": url,
            "method": method,
            "data": data,
            "headers": headers,
            "cookies": cookies,
            "action": action
        }

        logger.info(f"{RedVectorColors.FIRE_RED}🔥 Starting HTTP Framework {action}: {url}{RedVectorColors.RESET}")
        result = redvector_client.safe_post("api/tools/http-framework", data_payload)

        if result.get("success"):
            logger.info(f"{RedVectorColors.SUCCESS}✅ HTTP Framework {action} completed for {url}{RedVectorColors.RESET}")

            # Enhanced logging for vulnerabilities found
            if result.get("result", {}).get("vulnerabilities"):
                vuln_count = len(result["result"]["vulnerabilities"])
                logger.info(f"{RedVectorColors.HIGHLIGHT_RED} Found {vuln_count} potential vulnerabilities {RedVectorColors.RESET}")
        else:
            logger.error(f"{RedVectorColors.ERROR}❌ HTTP Framework {action} failed for {url}{RedVectorColors.RESET}")

        return result

    @mcp.tool()
    def browser_agent_inspect(url: str, headless: bool = True, wait_time: int = 5,
                             action: str = "navigate", proxy_port: int = None, active_tests: bool = False) -> Dict[str, Any]:
        """
        AI-powered browser agent for comprehensive web application inspection and security analysis.

        Args:
            url: Target URL to inspect
            headless: Run browser in headless mode
            wait_time: Time to wait after page load
            action: Action to perform (navigate, screenshot, close, status)
            proxy_port: Optional proxy port for request interception
            active_tests: Run lightweight active reflected XSS tests (safe GET-only)

        Returns:
            Browser inspection results with security analysis
        """
        data_payload = {
            "url": url,
            "headless": headless,
            "wait_time": wait_time,
            "action": action,
            "proxy_port": proxy_port,
            "active_tests": active_tests
        }

        logger.info(f"{RedVectorColors.CRIMSON}🌐 Starting Browser Agent {action}: {url}{RedVectorColors.RESET}")
        result = redvector_client.safe_post("api/tools/browser-agent", data_payload)

        if result.get("success"):
            logger.info(f"{RedVectorColors.SUCCESS}✅ Browser Agent {action} completed for {url}{RedVectorColors.RESET}")

            # Enhanced logging for security analysis
            if action == "navigate" and result.get("result", {}).get("security_analysis"):
                security_analysis = result["result"]["security_analysis"]
                issues_count = security_analysis.get("total_issues", 0)
                security_score = security_analysis.get("security_score", 0)

                if issues_count > 0:
                    logger.warning(f"{RedVectorColors.HIGHLIGHT_YELLOW} Security Issues: {issues_count} | Score: {security_score}/100 {RedVectorColors.RESET}")
                else:
                    logger.info(f"{RedVectorColors.HIGHLIGHT_GREEN} No security issues found | Score: {security_score}/100 {RedVectorColors.RESET}")
        else:
            logger.error(f"{RedVectorColors.ERROR}❌ Browser Agent {action} failed for {url}{RedVectorColors.RESET}")

        return result

    # ---------------- Additional HTTP Framework Tools (sync with server) ----------------
    @mcp.tool()
    def http_set_rules(rules: list) -> Dict[str, Any]:
        """Set match/replace rules used to rewrite parts of URL/query/headers/body before sending.
        Rule format: {'where':'url|query|headers|body','pattern':'regex','replacement':'string'}"""
        payload = {"action": "set_rules", "rules": rules}
        return redvector_client.safe_post("api/tools/http-framework", payload)

    @mcp.tool()
    def http_set_scope(host: str, include_subdomains: bool = True) -> Dict[str, Any]:
        """Define in-scope host (and optionally subdomains) so out-of-scope requests are skipped."""
        payload = {"action": "set_scope", "host": host, "include_subdomains": include_subdomains}
        return redvector_client.safe_post("api/tools/http-framework", payload)

    @mcp.tool()
    def http_repeater(request_spec: dict) -> Dict[str, Any]:
        """Send a crafted request (Burp Repeater equivalent). request_spec keys: url, method, headers, cookies, data."""
        payload = {"action": "repeater", "request": request_spec}
        return redvector_client.safe_post("api/tools/http-framework", payload)

    @mcp.tool()
    def http_intruder(url: str, method: str = "GET", location: str = "query", params: list = None,
                      payloads: list = None, base_data: dict = None, max_requests: int = 100) -> Dict[str, Any]:
        """Simple Intruder (sniper) fuzzing. Iterates payloads over each param individually.
        location: query|body|headers|cookie."""
        payload = {
            "action": "intruder",
            "url": url,
            "method": method,
            "location": location,
            "params": params or [],
            "payloads": payloads or [],
            "base_data": base_data or {},
            "max_requests": max_requests
        }
        return redvector_client.safe_post("api/tools/http-framework", payload)

    @mcp.tool()
    def burpsuite_alternative_scan(target: str, scan_type: str = "comprehensive",
                                  headless: bool = True, max_depth: int = 3,
                                  max_pages: int = 50) -> Dict[str, Any]:
        """
        Comprehensive Burp Suite alternative combining HTTP framework and browser agent for complete web security testing.

        Args:
            target: Target URL or domain to scan
            scan_type: Type of scan (comprehensive, spider, passive, active)
            headless: Run browser in headless mode
            max_depth: Maximum crawling depth
            max_pages: Maximum pages to analyze

        Returns:
            Comprehensive security assessment results
        """
        data_payload = {
            "target": target,
            "scan_type": scan_type,
            "headless": headless,
            "max_depth": max_depth,
            "max_pages": max_pages
        }

        logger.info(f"{RedVectorColors.BLOOD_RED}🔥 Starting Burp Suite Alternative {scan_type} scan: {target}{RedVectorColors.RESET}")
        result = redvector_client.safe_post("api/tools/burpsuite-alternative", data_payload)

        if result.get("success"):
            logger.info(f"{RedVectorColors.SUCCESS}✅ Burp Suite Alternative scan completed for {target}{RedVectorColors.RESET}")

            # Enhanced logging for comprehensive results
            if result.get("result", {}).get("summary"):
                summary = result["result"]["summary"]
                total_vulns = summary.get("total_vulnerabilities", 0)
                pages_analyzed = summary.get("pages_analyzed", 0)
                security_score = summary.get("security_score", 0)

                logger.info(f"{RedVectorColors.HIGHLIGHT_BLUE} SCAN SUMMARY {RedVectorColors.RESET}")
                logger.info(f"  📊 Pages Analyzed: {pages_analyzed}")
                logger.info(f"  🚨 Vulnerabilities: {total_vulns}")
                logger.info(f"  🛡️  Security Score: {security_score}/100")

                # Log vulnerability breakdown
                vuln_breakdown = summary.get("vulnerability_breakdown", {})
                for severity, count in vuln_breakdown.items():
                    if count > 0:
                        color = {
                            'critical': RedVectorColors.CRITICAL,
                            'high': RedVectorColors.FIRE_RED,
                            'medium': RedVectorColors.CYBER_ORANGE,
                            'low': RedVectorColors.YELLOW,
                            'info': RedVectorColors.INFO
                        }.get(severity.lower(), RedVectorColors.WHITE)

                        logger.info(f"  {color}{severity.upper()}: {count}{RedVectorColors.RESET}")
        else:
            logger.error(f"{RedVectorColors.ERROR}❌ Burp Suite Alternative scan failed for {target}{RedVectorColors.RESET}")

        return result

    @mcp.tool()
    def error_handling_statistics() -> Dict[str, Any]:
        """
        Get intelligent error handling system statistics and recent error patterns.

        Returns:
            Error handling statistics and patterns
        """
        logger.info(f"{RedVectorColors.ELECTRIC_PURPLE}📊 Retrieving error handling statistics{RedVectorColors.RESET}")
        result = redvector_client.safe_get("api/error-handling/statistics")

        if result.get("success"):
            stats = result.get("statistics", {})
            total_errors = stats.get("total_errors", 0)
            recent_errors = stats.get("recent_errors_count", 0)

            logger.info(f"{RedVectorColors.SUCCESS}✅ Error statistics retrieved{RedVectorColors.RESET}")
            logger.info(f"  📈 Total Errors: {total_errors}")
            logger.info(f"  🕒 Recent Errors: {recent_errors}")

            # Log error breakdown by type
            error_counts = stats.get("error_counts_by_type", {})
            if error_counts:
                logger.info(f"{RedVectorColors.HIGHLIGHT_BLUE} ERROR BREAKDOWN {RedVectorColors.RESET}")
                for error_type, count in error_counts.items():
                    logger.info(f"  {RedVectorColors.FIRE_RED}{error_type}: {count}{RedVectorColors.RESET}")
        else:
            logger.error(f"{RedVectorColors.ERROR}❌ Failed to retrieve error statistics{RedVectorColors.RESET}")

        return result

    @mcp.tool()
    def test_error_recovery(tool_name: str, error_type: str = "timeout",
                           target: str = "example.com") -> Dict[str, Any]:
        """
        Test the intelligent error recovery system with simulated failures.

        Args:
            tool_name: Name of tool to simulate error for
            error_type: Type of error to simulate (timeout, permission_denied, network_unreachable, etc.)
            target: Target for the simulated test

        Returns:
            Recovery strategy and system response
        """
        data_payload = {
            "tool_name": tool_name,
            "error_type": error_type,
            "target": target
        }

        logger.info(f"{RedVectorColors.RUBY}🧪 Testing error recovery for {tool_name} with {error_type}{RedVectorColors.RESET}")
        result = redvector_client.safe_post("api/error-handling/test-recovery", data_payload)

        if result.get("success"):
            recovery_strategy = result.get("recovery_strategy", {})
            action = recovery_strategy.get("action", "unknown")
            success_prob = recovery_strategy.get("success_probability", 0)

            logger.info(f"{RedVectorColors.SUCCESS}✅ Error recovery test completed{RedVectorColors.RESET}")
            logger.info(f"  🔧 Recovery Action: {action}")
            logger.info(f"  📊 Success Probability: {success_prob:.2%}")

            # Log alternative tools if available
            alternatives = result.get("alternative_tools", [])
            if alternatives:
                logger.info(f"  🔄 Alternative Tools: {', '.join(alternatives)}")
        else:
            logger.error(f"{RedVectorColors.ERROR}❌ Error recovery test failed{RedVectorColors.RESET}")

        return result

    # ============================================================================
    # CTF CHALLENGE TOOLS
    # ============================================================================

    @mcp.tool()
    def ctf_create_challenge_workflow(
        name: str = "",
        category: str = "misc",
        difficulty: str = "unknown",
        points: int = 100,
        description: str = "",
        target: str = ""
    ) -> Dict[str, Any]:
        """
        Create a structured CTF challenge-solving workflow with AI-guided approach.

        Args:
            name: Challenge name
            category: Challenge category (web, pwn, crypto, forensics, misc, rev, stego)
            difficulty: Difficulty level (easy, medium, hard, unknown)
            points: Challenge point value
            description: Challenge description text
            target: Target URL or file path

        Returns:
            Structured workflow with suggested tools, approach, and methodology
        """
        data = {"name": name, "category": category, "difficulty": difficulty, "points": points, "description": description, "target": target}
        logger.info(f"🏁 Creating CTF workflow for: {name} [{category}]")
        result = redvector_client.safe_post("api/ctf/create-challenge-workflow", data)
        if result.get("success"):
            logger.info(f"✅ CTF workflow created for {name}")
        else:
            logger.error(f"❌ CTF workflow creation failed")
        return result

    @mcp.tool()
    def ctf_auto_solve(
        name: str = "",
        category: str = "misc",
        difficulty: str = "unknown",
        points: int = 100,
        description: str = "",
        target: str = ""
    ) -> Dict[str, Any]:
        """
        Attempt to auto-solve a CTF challenge using AI-driven tool selection and execution.

        Args:
            name: Challenge name
            category: Challenge category (web, pwn, crypto, forensics, misc, rev, stego)
            difficulty: Difficulty level
            points: Challenge point value
            description: Challenge description
            target: Target URL or file path

        Returns:
            Solve attempt results including flag if found
        """
        data = {"name": name, "category": category, "difficulty": difficulty, "points": points, "description": description, "target": target}
        logger.info(f"🏁 Auto-solving CTF challenge: {name} [{category}]")
        result = redvector_client.safe_post("api/ctf/auto-solve-challenge", data)
        if result.get("success"):
            logger.info(f"✅ CTF auto-solve completed for {name}")
        else:
            logger.error(f"❌ CTF auto-solve failed for {name}")
        return result

    @mcp.tool()
    def ctf_team_strategy(
        challenges: str = "[]",
        team_skills: str = "{}"
    ) -> Dict[str, Any]:
        """
        Generate an optimal CTF team strategy based on available challenges and team skills.

        Args:
            challenges: JSON string of challenge list. Each: {"name": str, "category": str, "difficulty": str, "points": int}
            team_skills: JSON string of team skills map. Example: {"alice": ["web","crypto"], "bob": ["pwn","rev"]}

        Returns:
            Optimal challenge assignment and time allocation strategy
        """
        import json as _json
        try:
            challenges_list = _json.loads(challenges) if isinstance(challenges, str) else challenges
            skills_map = _json.loads(team_skills) if isinstance(team_skills, str) else team_skills
        except (ValueError, _json.JSONDecodeError):
            challenges_list = []
            skills_map = {}
        data = {"challenges": challenges_list, "team_skills": skills_map}
        logger.info(f"🏁 Generating CTF team strategy")
        result = redvector_client.safe_post("api/ctf/team-strategy", data)
        if result.get("success"):
            logger.info(f"✅ CTF team strategy generated")
        else:
            logger.error(f"❌ CTF team strategy generation failed")
        return result

    @mcp.tool()
    def ctf_suggest_tools(
        description: str = "",
        category: str = "misc"
    ) -> Dict[str, Any]:
        """
        Suggest optimal tools for solving a CTF challenge.

        Args:
            description: Challenge description text
            category: Challenge category (web, pwn, crypto, forensics, misc, rev, stego)

        Returns:
            Recommended tools and techniques for the challenge
        """
        data = {"description": description, "category": category}
        logger.info(f"🔧 Suggesting CTF tools for [{category}] challenge")
        result = redvector_client.safe_post("api/ctf/suggest-tools", data)
        if result.get("success"):
            logger.info(f"✅ CTF tool suggestions ready")
        else:
            logger.error(f"❌ CTF tool suggestion failed")
        return result

    @mcp.tool()
    def ctf_crypto_solver(
        cipher_text: str = "",
        cipher_type: str = "unknown",
        key_hint: str = "",
        known_plaintext: str = "",
        additional_info: str = ""
    ) -> Dict[str, Any]:
        """
        Solve CTF cryptography challenges with automated cipher detection and decryption.

        Args:
            cipher_text: The encrypted/encoded text to analyze
            cipher_type: Known cipher type (unknown, caesar, vigenere, base64, rot13, xor, rsa, aes, etc.)
            key_hint: Any hint about the encryption key
            known_plaintext: Known plaintext for known-plaintext attacks
            additional_info: Additional challenge information

        Returns:
            Decryption attempts and analysis results
        """
        data = {"cipher_text": cipher_text, "cipher_type": cipher_type, "key_hint": key_hint, "known_plaintext": known_plaintext, "additional_info": additional_info}
        logger.info(f"🔐 Solving CTF crypto challenge (type: {cipher_type})")
        result = redvector_client.safe_post("api/ctf/cryptography-solver", data)
        if result.get("success"):
            logger.info(f"✅ Crypto solver completed")
        else:
            logger.error(f"❌ Crypto solver failed")
        return result

    @mcp.tool()
    def ctf_forensics_analyzer(
        file_path: str = "",
        analysis_type: str = "comprehensive",
        extract_hidden: bool = True,
        check_steganography: bool = True
    ) -> Dict[str, Any]:
        """
        Analyze files for CTF forensics challenges (hidden data, steganography, metadata).

        Args:
            file_path: Path to the file to analyze
            analysis_type: Type of analysis (comprehensive, metadata, steganography, strings, hex)
            extract_hidden: Attempt to extract hidden data
            check_steganography: Check for steganographic content

        Returns:
            Forensic analysis results including hidden data and metadata
        """
        data = {"file_path": file_path, "analysis_type": analysis_type, "extract_hidden": extract_hidden, "check_steganography": check_steganography}
        logger.info(f"🔍 CTF forensics analysis: {file_path}")
        result = redvector_client.safe_post("api/ctf/forensics-analyzer", data)
        if result.get("success"):
            logger.info(f"✅ Forensics analysis completed")
        else:
            logger.error(f"❌ Forensics analysis failed")
        return result

    @mcp.tool()
    def ctf_binary_analyzer(
        binary_path: str = "",
        analysis_depth: str = "comprehensive",
        check_protections: bool = True,
        find_gadgets: bool = True
    ) -> Dict[str, Any]:
        """
        Analyze binaries for CTF pwn/reverse engineering challenges.

        Args:
            binary_path: Path to the binary to analyze
            analysis_depth: Depth of analysis (quick, comprehensive, deep)
            check_protections: Check binary security protections (NX, PIE, canary, RELRO)
            find_gadgets: Search for ROP gadgets

        Returns:
            Binary analysis results including protections, gadgets, and vulnerability hints
        """
        data = {"binary_path": binary_path, "analysis_depth": analysis_depth, "check_protections": check_protections, "find_gadgets": find_gadgets}
        logger.info(f"🔍 CTF binary analysis: {binary_path}")
        result = redvector_client.safe_post("api/ctf/binary-analyzer", data)
        if result.get("success"):
            logger.info(f"✅ Binary analysis completed")
        else:
            logger.error(f"❌ Binary analysis failed")
        return result

    # ============================================================================
    # PHASE 6: PRIVILEGE ESCALATION TOOLS
    # ============================================================================

    @mcp.tool()
    def linpeas_scan(
        check_type: str = "all",
        output_file: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute LinPEAS for Linux privilege escalation enumeration.

        Args:
            check_type: Type of check (all, system_information, container, procs_crons_timers_srvcs_sockets, network_information, users_information, software_information, interesting_files)
            output_file: Save output to file
            additional_args: Additional arguments

        Returns:
            LinPEAS enumeration results with potential privilege escalation vectors
        """
        data = {
            "check_type": check_type,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting LinPEAS privilege escalation enumeration")
        result = redvector_client.safe_post("api/tools/linpeas", data)
        if result.get("success"):
            logger.info(f"✅ LinPEAS enumeration completed")
        else:
            logger.error(f"❌ LinPEAS enumeration failed")
        return result

    @mcp.tool()
    def winpeas_scan(
        check_type: str = "all",
        output_file: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute WinPEAS for Windows privilege escalation enumeration.

        Args:
            check_type: Type of check (all, systeminfo, userinfo, processinfo, servicesinfo, applicationsinfo, networkinfo, windowscreds, browserinfo, filesinfo)
            output_file: Save output to file
            additional_args: Additional arguments

        Returns:
            WinPEAS enumeration results with potential privilege escalation vectors
        """
        data = {
            "check_type": check_type,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting WinPEAS privilege escalation enumeration")
        result = redvector_client.safe_post("api/tools/winpeas", data)
        if result.get("success"):
            logger.info(f"✅ WinPEAS enumeration completed")
        else:
            logger.error(f"❌ WinPEAS enumeration failed")
        return result

    @mcp.tool()
    def linux_exploit_suggester_scan(
        kernel_version: str = "",
        uname_output: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute linux-exploit-suggester to identify applicable kernel exploits.

        Args:
            kernel_version: Kernel version string (e.g., 4.15.0-142)
            uname_output: Full uname -a output
            additional_args: Additional arguments

        Returns:
            List of potentially applicable kernel exploits
        """
        data = {
            "kernel_version": kernel_version,
            "uname_output": uname_output,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Linux Exploit Suggester")
        result = redvector_client.safe_post("api/tools/linux-exploit-suggester", data)
        if result.get("success"):
            logger.info(f"✅ Linux Exploit Suggester completed")
        else:
            logger.error(f"❌ Linux Exploit Suggester failed")
        return result

    @mcp.tool()
    def windows_exploit_suggester_scan(
        systeminfo_file: str = "",
        database: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute windows-exploit-suggester for Windows patch gap analysis.

        Args:
            systeminfo_file: Path to systeminfo output file
            database: Path to vulnerability database file
            additional_args: Additional arguments

        Returns:
            List of missing patches and applicable exploits
        """
        data = {
            "systeminfo_file": systeminfo_file,
            "database": database,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Windows Exploit Suggester")
        result = redvector_client.safe_post("api/tools/windows-exploit-suggester", data)
        if result.get("success"):
            logger.info(f"✅ Windows Exploit Suggester completed")
        else:
            logger.error(f"❌ Windows Exploit Suggester failed")
        return result

    @mcp.tool()
    def gtfobins_lookup(
        binary: str = "",
        function_type: str = "",
        list_all: bool = False
    ) -> Dict[str, Any]:
        """
        Look up GTFOBins for SUID/capability/sudo abuse vectors on Linux.

        Args:
            binary: Binary name to look up (e.g., python, vim, find)
            function_type: Filter by function type (shell, suid, sudo, file_read)
            list_all: List all available binaries and categories

        Returns:
            Privilege escalation techniques for the specified binary
        """
        data = {
            "binary": binary,
            "function_type": function_type,
            "list_all": list_all
        }
        logger.info(f"🔍 Looking up GTFOBins for: {binary or 'all binaries'}")
        result = redvector_client.safe_post("api/tools/gtfobins-lookup", data)
        if result.get("success"):
            logger.info(f"✅ GTFOBins lookup completed")
        else:
            logger.error(f"❌ GTFOBins lookup failed")
        return result

    @mcp.tool()
    def lolbas_lookup(
        binary: str = "",
        category: str = "",
        list_all: bool = False
    ) -> Dict[str, Any]:
        """
        Look up LOLBAS (Living Off The Land Binaries and Scripts) for Windows.

        Args:
            binary: Binary name to look up (e.g., certutil, mshta, rundll32)
            category: Filter by category (execute, download, persistence, uac_bypass)
            list_all: List all available binaries and categories

        Returns:
            LOL techniques for the specified Windows binary
        """
        data = {
            "binary": binary,
            "category": category,
            "list_all": list_all
        }
        logger.info(f"🔍 Looking up LOLBAS for: {binary or 'all binaries'}")
        result = redvector_client.safe_post("api/tools/lolbas-lookup", data)
        if result.get("success"):
            logger.info(f"✅ LOLBAS lookup completed")
        else:
            logger.error(f"❌ LOLBAS lookup failed")
        return result

    @mcp.tool()
    def pspy_monitor(
        duration: int = 60,
        output_file: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute pspy for unprivileged Linux process and cron job monitoring.

        Args:
            duration: Monitoring duration in seconds (default: 60)
            output_file: Save output to file
            additional_args: Additional arguments

        Returns:
            Monitored processes and cron jobs
        """
        data = {
            "duration": duration,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting pspy process monitoring for {duration}s")
        result = redvector_client.safe_post("api/tools/pspy", data)
        if result.get("success"):
            logger.info(f"✅ pspy monitoring completed")
        else:
            logger.error(f"❌ pspy monitoring failed")
        return result

    @mcp.tool()
    def sudo_misconfiguration_check(
        check_type: str = "all",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Check for sudo misconfigurations and exploitable sudo rules.

        Args:
            check_type: Type of check (list, version, env, all)
            additional_args: Additional arguments

        Returns:
            Sudo permissions, version info, and potential misconfigurations
        """
        data = {
            "check_type": check_type,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Checking sudo misconfigurations")
        result = redvector_client.safe_post("api/tools/sudo-check", data)
        if result.get("success"):
            logger.info(f"✅ Sudo check completed")
        else:
            logger.error(f"❌ Sudo check failed")
        return result

    @mcp.tool()
    def suid_sgid_finder(
        search_type: str = "all",
        path: str = "/"
    ) -> Dict[str, Any]:
        """
        Find SUID/SGID binaries and file capabilities for privilege escalation.

        Args:
            search_type: Type of search (suid, sgid, capabilities, writable, all)
            path: Starting path for the search (default: /)

        Returns:
            Lists of SUID/SGID binaries, capabilities, and writable files
        """
        data = {
            "search_type": search_type,
            "path": path
        }
        logger.info(f"🔍 Searching for SUID/SGID/capabilities in {path}")
        result = redvector_client.safe_post("api/tools/suid-finder", data)
        if result.get("success"):
            logger.info(f"✅ SUID/SGID finder completed")
        else:
            logger.error(f"❌ SUID/SGID finder failed")
        return result

    # ============================================================================
    # PHASE 7: LATERAL MOVEMENT & PERSISTENCE TOOLS
    # ============================================================================

    @mcp.tool()
    def impacket_psexec(
        target: str,
        username: str = "",
        password: str = "",
        hashes: str = "",
        domain: str = "",
        command: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Impacket's psexec.py for remote command execution via SMB.

        Args:
            target: Target IP or hostname
            username: Username for authentication
            password: Password for authentication
            hashes: NTLM hash (LM:NT format) for pass-the-hash
            domain: Active Directory domain
            command: Command to execute on remote host
            additional_args: Additional arguments

        Returns:
            Remote command execution results
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "hashes": hashes,
            "domain": domain,
            "command": command,
            "additional_args": additional_args
        }
        logger.info(f"🔑 Starting Impacket psexec against {target}")
        result = redvector_client.safe_post("api/tools/impacket-psexec", data)
        if result.get("success"):
            logger.info(f"✅ Impacket psexec completed for {target}")
        else:
            logger.error(f"❌ Impacket psexec failed for {target}")
        return result

    @mcp.tool()
    def impacket_wmiexec(
        target: str,
        username: str = "",
        password: str = "",
        hashes: str = "",
        domain: str = "",
        command: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Impacket's wmiexec.py for WMI-based remote command execution.

        Args:
            target: Target IP or hostname
            username: Username for authentication
            password: Password for authentication
            hashes: NTLM hash (LM:NT format) for pass-the-hash
            domain: Active Directory domain
            command: Command to execute on remote host
            additional_args: Additional arguments

        Returns:
            Remote command execution results via WMI
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "hashes": hashes,
            "domain": domain,
            "command": command,
            "additional_args": additional_args
        }
        logger.info(f"🔑 Starting Impacket wmiexec against {target}")
        result = redvector_client.safe_post("api/tools/impacket-wmiexec", data)
        if result.get("success"):
            logger.info(f"✅ Impacket wmiexec completed for {target}")
        else:
            logger.error(f"❌ Impacket wmiexec failed for {target}")
        return result

    @mcp.tool()
    def impacket_smbexec(
        target: str,
        username: str = "",
        password: str = "",
        hashes: str = "",
        domain: str = "",
        command: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Impacket's smbexec.py for SMB-based remote command execution.

        Args:
            target: Target IP or hostname
            username: Username for authentication
            password: Password for authentication
            hashes: NTLM hash (LM:NT format) for pass-the-hash
            domain: Active Directory domain
            command: Command to execute on remote host
            additional_args: Additional arguments

        Returns:
            Remote command execution results via SMB
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "hashes": hashes,
            "domain": domain,
            "command": command,
            "additional_args": additional_args
        }
        logger.info(f"🔑 Starting Impacket smbexec against {target}")
        result = redvector_client.safe_post("api/tools/impacket-smbexec", data)
        if result.get("success"):
            logger.info(f"✅ Impacket smbexec completed for {target}")
        else:
            logger.error(f"❌ Impacket smbexec failed for {target}")
        return result

    @mcp.tool()
    def impacket_secretsdump(
        target: str,
        username: str = "",
        password: str = "",
        hashes: str = "",
        domain: str = "",
        just_dc: bool = False,
        just_dc_ntlm: bool = False,
        output_file: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Impacket's secretsdump.py for credential harvesting (SAM, NTDS, LSA).

        Args:
            target: Target IP or hostname (Domain Controller for NTDS)
            username: Username for authentication
            password: Password for authentication
            hashes: NTLM hash (LM:NT format) for pass-the-hash
            domain: Active Directory domain
            just_dc: Extract only NTDS.DIT data (DRSUAPI)
            just_dc_ntlm: Extract only NTDS.DIT NTLM hashes
            output_file: Base output filename for extracted secrets
            additional_args: Additional arguments

        Returns:
            Extracted credentials (SAM hashes, NTDS.DIT entries, LSA secrets, cached creds)
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "hashes": hashes,
            "domain": domain,
            "just_dc": just_dc,
            "just_dc_ntlm": just_dc_ntlm,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🔑 Starting Impacket secretsdump against {target}")
        result = redvector_client.safe_post("api/tools/impacket-secretsdump", data)
        if result.get("success"):
            logger.info(f"✅ Impacket secretsdump completed for {target}")
        else:
            logger.error(f"❌ Impacket secretsdump failed for {target}")
        return result

    @mcp.tool()
    def evil_winrm_connect(
        target: str,
        username: str = "",
        password: str = "",
        hash_val: str = "",
        ssl: bool = False,
        scripts_path: str = "",
        executables_path: str = "",
        command: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute evil-winrm for WinRM-based remote shell access.

        Args:
            target: Target IP or hostname
            username: Username for authentication
            password: Password for authentication
            hash_val: NTLM hash for pass-the-hash
            ssl: Use SSL connection
            scripts_path: Path to PowerShell scripts directory
            executables_path: Path to executables directory
            command: Command to execute remotely
            additional_args: Additional arguments

        Returns:
            Remote shell execution results
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "hash": hash_val,
            "ssl": ssl,
            "scripts_path": scripts_path,
            "executables_path": executables_path,
            "command": command,
            "additional_args": additional_args
        }
        logger.info(f"🔑 Starting evil-winrm against {target}")
        result = redvector_client.safe_post("api/tools/evil-winrm", data)
        if result.get("success"):
            logger.info(f"✅ evil-winrm session completed for {target}")
        else:
            logger.error(f"❌ evil-winrm failed for {target}")
        return result

    @mcp.tool()
    def bloodhound_collection(
        domain: str,
        username: str = "",
        password: str = "",
        dc_ip: str = "",
        collection_method: str = "All",
        output_dir: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute BloodHound.py for Active Directory attack path mapping.

        Args:
            domain: Target Active Directory domain
            username: Username for authentication
            password: Password for authentication
            dc_ip: Domain Controller IP address
            collection_method: Collection method (All, DCOnly, Group, LocalAdmin, Session, Trusts, ACL, ObjectProps, Container, SPNTargets, PSRemote)
            output_dir: Output directory for collection data
            additional_args: Additional arguments

        Returns:
            BloodHound collection data (ZIP file with JSON data for import)
        """
        data = {
            "domain": domain,
            "username": username,
            "password": password,
            "dc_ip": dc_ip,
            "collection_method": collection_method,
            "output_dir": output_dir,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting BloodHound.py collection against {domain}")
        result = redvector_client.safe_post("api/tools/bloodhound-python", data)
        if result.get("success"):
            logger.info(f"✅ BloodHound.py collection completed for {domain}")
        else:
            logger.error(f"❌ BloodHound.py collection failed for {domain}")
        return result

    @mcp.tool()
    def kerbrute_attack(
        domain: str,
        action: str = "userenum",
        dc_ip: str = "",
        userlist: str = "",
        passwordlist: str = "",
        username: str = "",
        password: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Kerbrute for Kerberos pre-authentication attacks.

        Args:
            domain: Target Active Directory domain
            action: Attack type (userenum, passwordspray, bruteuser, bruteforce)
            dc_ip: Domain Controller IP address
            userlist: Path to username wordlist
            passwordlist: Path to password wordlist
            username: Single username for bruteuser mode
            password: Single password for passwordspray mode
            additional_args: Additional arguments

        Returns:
            Valid usernames or credentials found via Kerberos
        """
        data = {
            "domain": domain,
            "action": action,
            "dc_ip": dc_ip,
            "userlist": userlist,
            "passwordlist": passwordlist,
            "username": username,
            "password": password,
            "additional_args": additional_args
        }
        logger.info(f"🔑 Starting Kerbrute {action} against {domain}")
        result = redvector_client.safe_post("api/tools/kerbrute", data)
        if result.get("success"):
            logger.info(f"✅ Kerbrute {action} completed for {domain}")
        else:
            logger.error(f"❌ Kerbrute {action} failed for {domain}")
        return result

    @mcp.tool()
    def chisel_tunnel(
        mode: str = "client",
        server: str = "",
        port: str = "8080",
        remote: str = "",
        reverse: bool = False,
        socks5: bool = False,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Chisel for TCP/UDP tunneling and pivoting through compromised hosts.

        Args:
            mode: Chisel mode (server, client)
            server: Server address (for client mode)
            port: Listening port (default: 8080)
            remote: Remote tunnel specification (e.g., R:8080:localhost:80)
            reverse: Enable reverse tunneling (server mode)
            socks5: Enable SOCKS5 proxy
            additional_args: Additional arguments

        Returns:
            Tunnel establishment results
        """
        data = {
            "mode": mode,
            "server": server,
            "port": port,
            "remote": remote,
            "reverse": reverse,
            "socks5": socks5,
            "additional_args": additional_args
        }
        logger.info(f"🔗 Starting Chisel {mode} on port {port}")
        result = redvector_client.safe_post("api/tools/chisel", data)
        if result.get("success"):
            logger.info(f"✅ Chisel {mode} established")
        else:
            logger.error(f"❌ Chisel {mode} failed")
        return result

    @mcp.tool()
    def ligolo_tunnel(
        mode: str = "proxy",
        listen_addr: str = "0.0.0.0:11601",
        selfcert: bool = True,
        connect_to: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Ligolo-ng for tunneling through compromised hosts.

        Args:
            mode: Ligolo mode (proxy for attacker machine, agent for target)
            listen_addr: Listening address for proxy mode (default: 0.0.0.0:11601)
            selfcert: Use self-signed certificate
            connect_to: Proxy address to connect to (agent mode)
            additional_args: Additional arguments

        Returns:
            Tunnel establishment results
        """
        data = {
            "mode": mode,
            "listen_addr": listen_addr,
            "selfcert": selfcert,
            "connect_to": connect_to,
            "additional_args": additional_args
        }
        logger.info(f"🔗 Starting Ligolo-ng {mode}")
        result = redvector_client.safe_post("api/tools/ligolo-ng", data)
        if result.get("success"):
            logger.info(f"✅ Ligolo-ng {mode} established")
        else:
            logger.error(f"❌ Ligolo-ng {mode} failed")
        return result

    @mcp.tool()
    def proxychains_execute(
        command: str,
        config_file: str = "",
        quiet: bool = False,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute commands through ProxyChains for traffic proxying via compromised hosts.

        Args:
            command: Command to execute through the proxy chain
            config_file: Custom ProxyChains configuration file
            quiet: Suppress ProxyChains output
            additional_args: Additional arguments

        Returns:
            Proxied command execution results
        """
        data = {
            "command": command,
            "config_file": config_file,
            "quiet": quiet,
            "additional_args": additional_args
        }
        logger.info(f"🔗 Executing through ProxyChains: {command}")
        result = redvector_client.safe_post("api/tools/proxychains", data)
        if result.get("success"):
            logger.info(f"✅ ProxyChains execution completed")
        else:
            logger.error(f"❌ ProxyChains execution failed")
        return result

    @mcp.tool()
    def ssh_tunnel_setup(
        target: str,
        username: str = "",
        tunnel_type: str = "local",
        local_port: str = "",
        remote_host: str = "",
        remote_port: str = "",
        key_file: str = "",
        dynamic_port: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Set up SSH tunnels for port forwarding and pivoting.

        Args:
            target: Target SSH server
            username: SSH username
            tunnel_type: Tunnel type (local, remote, dynamic)
            local_port: Local port for the tunnel
            remote_host: Remote host to tunnel to
            remote_port: Remote port to tunnel to
            key_file: SSH private key file
            dynamic_port: Port for SOCKS proxy (dynamic tunnel)
            additional_args: Additional SSH arguments

        Returns:
            SSH tunnel setup results
        """
        data = {
            "target": target,
            "username": username,
            "tunnel_type": tunnel_type,
            "local_port": local_port,
            "remote_host": remote_host,
            "remote_port": remote_port,
            "key_file": key_file,
            "dynamic_port": dynamic_port,
            "additional_args": additional_args
        }
        logger.info(f"🔗 Setting up SSH {tunnel_type} tunnel to {target}")
        result = redvector_client.safe_post("api/tools/ssh-tunnel", data)
        if result.get("success"):
            logger.info(f"✅ SSH tunnel established to {target}")
        else:
            logger.error(f"❌ SSH tunnel setup failed for {target}")
        return result

    @mcp.tool()
    def mimikatz_execute(
        command: str = "sekurlsa::logonpasswords",
        module: str = "",
        output_file: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Mimikatz for Windows credential extraction from memory.

        Args:
            command: Mimikatz command (default: sekurlsa::logonpasswords)
            module: Mimikatz module (sekurlsa, lsadump, kerberos, crypto, vault, token, etc.)
            output_file: Save output to log file
            additional_args: Additional arguments

        Returns:
            Extracted credentials and security tokens
        """
        data = {
            "command": command,
            "module": module,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🔑 Starting Mimikatz: {command}")
        result = redvector_client.safe_post("api/tools/mimikatz", data)
        if result.get("success"):
            logger.info(f"✅ Mimikatz execution completed")
        else:
            logger.error(f"❌ Mimikatz execution failed")
        return result

    @mcp.tool()
    def persistence_install(
        technique: str = "",
        platform: str = "linux",
        payload: str = "",
        name: str = "system-update",
        schedule: str = "",
        action: str = "install",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Manage persistence mechanisms on compromised hosts.

        Args:
            technique: Persistence technique. Linux: crontab, systemd, bashrc, ssh_key, ld_preload. Windows: registry, scheduled_task, startup_folder, service, wmi. Leave empty to list available techniques.
            platform: Target platform (linux, windows)
            payload: Payload command or binary path to persist
            name: Service/task name for the persistence mechanism
            schedule: Cron schedule or task trigger (default varies by technique)
            action: Action to take (install, remove)
            additional_args: Additional arguments

        Returns:
            Persistence installation results
        """
        data = {
            "technique": technique,
            "platform": platform,
            "payload": payload,
            "name": name,
            "schedule": schedule,
            "action": action,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Managing persistence: {technique or 'listing techniques'} on {platform}")
        result = redvector_client.safe_post("api/tools/persistence-manager", data)
        if result.get("success"):
            logger.info(f"✅ Persistence {action} completed")
        else:
            logger.error(f"❌ Persistence {action} failed")
        return result

    @mcp.tool()
    def reverse_shell_generate(
        lhost: str = "",
        lport: str = "4444",
        shell_type: str = "bash",
        encoding: str = "",
        list_types: bool = False
    ) -> Dict[str, Any]:
        """
        Generate reverse shell payloads for multiple platforms and languages.

        Args:
            lhost: Attacker IP address (listener address)
            lport: Attacker port (default: 4444)
            shell_type: Shell type (bash, sh, python, python3, perl, php, ruby, netcat, ncat, powershell, java, node, groovy, lua, awk, socat, msfvenom_linux, msfvenom_windows)
            encoding: Encoding type (base64 or empty for none)
            list_types: List all available shell types

        Returns:
            Generated reverse shell payload
        """
        data = {
            "lhost": lhost,
            "lport": lport,
            "shell_type": shell_type,
            "encoding": encoding,
            "list_types": list_types
        }
        logger.info(f"🔧 Generating {shell_type} reverse shell to {lhost}:{lport}")
        result = redvector_client.safe_post("api/tools/reverse-shell-generator", data)
        if result.get("success"):
            logger.info(f"✅ Reverse shell payload generated")
        else:
            logger.error(f"❌ Reverse shell generation failed")
        return result

    # ============================================================================
    # PHASE 1 ADDITIONS: SCANNING & RECONNAISSANCE
    # ============================================================================

    @mcp.tool()
    def theharvester_scan(
        domain: str,
        source: str = "all",
        limit: int = 500,
        start: int = 0,
        output_file: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute theHarvester for OSINT email, subdomain, and host discovery.

        Args:
            domain: Target domain to harvest
            source: Data source (all, google, bing, linkedin, twitter, dnsdumpster, certspotter, crtsh, etc.)
            limit: Maximum number of results (default: 500)
            start: Start result number
            output_file: Save results to file (HTML/XML)
            additional_args: Additional arguments

        Returns:
            Discovered emails, subdomains, hosts, and IPs
        """
        data = {"domain": domain, "source": source, "limit": limit, "start": start, "output_file": output_file, "additional_args": additional_args}
        logger.info(f"🔍 Starting theHarvester OSINT for {domain} (source: {source})")
        result = redvector_client.safe_post("api/tools/theharvester", data)
        if result.get("success"):
            logger.info(f"✅ theHarvester completed for {domain}")
        else:
            logger.error(f"❌ theHarvester failed for {domain}")
        return result

    @mcp.tool()
    def whois_lookup(
        target: str,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute WHOIS for domain registration and IP information lookup.

        Args:
            target: Domain name or IP address to look up
            additional_args: Additional arguments

        Returns:
            Registration details, nameservers, registrar info, contact details
        """
        data = {"target": target, "additional_args": additional_args}
        logger.info(f"🔍 Starting WHOIS lookup for {target}")
        result = redvector_client.safe_post("api/tools/whois", data)
        if result.get("success"):
            logger.info(f"✅ WHOIS lookup completed for {target}")
        else:
            logger.error(f"❌ WHOIS lookup failed for {target}")
        return result

    @mcp.tool()
    def dnsrecon_scan(
        domain: str,
        scan_type: str = "std",
        nameserver: str = "",
        wordlist: str = "",
        output_file: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute dnsrecon for DNS enumeration, zone transfers, and brute-forcing.

        Args:
            domain: Target domain
            scan_type: Scan type (std=standard, brt=brute-force, axfr=zone transfer, rvl=reverse, snoop=cache snooping, zonewalk=DNSSEC zone walk)
            nameserver: Specific nameserver to query
            wordlist: Wordlist for brute-force mode
            output_file: Save results to XML file
            additional_args: Additional arguments

        Returns:
            DNS records, zone transfer results, brute-force findings
        """
        data = {"domain": domain, "scan_type": scan_type, "nameserver": nameserver, "wordlist": wordlist, "output_file": output_file, "additional_args": additional_args}
        logger.info(f"🔍 Starting dnsrecon for {domain} (type: {scan_type})")
        result = redvector_client.safe_post("api/tools/dnsrecon", data)
        if result.get("success"):
            logger.info(f"✅ dnsrecon completed for {domain}")
        else:
            logger.error(f"❌ dnsrecon failed for {domain}")
        return result

    @mcp.tool()
    def shodan_search(
        action: str = "host",
        query: str = "",
        target: str = "",
        facets: str = "",
        limit: int = 100,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Shodan CLI for internet-wide host and service discovery.

        Args:
            action: Shodan action (host=IP lookup, search=query, count=result count, scan=on-demand scan, info=API info, honeyscore=honeypot check)
            query: Shodan search query (e.g., "apache port:443 country:US")
            target: Target IP for host/scan/honeyscore actions
            facets: Facets for search aggregation (e.g., "country,org")
            limit: Maximum search results (default: 100)
            additional_args: Additional arguments

        Returns:
            Host details, open ports, services, vulnerabilities, or search results
        """
        data = {"action": action, "query": query, "target": target, "facets": facets, "limit": limit, "additional_args": additional_args}
        logger.info(f"🔍 Starting Shodan {action}: {target or query}")
        result = redvector_client.safe_post("api/tools/shodan", data)
        if result.get("success"):
            logger.info(f"✅ Shodan {action} completed")
        else:
            logger.error(f"❌ Shodan {action} failed")
        return result

    @mcp.tool()
    def sherlock_username_search(
        username: str,
        site: str = "",
        output_file: str = "",
        timeout: int = 60,
        print_all: bool = False,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Sherlock for username enumeration across social media platforms.

        Args:
            username: Username to search for across platforms
            site: Specific site to check (leave empty for all platforms)
            output_file: Save results to file
            timeout: Request timeout in seconds
            print_all: Print all results including not found
            additional_args: Additional arguments

        Returns:
            Social media accounts found for the username
        """
        data = {"username": username, "site": site, "output_file": output_file, "timeout": timeout, "print_all": print_all, "additional_args": additional_args}
        logger.info(f"🔍 Starting Sherlock username enumeration for {username}")
        result = redvector_client.safe_post("api/tools/sherlock", data)
        if result.get("success"):
            logger.info(f"✅ Sherlock completed for {username}")
        else:
            logger.error(f"❌ Sherlock failed for {username}")
        return result

    # ============================================================================
    # PHASE 2 ADDITIONS: VULNERABILITY IDENTIFICATION
    # ============================================================================

    @mcp.tool()
    def testssl_scan(
        target: str,
        checks: str = "",
        severity: str = "",
        output_file: str = "",
        json_output: bool = False,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute testssl.sh for comprehensive TLS/SSL configuration testing.

        Args:
            target: Target host:port (e.g., example.com:443)
            checks: Comma-separated checks (protocols, ciphers, vulnerabilities, headers, etc.)
            severity: Minimum severity to show (LOW, MEDIUM, HIGH, CRITICAL)
            output_file: Save results to file
            json_output: Output in JSON format
            additional_args: Additional arguments

        Returns:
            TLS/SSL configuration issues, weak ciphers, protocol vulnerabilities
        """
        data = {"target": target, "checks": checks, "severity": severity, "output_file": output_file, "json_output": json_output, "additional_args": additional_args}
        logger.info(f"🔒 Starting testssl.sh for {target}")
        result = redvector_client.safe_post("api/tools/testssl", data)
        if result.get("success"):
            logger.info(f"✅ testssl.sh completed for {target}")
        else:
            logger.error(f"❌ testssl.sh failed for {target}")
        return result

    @mcp.tool()
    def commix_scan(
        url: str,
        data: str = "",
        cookie: str = "",
        level: int = 1,
        technique: str = "",
        os_cmd: str = "",
        batch: bool = True,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Commix for automated command injection detection and exploitation.

        Args:
            url: Target URL with injectable parameter (e.g., http://target/page?id=1)
            data: POST data (e.g., "param1=val1&param2=val2")
            cookie: HTTP cookie string
            level: Injection test level 1-3 (default: 1)
            technique: Injection technique (classic, eval-based, time-based, file-based)
            os_cmd: Execute this OS command if injection found
            batch: Run in batch mode without prompts (default: true)
            additional_args: Additional arguments

        Returns:
            Command injection vulnerability findings and exploitation results
        """
        data_payload = {"url": url, "data": data, "cookie": cookie, "level": level, "technique": technique, "os_cmd": os_cmd, "batch": batch, "additional_args": additional_args}
        logger.info(f"🔍 Starting Commix command injection test on {url}")
        result = redvector_client.safe_post("api/tools/commix", data_payload)
        if result.get("success"):
            logger.info(f"✅ Commix completed for {url}")
        else:
            logger.error(f"❌ Commix failed for {url}")
        return result

    @mcp.tool()
    def nosqlmap_scan(
        url: str,
        form_data: str = "",
        dbtype: str = "MongoDB",
        attack: int = 1,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute NoSQLMap for NoSQL injection testing (MongoDB, CouchDB, etc.).

        Args:
            url: Target URL
            form_data: POST form data with injectable parameters
            dbtype: Database type (MongoDB, CouchDB, Redis)
            attack: Attack type (1=default injection, 2=SSJI scan, 3=GET parameter, etc.)
            additional_args: Additional arguments

        Returns:
            NoSQL injection vulnerability findings
        """
        data = {"url": url, "form_data": form_data, "dbtype": dbtype, "attack": attack, "additional_args": additional_args}
        logger.info(f"🔍 Starting NoSQLMap injection test on {url}")
        result = redvector_client.safe_post("api/tools/nosqlmap", data)
        if result.get("success"):
            logger.info(f"✅ NoSQLMap completed for {url}")
        else:
            logger.error(f"❌ NoSQLMap failed for {url}")
        return result

    # ============================================================================
    # PHASE 3 ADDITIONS: EXPLOIT SELECTION & DEVELOPMENT
    # ============================================================================

    @mcp.tool()
    def searchsploit_lookup(
        query: str = "",
        cve: str = "",
        exact: bool = False,
        title_only: bool = False,
        exclude: str = "",
        json_output: bool = True,
        mirror: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Search the local Exploit-DB database using SearchSploit.

        Args:
            query: Search query (e.g., "Apache 2.4", "WordPress 5.0", "Windows SMB")
            cve: Search by CVE ID (e.g., "2021-44228")
            exact: Use exact match instead of fuzzy search
            title_only: Search only in exploit titles
            exclude: Exclude terms from results (e.g., "dos,denial")
            json_output: Return results in JSON format (default: true)
            mirror: Mirror exploit file to current directory (exploit ID)
            additional_args: Additional arguments

        Returns:
            Matching exploits with ID, title, path, platform, and type
        """
        data = {"query": query, "cve": cve, "exact": exact, "title_only": title_only, "exclude": exclude, "json_output": json_output, "mirror": mirror, "additional_args": additional_args}
        logger.info(f"🔍 Searching ExploitDB for: {query or cve}")
        result = redvector_client.safe_post("api/tools/searchsploit", data)
        if result.get("success"):
            logger.info(f"✅ SearchSploit completed for {query or cve}")
        else:
            logger.error(f"❌ SearchSploit failed for {query or cve}")
        return result

    @mcp.tool()
    def metasploit_module_search(
        query: str = "",
        cve: str = "",
        platform: str = "",
        module_type: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Search Metasploit Framework modules by CVE, name, platform, or type.

        Args:
            query: Search query (e.g., "eternalblue", "apache struts", "smb")
            cve: Search by CVE ID (e.g., "2017-0144")
            platform: Filter by platform (windows, linux, osx, android, multi)
            module_type: Filter by type (exploit, auxiliary, post, payload, encoder, nop)
            additional_args: Additional search terms

        Returns:
            Matching Metasploit modules with name, description, rank, and disclosure date
        """
        data = {"query": query, "cve": cve, "platform": platform, "module_type": module_type, "additional_args": additional_args}
        logger.info(f"🔍 Searching Metasploit modules: {query or cve}")
        result = redvector_client.safe_post("api/tools/metasploit-search", data)
        if result.get("success"):
            logger.info(f"✅ Metasploit module search completed")
        else:
            logger.error(f"❌ Metasploit module search failed")
        return result

    # ============================================================================
    # PHASE 4 ADDITIONS: PAYLOAD EXECUTION
    # ============================================================================

    @mcp.tool()
    def netexec_execute(
        target: str,
        protocol: str = "smb",
        username: str = "",
        password: str = "",
        hashes: str = "",
        domain: str = "",
        command: str = "",
        ps_command: str = "",
        exec_method: str = "",
        module: str = "",
        module_options: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute commands on remote hosts via NetExec (CrackMapExec successor).

        Args:
            target: Target IP, hostname, or CIDR range
            protocol: Protocol (smb, ssh, winrm, ldap, mssql, rdp, wmi, ftp)
            username: Username for authentication
            password: Password for authentication
            hashes: NTLM hash for pass-the-hash (LM:NT format)
            domain: Active Directory domain
            command: OS command to execute (-x flag)
            ps_command: PowerShell command to execute (-X flag)
            exec_method: Execution method (smbexec, atexec, wmiexec, mmcexec)
            module: NetExec module to run (e.g., mimikatz, spider_plus, enum_av)
            module_options: Module-specific options
            additional_args: Additional arguments

        Returns:
            Remote command execution results across multiple hosts
        """
        data = {"target": target, "protocol": protocol, "username": username, "password": password, "hashes": hashes, "domain": domain, "command": command, "ps_command": ps_command, "exec_method": exec_method, "module": module, "module_options": module_options, "additional_args": additional_args}
        logger.info(f"🔑 Starting NetExec {protocol} exec against {target}")
        result = redvector_client.safe_post("api/tools/netexec-exec", data)
        if result.get("success"):
            logger.info(f"✅ NetExec exec completed for {target}")
        else:
            logger.error(f"❌ NetExec exec failed for {target}")
        return result

    @mcp.tool()
    def payload_stage(
        staging_method: str = "http",
        payload_path: str = "",
        lhost: str = "",
        lport: str = "8080",
        target: str = "",
        delivery_command: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Stage and deliver payloads via multiple protocols for target download/execution.

        Args:
            staging_method: Delivery method (http=Python HTTP server, smb=Impacket SMB share, ftp=FTP server, generate=custom delivery)
            payload_path: Path to payload file or directory
            lhost: Attacker IP address for download URLs
            lport: Listening port (default: 8080)
            target: Target host for delivery
            delivery_command: Custom command for 'generate' mode
            additional_args: Additional arguments

        Returns:
            Staging server commands and download commands for the target
        """
        data = {"staging_method": staging_method, "payload_path": payload_path, "lhost": lhost, "lport": lport, "target": target, "delivery_command": delivery_command, "additional_args": additional_args}
        logger.info(f"📦 Configuring payload staging via {staging_method}")
        result = redvector_client.safe_post("api/tools/payload-staging", data)
        if result.get("success"):
            logger.info(f"✅ Payload staging configured via {staging_method}")
        else:
            logger.error(f"❌ Payload staging failed")
        return result

    # ============================================================================
    # PHASE 5 ADDITIONS: POST-EXPLOITATION
    # ============================================================================

    @mcp.tool()
    def lazagne_harvest(
        module: str = "all",
        write_output: bool = False,
        output_dir: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute LaZagne for credential harvesting from installed applications.

        Args:
            module: Module to run (all, browsers, wifi, sysadmin, databases, git, mails, memory, multimedia, php, svn, windows, chats)
            write_output: Write results to a file
            output_dir: Output directory for results
            additional_args: Additional arguments

        Returns:
            Harvested credentials from browsers, WiFi, databases, mail clients, etc.
        """
        data = {"module": module, "write_output": write_output, "output_dir": output_dir, "additional_args": additional_args}
        logger.info(f"🔑 Starting LaZagne credential harvester (module: {module})")
        result = redvector_client.safe_post("api/tools/lazagne", data)
        if result.get("success"):
            logger.info(f"✅ LaZagne completed")
        else:
            logger.error(f"❌ LaZagne failed")
        return result

    @mcp.tool()
    def tshark_capture(
        interface: str = "",
        capture_filter: str = "",
        display_filter: str = "",
        read_file: str = "",
        write_file: str = "",
        count: int = 0,
        duration: int = 30,
        fields: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute tshark for network traffic capture and protocol analysis.

        Args:
            interface: Network interface to capture on (e.g., eth0, wlan0)
            capture_filter: BPF capture filter (e.g., "port 80", "host 10.10.10.5")
            display_filter: Wireshark display filter (e.g., "http.request", "dns")
            read_file: Read and analyze existing PCAP file
            write_file: Write captured packets to PCAP file
            count: Number of packets to capture (0=unlimited)
            duration: Capture duration in seconds (default: 30)
            fields: Comma-separated fields to extract (e.g., "ip.src,ip.dst,tcp.port")
            additional_args: Additional arguments

        Returns:
            Captured network traffic data and protocol analysis
        """
        data = {"interface": interface, "capture_filter": capture_filter, "display_filter": display_filter, "read_file": read_file, "write_file": write_file, "count": count, "duration": duration, "fields": fields, "additional_args": additional_args}
        logger.info(f"📡 Starting tshark capture")
        result = redvector_client.safe_post("api/tools/tshark", data)
        if result.get("success"):
            logger.info(f"✅ tshark capture completed")
        else:
            logger.error(f"❌ tshark capture failed")
        return result

    @mcp.tool()
    def tcpdump_capture(
        interface: str = "",
        filter_expr: str = "",
        count: int = 100,
        write_file: str = "",
        verbose: bool = False,
        duration: int = 30,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute tcpdump for network packet capture.

        Args:
            interface: Network interface (e.g., eth0)
            filter_expr: BPF filter expression (e.g., "tcp port 80 and host 10.10.10.5")
            count: Number of packets to capture (default: 100)
            write_file: Write captured packets to PCAP file
            verbose: Enable verbose output
            duration: Capture duration in seconds (default: 30)
            additional_args: Additional arguments

        Returns:
            Captured network packets
        """
        data = {"interface": interface, "filter": filter_expr, "count": count, "write_file": write_file, "verbose": verbose, "duration": duration, "additional_args": additional_args}
        logger.info(f"📡 Starting tcpdump capture")
        result = redvector_client.safe_post("api/tools/tcpdump", data)
        if result.get("success"):
            logger.info(f"✅ tcpdump capture completed")
        else:
            logger.error(f"❌ tcpdump capture failed")
        return result

    @mcp.tool()
    def powersploit_execute(
        module: str = "",
        function: str = "",
        target: str = "",
        arguments: str = "",
        script_path: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute PowerSploit modules for Windows post-exploitation.

        Args:
            module: PowerSploit module (Recon, Exfiltration, Privesc, Persistence, CodeExec, AntiVirus). Leave empty to list modules.
            function: Function name to invoke (e.g., Invoke-Mimikatz, Invoke-AllChecks, Get-GPPPassword, Invoke-Portscan)
            target: Target for the function
            arguments: Function arguments (e.g., "-ComputerName DC01")
            script_path: Local path to PowerSploit script (alternative to module download)
            additional_args: Additional arguments

        Returns:
            PowerSploit module execution results
        """
        data = {"module": module, "function": function, "target": target, "arguments": arguments, "script_path": script_path, "additional_args": additional_args}
        logger.info(f"🔧 Starting PowerSploit: {module}/{function or 'list'}")
        result = redvector_client.safe_post("api/tools/powersploit", data)
        if result.get("success"):
            logger.info(f"✅ PowerSploit completed")
        else:
            logger.error(f"❌ PowerSploit failed")
        return result

    # ==========================================================================
    # AUTONOMOUS EXPLOIT SYSTEM MCP TOOLS
    # ==========================================================================

    @mcp.tool()
    def autonomous_recon_to_shell(target: str, lhost: str = "0.0.0.0", lport: int = 4444, stealth_level: str = "normal") -> dict:
        """
        Autonomous Recon-to-Shell Pipeline - zero-human-input exploit chain.
        Scans target, identifies services, matches CVEs, selects exploits, generates payloads, and provides shell access.

        Args:
            target: Target IP or hostname
            lhost: Listener host for reverse shells
            lport: Listener port for reverse shells
            stealth_level: Scan stealth level (stealth, normal, aggressive)

        Returns:
            Complete attack pipeline with services, CVEs, exploits, payloads, and shell commands
        """
        data = {"target": target, "lhost": lhost, "lport": lport, "stealth_level": stealth_level}
        logger.info(f"🤖 Autonomous Recon-to-Shell for {target}")
        result = redvector_client.safe_post("api/autonomous/recon-to-shell", data)
        if result.get("success"):
            stages = len(result.get("pipeline_stages", []))
            logger.info(f"✅ Pipeline completed: {stages} stages")
        else:
            logger.error(f"❌ Recon-to-Shell pipeline failed")
        return result

    @mcp.tool()
    def evasion_analyze_defenses(target: str, response_headers: dict = None, response_code: int = 200) -> dict:
        """
        Adaptive Evasion Engine - detects WAF/IDS/IPS and generates bypass strategies.
        Identifies Cloudflare, Akamai, ModSecurity, AWS WAF, F5 BIG-IP, Imperva and more.

        Args:
            target: Target URL or hostname
            response_headers: HTTP response headers from target (for WAF fingerprinting)
            response_code: HTTP response status code

        Returns:
            Detected defenses, evasion strategy, bypass techniques, and recommended headers
        """
        data = {"target": target, "response_headers": response_headers or {}, "response_code": response_code}
        logger.info(f"🛡️ Evasion analysis for {target}")
        result = redvector_client.safe_post("api/autonomous/evasion-analyze", data)
        if result.get("success"):
            defenses = len(result.get("detected_defenses", []))
            logger.info(f"✅ Detected {defenses} defensive measures")
        else:
            logger.error(f"❌ Evasion analysis failed")
        return result

    @mcp.tool()
    def evasion_generate_payload(payload: str, target: str, evasion_level: str = "medium") -> dict:
        """
        Generate evasive payloads that bypass detected WAF/IDS.
        Transforms payloads using encoding, case variation, comment injection, chunking, etc.

        Args:
            payload: Original attack payload to transform
            target: Target URL or hostname
            evasion_level: Evasion intensity (low, medium, high)

        Returns:
            Multiple transformed payloads with different evasion techniques
        """
        data = {"payload": payload, "target": target, "evasion_level": evasion_level}
        logger.info(f"🎭 Generating evasive payloads for {target}")
        result = redvector_client.safe_post("api/autonomous/evasion-payload", data)
        if result.get("success"):
            count = len(result.get("transformed_payloads", []))
            logger.info(f"✅ Generated {count} evasive payloads")
        else:
            logger.error(f"❌ Evasive payload generation failed")
        return result

    @mcp.tool()
    def autonomous_ad_domination(domain: str, dc_ip: str, username: str = "", password: str = "", opsec_level: str = "medium") -> dict:
        """
        Autonomous Active Directory Domination Engine.
        Generates complete attack plan from foothold to Domain Admin: discovery, Kerberoasting,
        privilege escalation, lateral movement, DCSync, Golden Ticket.

        Args:
            domain: Active Directory domain name (e.g. corp.local)
            dc_ip: Domain Controller IP address
            username: Current user credentials (username)
            password: Current user credentials (password)
            opsec_level: OpSec level (low, medium, high)

        Returns:
            Complete AD attack plan with phases, commands, attack graph, and opsec advice
        """
        data = {"domain": domain, "dc_ip": dc_ip, "username": username, "password": password, "opsec_level": opsec_level}
        logger.info(f"👑 AD Domination for {domain}")
        result = redvector_client.safe_post("api/autonomous/ad-domination", data)
        if result.get("success"):
            phases = len(result.get("attack_phases", []))
            logger.info(f"✅ AD attack plan: {phases} phases")
        else:
            logger.error(f"❌ AD Domination failed")
        return result

    @mcp.tool()
    def web_vuln_chain_discover(target: str, vulnerabilities: list = None, max_chains: int = 10) -> dict:
        """
        Autonomous Web Vulnerability Chaining Engine - discovers exploit chains.
        Finds SSRF→RCE, XSS→ATO, SQLi→Full Compromise, LFI→RCE, File Upload→Shell, IDOR→Exfil chains.

        Args:
            target: Target URL
            vulnerabilities: List of known vulnerabilities (optional, each with 'type' field)
            max_chains: Maximum number of chains to return

        Returns:
            Discovered chains, vulnerability graph, highest impact chain, and scan recommendations
        """
        data = {"target": target, "vulnerabilities": vulnerabilities or [], "max_chains": max_chains}
        logger.info(f"🔗 Web vulnerability chain discovery for {target}")
        result = redvector_client.safe_post("api/autonomous/web-vuln-chains", data)
        if result.get("success"):
            chains = result.get("total_chains", 0)
            logger.info(f"✅ Discovered {chains} vulnerability chains")
        else:
            logger.error(f"❌ Vulnerability chain discovery failed")
        return result

    @mcp.tool()
    def web_vuln_chain_exploit(chain_type: str, target: str, parameters: dict = None) -> dict:
        """
        Generate exploit for a specific web vulnerability chain.
        Provides step-by-step exploitation commands for chains like ssrf_to_rce, xss_to_account_takeover, etc.

        Args:
            chain_type: Chain type (ssrf_to_rce, xss_to_account_takeover, idor_to_data_exfil, sqli_to_full_compromise, file_upload_to_shell, lfi_to_rce)
            target: Target URL
            parameters: Additional parameters for exploit generation

        Returns:
            Complete exploit steps with PoC commands for each stage of the chain
        """
        data = {"chain_type": chain_type, "target": target, "parameters": parameters or {}}
        logger.info(f"⚔️ Chain exploit: {chain_type} for {target}")
        result = redvector_client.safe_post("api/autonomous/web-vuln-chain-exploit", data)
        if result.get("success"):
            steps = len(result.get("exploit_steps", []))
            logger.info(f"✅ Exploit chain: {steps} steps generated")
        else:
            logger.error(f"❌ Chain exploit generation failed")
        return result

    @mcp.tool()
    def persistence_deploy(target_os: str = "linux", lhost: str = "0.0.0.0", lport: int = 4444, methods_count: int = 3, stealth_level: str = "medium") -> dict:
        """
        Autonomous Persistence & C2 Mesh - deploy multiple redundant persistence mechanisms.
        Supports Linux (crontab, systemd, bashrc, SSH keys, LD_PRELOAD) and Windows (registry, scheduled tasks, WMI, DLL hijack, startup folder).

        Args:
            target_os: Target OS (linux or windows)
            lhost: Listener host for callbacks
            lport: Listener port for callbacks
            methods_count: Number of persistence methods to deploy (1-5)
            stealth_level: Stealth level filter (low, medium, high)

        Returns:
            Persistence methods, C2 channels, self-healing config, cleanup commands, deployment script
        """
        data = {"target_os": target_os, "lhost": lhost, "lport": lport, "methods_count": methods_count, "stealth_level": stealth_level}
        logger.info(f"🔒 Persistence deployment for {target_os}")
        result = redvector_client.safe_post("api/autonomous/persistence-deploy", data)
        if result.get("success"):
            methods = len(result.get("persistence_methods", []))
            logger.info(f"✅ Deployed {methods} persistence methods")
        else:
            logger.error(f"❌ Persistence deployment failed")
        return result

    @mcp.tool()
    def c2_channel_config(c2_type: str, lhost: str = "0.0.0.0", lport: int = 4444, encryption: str = "aes256", callback_interval: int = 60) -> dict:
        """
        Generate C2 channel configuration for covert command & control.
        Supports DNS-over-HTTPS, ICMP tunnel, WebSocket, domain fronting, and dead drop C2.

        Args:
            c2_type: C2 channel type (dns_over_https, icmp_tunnel, websocket_c2, domain_fronting, dead_drop)
            lhost: C2 server host
            lport: C2 server port
            encryption: Encryption algorithm (aes256, chacha20)
            callback_interval: Callback interval in seconds

        Returns:
            C2 configuration, setup commands, and fallback channels
        """
        data = {"c2_type": c2_type, "lhost": lhost, "lport": lport, "encryption": encryption, "callback_interval": callback_interval}
        logger.info(f"📡 C2 config: {c2_type}")
        result = redvector_client.safe_post("api/autonomous/c2-config", data)
        if result.get("success"):
            logger.info(f"✅ C2 channel configured: {c2_type}")
        else:
            logger.error(f"❌ C2 config failed")
        return result

    @mcp.tool()
    def autonomous_sqli_scan(target_url: str, scan_depth: str = "normal", test_types: list = None, crawl: bool = True, max_params: int = 50) -> dict:
        """
        Autonomous SQL Injection Scanner - automatically crawl a website and find SQL injection vulnerabilities.
        Crawls the target, discovers forms/parameters, and tests them with error-based, boolean-blind,
        time-blind, union-based, stacked query, and WAF bypass payloads.

        Args:
            target_url: Target website URL (e.g. https://target.com)
            scan_depth: Scan intensity - normal (4 test types) or aggressive (all 6 including WAF bypass + stacked)
            test_types: Specific test types to run (error_based, blind_boolean, blind_time, union_based, stacked_queries, waf_bypass)
            crawl: Whether to crawl the site for endpoints (True/False)
            max_params: Maximum parameters to test (default 50)

        Returns:
            Discovered endpoints, parameters, SQL injection vulnerabilities, sqlmap commands, and remediation advice
        """
        data = {"target_url": target_url, "scan_depth": scan_depth, "test_types": test_types, "crawl": crawl, "max_params": max_params}
        logger.info(f"🔍 Autonomous SQLi scan for {target_url}")
        result = redvector_client.safe_post("api/autonomous/sqli-scan", data)
        if result.get("success"):
            vulns = result.get("total_vulns_found", 0)
            tests = result.get("total_tests_run", 0)
            logger.info(f"✅ SQLi scan complete: {vulns} potential vulns found in {tests} tests")
        else:
            logger.error(f"❌ SQLi scan failed")
        return result

    # ==========================================================================
    # AUTONOMOUS EXPLOIT ENGINE MCP TOOLS (System 7)
    # ==========================================================================

    @mcp.tool()
    def autonomous_exploit_engine(target: str, lhost: str = "0.0.0.0", lport: int = 4444,
                                   target_os: str = "auto", strategy: str = "balanced",
                                   max_exploits: int = 5) -> dict:
        """
        Autonomous Exploit Execution Engine - AI-driven Metasploit integration.
        Fingerprints target, selects best exploits via AI scoring, generates payloads,
        configures listeners, builds attack plan, and provides post-exploitation playbook.

        Args:
            target: Target IP or hostname
            lhost: Listener host for reverse shells
            lport: Listener port for reverse shells
            target_os: Target OS (auto, windows, linux) - auto-detected if 'auto'
            strategy: Exploit strategy (stealth, balanced, aggressive)
            max_exploits: Maximum number of exploits to include in plan

        Returns:
            Complete exploit pipeline: services, ranked exploits, payload config,
            listener setup, msfconsole attack commands, post-exploit playbook
        """
        data = {
            "target": target, "lhost": lhost, "lport": lport,
            "target_os": target_os, "strategy": strategy, "max_exploits": max_exploits,
        }
        logger.info(f"💀 Autonomous Exploit Engine for {target} (strategy={strategy})")
        result = redvector_client.safe_post("api/autonomous/exploit-engine", data)
        if result.get("success"):
            exploits = len(result.get("selected_exploits", []))
            logger.info(f"✅ Exploit engine: {exploits} exploits selected")
        else:
            logger.error(f"❌ Exploit engine failed")
        return result

    @mcp.tool()
    def exploit_select(service: str, version: str = "", target_os: str = "auto") -> dict:
        """
        AI-driven exploit selection for a specific service.
        Queries internal Metasploit module database and ranks exploits by reliability,
        CVSS, and stealth. Returns best matching modules with AI confidence scores.

        Args:
            service: Service name to find exploits for (http, smb, ssh, ftp, mysql, rdp, smtp, dns, telnet)
            version: Service version string (optional, for more precise matching)
            target_os: Target OS filter (auto, windows, linux)

        Returns:
            Ranked list of Metasploit modules with AI scores and recommendation
        """
        data = {"service": service, "version": version, "target_os": target_os}
        logger.info(f"🎯 Exploit selection for {service} {version}")
        result = redvector_client.safe_post("api/autonomous/exploit-select", data)
        if result.get("success"):
            count = len(result.get("ranked_exploits", []))
            logger.info(f"✅ Found {count} matching exploits")
        else:
            logger.error(f"❌ Exploit selection failed")
        return result

    @mcp.tool()
    def exploit_generate_payload(target_os: str = "linux", payload_type: str = "meterpreter",
                                  lhost: str = "0.0.0.0", lport: int = 4444,
                                  arch: str = "x64", encode: bool = False) -> dict:
        """
        Generate Metasploit payload with msfvenom command and matching listener config.
        Supports Meterpreter, shell, and command payloads for Windows and Linux.

        Args:
            target_os: Target OS (windows, linux)
            payload_type: Payload type (meterpreter, shell, command)
            lhost: Listener host for callbacks
            lport: Listener port for callbacks
            arch: Architecture (x64, x86, cmd)
            encode: Whether to encode payload with shikata_ga_nai

        Returns:
            Payload info, msfvenom command, and multi/handler listener setup
        """
        data = {
            "target_os": target_os, "payload_type": payload_type,
            "lhost": lhost, "lport": lport, "arch": arch, "encode": encode,
        }
        logger.info(f"🔫 Payload generation: {target_os}/{payload_type}/{arch}")
        result = redvector_client.safe_post("api/autonomous/exploit-payload", data)
        if result.get("success"):
            logger.info(f"✅ Payload generated: {result.get('payload_info', {}).get('payload', 'N/A')}")
        else:
            logger.error(f"❌ Payload generation failed")
        return result

    @mcp.tool()
    def post_exploit_playbook(target_os: str = "linux", phase: str = None) -> dict:
        """
        Get post-exploitation playbook for a target OS.
        Covers privilege escalation, credential harvesting, persistence, and lateral movement.

        Args:
            target_os: Target OS (windows, linux)
            phase: Filter to specific phase (privilege_escalation, credential_harvesting, persistence, lateral_movement) - omit for all

        Returns:
            Complete post-exploitation playbook with Meterpreter/shell commands
        """
        data = {"target_os": target_os, "phase": phase}
        logger.info(f"📋 Post-exploit playbook for {target_os}")
        result = redvector_client.safe_post("api/autonomous/post-exploit-playbook", data)
        if result.get("success"):
            total = result.get("total_actions", 0)
            logger.info(f"✅ Playbook: {total} post-exploitation actions")
        else:
            logger.error(f"❌ Post-exploit playbook failed")
        return result

    # ==========================================================================
    # AUTONOMOUS SQLMAP DATA EXFILTRATION MCP TOOLS (System 8)
    # ==========================================================================

    @mcp.tool()
    def autonomous_sqlmap_exfiltration(target_url: str, parameter: str,
                                       method: str = "GET", dbms: str = "auto",
                                       technique: str = "auto", depth: str = "tables",
                                       limit: int = 100) -> dict:
        """
        Autonomous SQLMap-style data exfiltration pipeline.
        Goes from 'check if vulnerable' to 'dump entire database' in one call.
        Detects injection, fingerprints DBMS, enumerates databases/tables,
        identifies high-value targets (credentials, API keys, PII, financial),
        dumps data previews, and generates complete sqlmap command suite.

        Args:
            target_url: Target URL with injectable parameter (e.g. https://target.com/page.php)
            parameter: Injectable parameter name (e.g. id, user, search)
            method: HTTP method (GET or POST)
            dbms: Database type hint (auto, mysql, postgresql, mssql, sqlite, oracle)
            technique: Injection technique (auto, or combination of B/E/U/S/T/Q)
            depth: Enumeration depth - 'tables' (with columns) or 'databases' (db list only)
            limit: Max rows per table dump (default 100)

        Returns:
            Complete exfiltration pipeline: injection techniques, DBMS, databases,
            tables, high-value targets, data dump previews, sqlmap commands, risk assessment
        """
        data = {
            "target_url": target_url, "parameter": parameter, "method": method,
            "dbms": dbms, "technique": technique, "depth": depth, "limit": limit,
        }
        logger.info(f"💉 SQLMap exfiltration pipeline for {target_url} param={parameter}")
        result = redvector_client.safe_post("api/autonomous/sqlmap-exfil", data)
        if result.get("success"):
            tables = len(result.get("high_value_targets", []))
            records = result.get("total_records_accessible", 0)
            logger.info(f"✅ Exfiltration: {tables} high-value targets, {records} records accessible")
        else:
            logger.error(f"❌ SQLMap exfiltration failed")
        return result

    @mcp.tool()
    def sqlmap_enumerate_databases(target_url: str, parameter: str,
                                    method: str = "GET", dbms: str = "auto") -> dict:
        """
        Enumerate all databases accessible through a SQL injection point.
        Returns database names, table counts, and the exact sqlmap command to reproduce.

        Args:
            target_url: Target URL with injectable parameter
            parameter: Injectable parameter name
            method: HTTP method (GET or POST)
            dbms: Database type hint (auto, mysql, postgresql, mssql, sqlite, oracle)

        Returns:
            List of databases with table counts and sizes, sqlmap --dbs command
        """
        data = {"target_url": target_url, "parameter": parameter, "method": method, "dbms": dbms}
        logger.info(f"🗄️ SQLMap database enumeration for {target_url}")
        result = redvector_client.safe_post("api/autonomous/sqlmap-enum-dbs", data)
        if result.get("success"):
            count = len(result.get("databases", []))
            logger.info(f"✅ Found {count} databases")
        else:
            logger.error(f"❌ Database enumeration failed")
        return result

    @mcp.tool()
    def sqlmap_dump_table(target_url: str, parameter: str, table: str,
                          database: str = "", method: str = "GET",
                          dbms: str = "auto", limit: int = 100) -> dict:
        """
        Dump a specific database table through a SQL injection point.
        Returns column info, row count, sample rows, and the sqlmap --dump command.

        Args:
            target_url: Target URL with injectable parameter
            parameter: Injectable parameter name
            table: Table name to dump (e.g. users, api_keys, payments)
            database: Database name (optional - uses current DB if empty)
            method: HTTP method (GET or POST)
            dbms: Database type hint (auto, mysql, postgresql, mssql, sqlite, oracle)
            limit: Max rows to dump (default 100)

        Returns:
            Table columns, row count, sample rows preview, sqlmap dump command
        """
        data = {
            "target_url": target_url, "parameter": parameter,
            "table": table, "database": database,
            "method": method, "dbms": dbms, "limit": limit,
        }
        logger.info(f"📦 SQLMap table dump: {database}.{table}")
        result = redvector_client.safe_post("api/autonomous/sqlmap-dump-table", data)
        if result.get("success"):
            rows = result.get("row_count", 0)
            logger.info(f"✅ Table {table}: {rows} rows accessible")
        else:
            logger.error(f"❌ Table dump failed")
        return result

    @mcp.tool()
    def sqlmap_extract_credentials(target_url: str, parameter: str,
                                    method: str = "GET", dbms: str = "auto") -> dict:
        """
        Targeted credential extraction - find and dump all user/password tables.
        Identifies credential tables, extracts password hashes, detects hash types,
        and generates hashcat/john cracking commands.

        Args:
            target_url: Target URL with injectable parameter
            parameter: Injectable parameter name
            method: HTTP method (GET or POST)
            dbms: Database type hint (auto, mysql, postgresql, mssql, sqlite, oracle)

        Returns:
            Credential tables, password hashes preview, hash types, cracking commands,
            sqlmap --passwords commands
        """
        data = {"target_url": target_url, "parameter": parameter, "method": method, "dbms": dbms}
        logger.info(f"🔑 SQLMap credential extraction for {target_url}")
        result = redvector_client.safe_post("api/autonomous/sqlmap-extract-creds", data)
        if result.get("success"):
            total = result.get("total_credentials", 0)
            logger.info(f"✅ Found {total} credentials across {len(result.get('credential_tables_found', []))} tables")
        else:
            logger.error(f"❌ Credential extraction failed")
        return result

    @mcp.tool()
    def sqlmap_manipulate_records(target_url: str, parameter: str, operation: str,
                                   method: str = "GET", dbms: str = "auto",
                                   database: str = "", table: str = "",
                                   target_user: str = "") -> dict:
        """
        Generate SQL record manipulation queries for authorized penetration testing.
        Supports add_admin, modify_password, delete_logs, drop_table, exfil_to_file.

        Args:
            target_url: Target URL with injectable parameter
            parameter: Injectable parameter name
            operation: Manipulation operation (add_admin, modify_password, delete_logs, drop_table, exfil_to_file)
            method: HTTP method (GET or POST)
            dbms: Database type hint (auto, mysql, postgresql, mssql, sqlite, oracle)
            database: Target database name
            table: Target table name
            target_user: Username to target (for modify_password)

        Returns:
            SQL manipulation query, sqlmap --sql-query command, rollback query, risk warning
        """
        data = {
            "target_url": target_url, "parameter": parameter, "operation": operation,
            "method": method, "dbms": dbms, "database": database,
            "table": table, "target_user": target_user,
        }
        logger.info(f"⚠️ SQLMap record manipulation: {operation}")
        result = redvector_client.safe_post("api/autonomous/sqlmap-manipulate", data)
        if result.get("success"):
            logger.info(f"✅ Manipulation query generated for '{operation}'")
        else:
            logger.error(f"❌ Record manipulation failed")
        return result

    # ── Autonomous RCE Engine Tools (System 9) ───────────────────────────

    @mcp.tool()
    def autonomous_rce_pipeline(target_url: str, parameter: str = "",
                                      lhost: str = "0.0.0.0", lport: int = 4444,
                                      target_os: str = "auto", vector: str = "auto",
                                      language: str = "auto", http_port: int = 8080) -> dict:
        """
        Full autonomous Remote Command Execution pipeline.
        Detect RCE vectors -> exploit -> generate reverse shells -> post-RCE takeover.

        Args:
            target_url: Target URL to test for RCE
            parameter: Injectable parameter name
            lhost: Listener host for reverse shells
            lport: Listener port for reverse shells
            target_os: Target OS (auto, linux, windows)
            vector: Specific RCE vector to test (auto for all)
            language: Server-side language hint (auto, php, python, java, nodejs, ruby)
            http_port: HTTP port for payload delivery

        Returns:
            Full RCE pipeline results: vectors, shells, post-RCE playbook, risk assessment
        """
        data = {
            "target_url": target_url, "parameter": parameter,
            "lhost": lhost, "lport": lport, "target_os": target_os,
            "vector": vector, "language": language, "http_port": http_port,
        }
        logger.info(f"🔥 Autonomous RCE pipeline against {target_url}")
        result = redvector_client.safe_post("api/autonomous/rce-pipeline", data)
        if result.get("success"):
            stages = len(result.get("pipeline_stages", []))
            vectors = len(result.get("rce_vectors_found", []))
            logger.info(f"✅ RCE pipeline complete: {stages} stages, {vectors} vectors")
        else:
            logger.error(f"❌ RCE pipeline failed")
        return result

    @mcp.tool()
    def autonomous_rce_detect(target_url: str, parameter: str = "",
                                    vector: str = "auto", language: str = "auto") -> dict:
        """
        Detect RCE injection vectors on the target URL.
        Tests OS command injection, code injection, deserialization, file upload, SSRF-to-RCE.

        Args:
            target_url: Target URL to scan for RCE vectors
            parameter: Injectable parameter name
            vector: Specific vector type to test (auto for all)
            language: Server-side language hint (auto, php, python, java, nodejs, ruby)

        Returns:
            Detected RCE vectors with payloads and verification commands
        """
        data = {
            "target_url": target_url, "parameter": parameter,
            "vector": vector, "language": language,
        }
        logger.info(f"🔍 RCE vector detection on {target_url}")
        result = redvector_client.safe_post("api/autonomous/rce-detect", data)
        if result.get("success"):
            logger.info(f"✅ Found {len(result.get('vectors', []))} RCE vectors")
        else:
            logger.error(f"❌ RCE detection failed")
        return result

    @mcp.tool()
    def autonomous_rce_shells(target_os: str = "linux", lhost: str = "0.0.0.0",
                                    lport: int = 4444, shell_type: str = "all") -> dict:
        """
        Generate reverse shell payloads for server takeover.
        Supports bash, python, netcat, PowerShell, PHP, Perl, Ruby, Msfvenom shells.

        Args:
            target_os: Target operating system (linux, windows)
            lhost: Listener host IP for reverse shell connection
            lport: Listener port for reverse shell connection
            shell_type: Shell type filter (all, bash, python, powershell, nc, php, perl, ruby, msfvenom)

        Returns:
            Reverse shell payloads and listener setup commands
        """
        data = {
            "target_os": target_os, "lhost": lhost,
            "lport": lport, "shell_type": shell_type,
        }
        logger.info(f"🐚 Generating reverse shells for {target_os}")
        result = redvector_client.safe_post("api/autonomous/rce-shells", data)
        if result.get("success"):
            logger.info(f"✅ Generated {len(result.get('shells', []))} reverse shells")
        else:
            logger.error(f"❌ Shell generation failed")
        return result

    @mcp.tool()
    def autonomous_rce_playbook(target_os: str = "linux", lhost: str = "0.0.0.0",
                                      lport: int = 4444, http_port: int = 8080,
                                      phase: str = "") -> dict:
        """
        Get post-RCE server takeover playbook: persistence, credential harvesting,
        malware deployment, data destruction.

        Args:
            target_os: Target OS (linux, windows)
            lhost: Attacker host IP
            lport: Attacker listener port
            http_port: HTTP server port for payload delivery
            phase: Specific phase (persistence, credential_harvesting, malware_deployment, data_destruction) or empty for all

        Returns:
            Post-RCE playbook with commands for each takeover phase
        """
        data = {
            "target_os": target_os, "lhost": lhost,
            "lport": lport, "http_port": http_port,
        }
        if phase:
            data["phase"] = phase
        logger.info(f"📋 Post-RCE playbook for {target_os}")
        result = redvector_client.safe_post("api/autonomous/rce-playbook", data)
        if result.get("success"):
            logger.info(f"✅ Playbook ready: {result.get('total_actions', 0)} actions")
        else:
            logger.error(f"❌ Playbook generation failed")
        return result

    @mcp.tool()
    def autonomous_rce_cve_check(target_url: str, lhost: str = "0.0.0.0",
                                       lport: int = 4444) -> dict:
        """
        Check target against known critical RCE CVEs.
        Tests for Log4Shell, Spring4Shell, Apache Struts, Shellshock, Drupalgeddon2, PHP-CGI.

        Args:
            target_url: Target URL to check against known RCE CVEs
            lhost: Attacker host IP for exploit commands
            lport: Attacker listener port for exploit commands

        Returns:
            Matched CVEs with detection payloads and exploit commands
        """
        data = {"target_url": target_url, "lhost": lhost, "lport": lport}
        logger.info(f"🛡️ RCE CVE check for {target_url}")
        result = redvector_client.safe_post("api/autonomous/rce-cve-check", data)
        if result.get("success"):
            logger.info(f"✅ Checked {result.get('total_checked', 0)} CVEs, {len(result.get('cve_matches', []))} matches")
        else:
            logger.error(f"❌ CVE check failed")
        return result

    # ========================================================================
    # System 10: Autonomous Privilege Escalation & Persistence Tools
    # ========================================================================

    @mcp.tool()
    def autonomous_privesc_pipeline(target: str, lhost: str = "0.0.0.0", lport: int = 4444, os_type: str = "") -> dict:
        """Run the full autonomous privilege escalation and persistence pipeline.

        Performs target profiling, privilege assessment, vector enumeration,
        escalation execution, persistence deployment, service modification,
        security control neutralization, and access verification.

        Args:
            target: Target system hostname/IP to escalate privileges on
            lhost: Attacker host IP for reverse connections
            lport: Attacker listener port
            os_type: Target OS type (linux/windows, auto-detected if empty)

        Returns:
            Complete pipeline results with 8-stage escalation and persistence data
        """
        data = {"target": target, "lhost": lhost, "lport": lport}
        if os_type:
            data["os_type"] = os_type
        logger.info(f"🔓 PrivEsc pipeline for {target}")
        result = redvector_client.safe_post("api/autonomous/privesc-pipeline", data)
        if result.get("success"):
            logger.info(f"✅ Pipeline completed: {result.get('pipeline_stages', 0)} stages")
        else:
            logger.error(f"❌ PrivEsc pipeline failed")
        return result

    @mcp.tool()
    def autonomous_privesc_enumerate(target: str, os_type: str = "") -> dict:
        """Enumerate all privilege escalation vectors on a target system.

        Discovers SUID binaries, sudo misconfigurations, kernel exploits,
        cron abuse, capabilities, writable paths (Linux) or token manipulation,
        UAC bypass, service abuse, DLL hijacking, registry persistence (Windows).

        Args:
            target: Target system hostname/IP to enumerate
            os_type: Target OS type (linux/windows, auto-detected if empty)

        Returns:
            All discovered privilege escalation vectors with severity ratings
        """
        data = {"target": target}
        if os_type:
            data["os_type"] = os_type
        logger.info(f"🔍 PrivEsc enumeration for {target}")
        result = redvector_client.safe_post("api/autonomous/privesc-enumerate", data)
        if result.get("success"):
            logger.info(f"✅ Found {result.get('total_vectors', 0)} escalation vectors")
        else:
            logger.error(f"❌ PrivEsc enumeration failed")
        return result

    @mcp.tool()
    def autonomous_privesc_persist(target: str, os_type: str = "", lhost: str = "0.0.0.0", lport: int = 4444) -> dict:
        """Deploy multi-layer persistence mechanisms on a compromised target.

        Deploys cron backdoors, SSH key injection, systemd services, bashrc backdoors,
        LD_PRELOAD rootkits, PAM backdoors, sudoers modification (Linux) or scheduled
        tasks, registry keys, WMI subscriptions, service creation, startup folder,
        admin user creation, DLL sideloading, group policy modification (Windows).

        Args:
            target: Target system hostname/IP to persist on
            os_type: Target OS type (linux/windows, auto-detected if empty)
            lhost: Attacker host IP for callback payloads
            lport: Attacker listener port

        Returns:
            Deployed persistence mechanisms with stealth ratings and reboot survival status
        """
        data = {"target": target, "lhost": lhost, "lport": lport}
        if os_type:
            data["os_type"] = os_type
        logger.info(f"🔗 Deploying persistence on {target}")
        result = redvector_client.safe_post("api/autonomous/privesc-persist", data)
        if result.get("success"):
            logger.info(f"✅ Deployed {result.get('total_mechanisms', 0)} persistence mechanisms")
        else:
            logger.error(f"❌ Persistence deployment failed")
        return result

    @mcp.tool()
    def autonomous_privesc_services(target: str, os_type: str = "") -> dict:
        """Modify system services for privilege escalation and persistence.

        Identifies and modifies systemd services, xinetd services (Linux)
        or Windows service binaries, service configurations (Windows) to
        maintain SYSTEM-level persistence through legitimate service infrastructure.

        Args:
            target: Target system hostname/IP
            os_type: Target OS type (linux/windows, auto-detected if empty)

        Returns:
            Service modification templates and additional high-value service targets
        """
        data = {"target": target}
        if os_type:
            data["os_type"] = os_type
        logger.info(f"⚙️ Service modification for {target}")
        result = redvector_client.safe_post("api/autonomous/privesc-services", data)
        if result.get("success"):
            logger.info(f"✅ {result.get('total_templates', 0)} service modification templates prepared")
        else:
            logger.error(f"❌ Service modification failed")
        return result

    @mcp.tool()
    def autonomous_privesc_security(target: str, os_type: str = "") -> dict:
        """Check and neutralize security controls on a target system.

        Detects and provides neutralization plans for AppArmor, SELinux, iptables,
        auditd, fail2ban, ClamAV (Linux) or Windows Defender, Firewall, UAC, Event
        Log, AMSI, ETW (Windows) to ensure undetected persistent access.

        Args:
            target: Target system hostname/IP
            os_type: Target OS type (linux/windows, auto-detected if empty)

        Returns:
            Detected security controls with disable/evade commands and overall security posture
        """
        data = {"target": target}
        if os_type:
            data["os_type"] = os_type
        logger.info(f"🛡️ Security control check for {target}")
        result = redvector_client.safe_post("api/autonomous/privesc-security", data)
        if result.get("success"):
            logger.info(f"✅ {result.get('total_controls', 0)} security controls detected ({result.get('security_posture', 'unknown')} posture)")
        else:
            logger.error(f"❌ Security control check failed")
        return result

    # ========================================================================
    # System 11: Autonomous Data Exfiltration & Secret Harvesting Tools
    # ========================================================================

    @mcp.tool()
    def autonomous_exfil_pipeline(target: str, os_type: str = "") -> dict:
        """Run the full data exfiltration and secret harvesting pipeline.

        Performs target reconnaissance, file system harvesting, environment variable
        extraction, cloud credential theft, memory analysis, internal API access,
        secret aggregation, and exfiltration staging across 8 stages.

        Args:
            target: Target system hostname/IP to exfiltrate data from
            os_type: Target OS type (linux/windows, auto-detected if empty)

        Returns:
            Complete pipeline results with all harvested secrets and exfil channels
        """
        data = {"target": target}
        if os_type:
            data["os_type"] = os_type
        logger.info(f"📦 Exfil pipeline for {target}")
        result = redvector_client.safe_post("api/autonomous/exfil-pipeline", data)
        if result.get("success"):
            logger.info(f"✅ Pipeline completed: {result.get('pipeline_stages', 0)} stages")
        else:
            logger.error(f"❌ Exfil pipeline failed")
        return result

    @mcp.tool()
    def autonomous_exfil_files(target: str, os_type: str = "") -> dict:
        """Harvest secrets from local files on the target system.

        Scans .env files, config files, SSH keys, token caches, backup files,
        private keys, and database files for embedded credentials and secrets.

        Args:
            target: Target system hostname/IP
            os_type: Target OS type (linux/windows, auto-detected if empty)

        Returns:
            All file categories scanned with secrets discovered in each
        """
        data = {"target": target}
        if os_type:
            data["os_type"] = os_type
        logger.info(f"📂 File harvesting for {target}")
        result = redvector_client.safe_post("api/autonomous/exfil-files", data)
        if result.get("success"):
            logger.info(f"✅ Found {result.get('total_secrets_found', 0)} secrets in files")
        else:
            logger.error(f"❌ File harvest failed")
        return result

    @mcp.tool()
    def autonomous_exfil_env(target: str) -> dict:
        """Extract secrets from environment variables on the target.

        Harvests cloud credentials, database credentials, API keys, auth secrets,
        and internal service tokens from the process environment.

        Args:
            target: Target system hostname/IP

        Returns:
            All environment variable categories with extracted secrets
        """
        data = {"target": target}
        logger.info(f"🔑 Environment extraction for {target}")
        result = redvector_client.safe_post("api/autonomous/exfil-env", data)
        if result.get("success"):
            logger.info(f"✅ Extracted {result.get('total_secrets_extracted', 0)} env secrets")
        else:
            logger.error(f"❌ Env extraction failed")
        return result

    @mcp.tool()
    def autonomous_exfil_cloud(target: str) -> dict:
        """Extract cloud credentials from metadata services and token endpoints.

        Queries AWS IMDS, Azure metadata, GCP metadata server, Kubernetes service
        account tokens, and Docker sockets for cloud IAM credentials.

        Args:
            target: Target system hostname/IP

        Returns:
            Cloud credential sources with extracted tokens and post-exploit capabilities
        """
        data = {"target": target}
        logger.info(f"☁️ Cloud credential extraction for {target}")
        result = redvector_client.safe_post("api/autonomous/exfil-cloud", data)
        if result.get("success"):
            logger.info(f"✅ Extracted {result.get('total_credentials_extracted', 0)} cloud credentials")
        else:
            logger.error(f"❌ Cloud credential extraction failed")
        return result

    @mcp.tool()
    def autonomous_exfil_memory(target: str, os_type: str = "") -> dict:
        """Dump secrets from process memory, swap, and credential stores.

        Extracts secrets from live process memory, swap/temp files, core dumps,
        and Windows credential stores (LSASS, Credential Manager, DPAPI).

        Args:
            target: Target system hostname/IP
            os_type: Target OS type (linux/windows, auto-detected if empty)

        Returns:
            Memory dump targets with extracted secrets from each source
        """
        data = {"target": target}
        if os_type:
            data["os_type"] = os_type
        logger.info(f"🧠 Memory dump for {target}")
        result = redvector_client.safe_post("api/autonomous/exfil-memory", data)
        if result.get("success"):
            logger.info(f"✅ Dumped {result.get('total_secrets_dumped', 0)} secrets from memory")
        else:
            logger.error(f"❌ Memory dump failed")
        return result

    # ========================================================================
    # System 12: Autonomous Lateral Movement Tools
    # ========================================================================

    @mcp.tool()
    def autonomous_lateral_pipeline(target: str, domain: str = "corp.local", username: str = "", password_or_hash: str = "") -> dict:
        """Run the full lateral movement pipeline across the internal network.

        Performs credential harvesting, network enumeration, target prioritization,
        lateral execution, credential extraction, propagation, and domain dominance
        assessment across 8 stages.

        Args:
            target: Initial compromised host IP/hostname
            domain: Active Directory domain name
            username: Compromised username for initial access
            password_or_hash: Password or NTLM hash for authentication

        Returns:
            Complete pipeline with movement chain, compromised hosts, and domain dominance status
        """
        data = {"target": target, "domain": domain}
        if username:
            data["username"] = username
        if password_or_hash:
            data["password_or_hash"] = password_or_hash
        logger.info(f"🕸️ Lateral movement pipeline for {target}")
        result = redvector_client.safe_post("api/autonomous/lateral-pipeline", data)
        if result.get("success"):
            logger.info(f"✅ Pipeline completed: {result.get('pipeline_stages', 0)} stages")
        else:
            logger.error(f"❌ Lateral pipeline failed")
        return result

    @mcp.tool()
    def autonomous_lateral_creds(target: str) -> dict:
        """Harvest credentials using password spraying, kerberoasting, AS-REP roasting.

        Executes credential reuse, credential stuffing, service account reuse,
        kerberoasting, and AS-REP roasting to collect authentication material.

        Args:
            target: Target system hostname/IP to harvest credentials from

        Returns:
            Credential harvesting results with techniques used and credentials found
        """
        data = {"target": target}
        logger.info(f"🔐 Credential harvesting for {target}")
        result = redvector_client.safe_post("api/autonomous/lateral-creds", data)
        if result.get("success"):
            logger.info(f"✅ Harvested {result.get('credentials_harvested', 0)} credentials")
        else:
            logger.error(f"❌ Credential harvest failed")
        return result

    @mcp.tool()
    def autonomous_lateral_enum(target: str, domain: str = "corp.local") -> dict:
        """Enumerate network via SMB/Active Directory reconnaissance.

        Discovers domain users, admin accounts, shared folders, domain controllers,
        trust relationships, and computer accounts across the domain.

        Args:
            target: Target domain controller or host IP
            domain: Active Directory domain name

        Returns:
            Network enumeration results with all discovered objects and relationships
        """
        data = {"target": target, "domain": domain}
        logger.info(f"🗺️ Network enumeration for {target}")
        result = redvector_client.safe_post("api/autonomous/lateral-enum", data)
        if result.get("success"):
            logger.info(f"✅ Discovered {result.get('total_objects_discovered', 0)} network objects")
        else:
            logger.error(f"❌ Network enumeration failed")
        return result

    @mcp.tool()
    def autonomous_lateral_protocols(target: str = "") -> dict:
        """List all available lateral movement protocols and execution methods.

        Enumerates PsExec, WMIExec, WinRM, SMBExec, SSH, RDP, and DCOM protocols
        with authentication methods, tools, and detection risk levels.

        Args:
            target: Optional target to contextualize protocol selection

        Returns:
            All lateral movement protocols with ports, auth methods, and tools
        """
        data = {}
        if target:
            data["target"] = target
        logger.info(f"📡 Listing lateral movement protocols")
        result = redvector_client.safe_post("api/autonomous/lateral-protocols", data)
        if result.get("success"):
            logger.info(f"✅ {result.get('total_protocols', 0)} protocols available")
        else:
            logger.error(f"❌ Protocol listing failed")
        return result

    @mcp.tool()
    def autonomous_lateral_hash(target: str = "") -> dict:
        """List all hash-based authentication techniques for lateral movement.

        Covers Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, NTLM Relay,
        and DCSync techniques with tools, prerequisites, and detection risk.

        Args:
            target: Optional target to contextualize technique selection

        Returns:
            All hash authentication techniques with tools and effectiveness ratings
        """
        data = {}
        if target:
            data["target"] = target
        logger.info(f"#️⃣ Hash authentication techniques")
        result = redvector_client.safe_post("api/autonomous/lateral-hash", data)
        if result.get("success"):
            logger.info(f"✅ {result.get('total_techniques', 0)} hash techniques available")
        else:
            logger.error(f"❌ Hash technique listing failed")
        return result

    # ================================================================
    # System 13: Autonomous OWASP Top 10 Engine - MCP Tools
    # ================================================================

    @mcp.tool()
    def autonomous_owasp_pipeline(target: str, categories: str = "") -> dict:
        """Full OWASP Top 10 scan and auto-exploit pipeline.
        Scans all 10 OWASP categories, auto-exploits findings, generates compliance score.
        Args: target - Target URL/host. categories - Comma-separated category list (optional).
        """
        logger.info(f"[OWASP] Full pipeline against {target}")
        payload = {"target": target}
        if categories:
            payload["categories"] = [c.strip() for c in categories.split(",")]
        result = redvector_client.safe_post("api/autonomous/owasp-pipeline", payload)
        if result.get("success"):
            logger.info(f"✅ {result.get('total_vulnerabilities', 0)} vulns, {result.get('total_exploits_successful', 0)} exploited")
        else:
            logger.error(f"❌ OWASP pipeline failed")
        return result

    @mcp.tool()
    def autonomous_owasp_scan(target: str, categories: str = "") -> dict:
        """Scan specific OWASP categories against a target.
        Args: target - Target URL/host. categories - Comma-separated category list (optional).
        """
        logger.info(f"[OWASP] Scanning {target}")
        payload = {"target": target}
        if categories:
            payload["categories"] = [c.strip() for c in categories.split(",")]
        result = redvector_client.safe_post("api/autonomous/owasp-scan", payload)
        if result.get("success"):
            logger.info(f"✅ {result.get('total_vulnerabilities', 0)} vulnerabilities found")
        else:
            logger.error(f"❌ OWASP scan failed")
        return result

    @mcp.tool()
    def autonomous_owasp_exploit(target: str, category: str = "") -> dict:
        """Auto-exploit discovered OWASP vulnerabilities.
        Args: target - Target URL/host. category - Specific category to exploit (optional).
        """
        logger.info(f"[OWASP] Auto-exploiting {target}")
        payload = {"target": target}
        if category:
            payload["category"] = category
        result = redvector_client.safe_post("api/autonomous/owasp-exploit", payload)
        if result.get("success"):
            logger.info(f"✅ {result.get('total_exploits_successful', 0)}/{result.get('total_exploits_attempted', 0)} exploits successful")
        else:
            logger.error(f"❌ OWASP exploit failed")
        return result

    @mcp.tool()
    def autonomous_owasp_report(target: str) -> dict:
        """Generate OWASP Top 10 compliance report.
        Args: target - Target URL/host.
        """
        logger.info(f"[OWASP] Generating compliance report for {target}")
        result = redvector_client.safe_post("api/autonomous/owasp-report", {"target": target})
        if result.get("success"):
            logger.info(f"✅ Compliance score: {result.get('compliance_score', 0)}%")
        else:
            logger.error(f"❌ OWASP report failed")
        return result

    @mcp.tool()
    def autonomous_owasp_remediate(target: str) -> dict:
        """Suggest remediations for OWASP vulnerabilities.
        Args: target - Target URL/host.
        """
        logger.info(f"[OWASP] Suggesting remediations for {target}")
        result = redvector_client.safe_post("api/autonomous/owasp-remediate", {"target": target})
        if result.get("success"):
            logger.info(f"✅ {result.get('total_remediation_items', 0)} remediation items")
        else:
            logger.error(f"❌ OWASP remediation failed")
        return result

    # ================================================================
    # System 14: Autonomous Cloud Infrastructure Attack - MCP Tools
    # ================================================================

    @mcp.tool()
    def autonomous_cloud_pipeline(target: str, provider: str = "") -> dict:
        """Full cloud infrastructure attack pipeline (AWS/Azure/GCP).
        8-stage pipeline: recon, IAM enum, privesc, storage, serverless, container, IaC, pivot.
        Args: target - Cloud target. provider - aws/azure/gcp (auto-detected if empty).
        """
        logger.info(f"[CLOUD] Full pipeline against {target}")
        payload = {"target": target}
        if provider:
            payload["provider"] = provider
        result = redvector_client.safe_post("api/autonomous/cloud-pipeline", payload)
        if result.get("success"):
            logger.info(f"✅ Cloud pipeline complete, provider: {result.get('provider', 'unknown')}")
        else:
            logger.error(f"❌ Cloud pipeline failed")
        return result

    @mcp.tool()
    def autonomous_cloud_iam(target: str, provider: str = "") -> dict:
        """Enumerate IAM policies, roles, and permissions.
        Args: target - Cloud target. provider - aws/azure/gcp (auto-detected if empty).
        """
        logger.info(f"[CLOUD] IAM enumeration on {target}")
        payload = {"target": target}
        if provider:
            payload["provider"] = provider
        result = redvector_client.safe_post("api/autonomous/cloud-iam", payload)
        if result.get("success"):
            logger.info(f"✅ {result.get('total_identities', 0)} identities discovered")
        else:
            logger.error(f"❌ Cloud IAM enum failed")
        return result

    @mcp.tool()
    def autonomous_cloud_storage(target: str, provider: str = "") -> dict:
        """Enumerate and exploit cloud storage (S3/Blobs/GCS).
        Args: target - Cloud target. provider - aws/azure/gcp (auto-detected if empty).
        """
        logger.info(f"[CLOUD] Storage attack on {target}")
        payload = {"target": target}
        if provider:
            payload["provider"] = provider
        result = redvector_client.safe_post("api/autonomous/cloud-storage", payload)
        if result.get("success"):
            logger.info(f"✅ {result.get('total_objects_accessed', 0)} objects accessed")
        else:
            logger.error(f"❌ Cloud storage attack failed")
        return result

    @mcp.tool()
    def autonomous_cloud_serverless(target: str, provider: str = "") -> dict:
        """Hijack serverless functions (Lambda/Azure Functions/Cloud Functions).
        Args: target - Cloud target. provider - aws/azure/gcp (auto-detected if empty).
        """
        logger.info(f"[CLOUD] Serverless hijack on {target}")
        payload = {"target": target}
        if provider:
            payload["provider"] = provider
        result = redvector_client.safe_post("api/autonomous/cloud-serverless", payload)
        if result.get("success"):
            logger.info(f"✅ {result.get('total_functions_compromised', 0)} functions hijacked")
        else:
            logger.error(f"❌ Cloud serverless hijack failed")
        return result

    @mcp.tool()
    def autonomous_cloud_container(target: str) -> dict:
        """Container escape and Kubernetes cluster takeover.
        Args: target - Container/K8s target.
        """
        logger.info(f"[CLOUD] Container escape on {target}")
        result = redvector_client.safe_post("api/autonomous/cloud-container", {"target": target})
        if result.get("success"):
            logger.info(f"✅ {result.get('escapes_successful', 0)} escape vectors, cluster compromised: {result.get('cluster_compromised', False)}")
        else:
            logger.error(f"❌ Container escape failed")
        return result

    # ================================================================
    # System 15: Autonomous Zero-Day Fuzzing & Exploit Dev - MCP Tools
    # ================================================================

    @mcp.tool()
    def autonomous_fuzz_pipeline(target: str, protocol: str = "", strategy: str = "") -> dict:
        """Full zero-day fuzzing and exploit development pipeline.
        8-stage pipeline: analysis, harness, fuzzing, triage, RCA, exploit dev, weaponization, delivery.
        Args: target - Fuzzing target. protocol - http/dns/smb/ssh/tls/mqtt/grpc/ftp (auto-detected). strategy - Fuzzing strategy (optional).
        """
        logger.info(f"[FUZZ] Full pipeline against {target}")
        payload = {"target": target}
        if protocol:
            payload["protocol"] = protocol
        if strategy:
            payload["strategy"] = strategy
        result = redvector_client.safe_post("api/autonomous/fuzz-pipeline", payload)
        if result.get("success"):
            logger.info(f"✅ {result.get('zero_days_found', 0)} zero-days, {result.get('exploits_developed', 0)} exploits")
        else:
            logger.error(f"❌ Fuzz pipeline failed")
        return result

    @mcp.tool()
    def autonomous_fuzz_strategies(target: str = "") -> dict:
        """List all available fuzzing strategies.
        Args: target - Optional target for context.
        """
        logger.info(f"[FUZZ] Listing fuzzing strategies")
        payload = {}
        if target:
            payload["target"] = target
        result = redvector_client.safe_post("api/autonomous/fuzz-strategies", payload)
        if result.get("success"):
            logger.info(f"✅ {result.get('total_strategies', 0)} strategies available")
        else:
            logger.error(f"❌ Fuzz strategy listing failed")
        return result

    @mcp.tool()
    def autonomous_fuzz_crashes(target: str = "") -> dict:
        """List all crash/vulnerability categories and exploitability.
        Args: target - Optional target for context.
        """
        logger.info(f"[FUZZ] Listing crash categories")
        payload = {}
        if target:
            payload["target"] = target
        result = redvector_client.safe_post("api/autonomous/fuzz-crashes", payload)
        if result.get("success"):
            logger.info(f"✅ {result.get('total_categories', 0)} crash categories")
        else:
            logger.error(f"❌ Fuzz crash listing failed")
        return result

    @mcp.tool()
    def autonomous_fuzz_protocols(target: str = "") -> dict:
        """List all supported protocol fuzzing targets.
        Args: target - Optional target for context.
        """
        logger.info(f"[FUZZ] Listing fuzzing protocols")
        payload = {}
        if target:
            payload["target"] = target
        result = redvector_client.safe_post("api/autonomous/fuzz-protocols", payload)
        if result.get("success"):
            logger.info(f"✅ {result.get('total_protocols', 0)} protocols supported")
        else:
            logger.error(f"❌ Fuzz protocol listing failed")
        return result

    @mcp.tool()
    def autonomous_fuzz_analyze(target: str, crash_type: str = "") -> dict:
        """Analyze a crash type and determine exploitability.
        Args: target - Target application. crash_type - Specific crash type (optional).
        """
        logger.info(f"[FUZZ] Crash analysis for {target}")
        payload = {"target": target}
        if crash_type:
            payload["crash_type"] = crash_type
        result = redvector_client.safe_post("api/autonomous/fuzz-analyze", payload)
        if result.get("success"):
            logger.info(f"✅ {result.get('crashes_analyzed', 0)} crashes analyzed, {result.get('exploitable_count', 0)} exploitable")
        else:
            logger.error(f"❌ Fuzz analysis failed")
        return result

    # ========================================================================
    # CCTV / IP CAMERA PENTESTING TOOLS
    # ========================================================================

    @mcp.tool()
    def cctv_discovery(target: str, scan_type: str = "quick", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Discover and fingerprint CCTV/IP cameras on a network.

        Scans for common camera ports (80, 443, 554, 8080, 37777, 34567, etc.)
        and fingerprints manufacturer/model from service banners.

        Args:
            target: IP address, CIDR range, or hostname to scan
            scan_type: Scan mode - 'quick' (fast open ports), 'deep' (scripts + RTSP brute), 'stealth' (slow SYN scan)
            ports: Custom port list (comma-separated). Defaults to common camera ports.
            additional_args: Extra nmap arguments

        Returns:
            Discovered cameras with open ports, manufacturer guess, RTSP paths, and known CVEs
        """
        data = {"target": target, "scan_type": scan_type}
        if ports:
            data["ports"] = ports
        if additional_args:
            data["additional_args"] = additional_args
        logger.info(f"📹 CCTV Discovery scan: {target} (mode={scan_type})")
        result = redvector_client.safe_post("api/tools/cctv-discovery", data)
        if result.get("success"):
            logger.info(f"✅ Found {result.get('total_cameras_found', 0)} cameras on {target}")
        else:
            logger.error(f"❌ CCTV Discovery failed for {target}")
        return result

    @mcp.tool()
    def cctv_default_creds(target: str, manufacturer: str = "generic", port: int = 80, protocol: str = "http", services: list = None, additional_args: str = "") -> Dict[str, Any]:
        """
        Audit CCTV/IP cameras for default credentials.

        Tests known default username/password pairs per manufacturer against
        HTTP basic/digest auth, RTSP, and SSH services.

        Args:
            target: IP or hostname of the camera
            manufacturer: Camera manufacturer (hikvision, dahua, axis, reolink, amcrest, foscam, generic)
            port: HTTP port for web interface (default: 80)
            protocol: Protocol for web UI (http or https)
            services: List of services to test (http, rtsp, ssh). Defaults to ['http'].
            additional_args: Extra arguments for hydra/nmap

        Returns:
            Credential audit results per service with full credential list tested
        """
        data = {"target": target, "manufacturer": manufacturer, "port": port, "protocol": protocol}
        if services:
            data["services"] = services
        if additional_args:
            data["additional_args"] = additional_args
        logger.info(f"🔑 CCTV Default Credential audit: {target} (mfg={manufacturer})")
        result = redvector_client.safe_post("api/tools/cctv-default-creds", data)
        if result.get("success"):
            logger.info(f"✅ Tested {result.get('credentials_tested', 0)} credential pairs on {target}")
        else:
            logger.error(f"❌ CCTV credential audit failed for {target}")
        return result

    @mcp.tool()
    def cctv_rtsp_probe(target: str, port: int = 554, manufacturer: str = "generic", paths: list = None, additional_args: str = "") -> Dict[str, Any]:
        """
        Probe RTSP streams on IP cameras for unauthenticated or default-credential access.

        Tests known RTSP paths per manufacturer using ffprobe and nmap RTSP scripts.

        Args:
            target: IP or hostname of the camera
            port: RTSP port (default: 554)
            manufacturer: Camera manufacturer for path selection (hikvision, dahua, axis, etc.)
            paths: Custom RTSP paths to test (in addition to manufacturer defaults)
            additional_args: Extra nmap arguments

        Returns:
            Unauthenticated streams, default-cred streams, and risk level
        """
        data = {"target": target, "port": port, "manufacturer": manufacturer}
        if paths:
            data["paths"] = paths
        if additional_args:
            data["additional_args"] = additional_args
        logger.info(f"📡 RTSP Probe: rtsp://{target}:{port} (mfg={manufacturer})")
        result = redvector_client.safe_post("api/tools/cctv-rtsp-probe", data)
        if result.get("success"):
            unauth = result.get("unauthenticated_count", 0)
            defcred = result.get("default_credential_count", 0)
            logger.info(f"✅ RTSP Probe: {unauth} unauthenticated, {defcred} default-cred streams")
        else:
            logger.error(f"❌ RTSP Probe failed for {target}")
        return result

    @mcp.tool()
    def cctv_firmware_cve(target: str, manufacturer: str = "", firmware_version: str = "", port: int = 80, additional_args: str = "") -> Dict[str, Any]:
        """
        Identify camera firmware and map against known CVEs.

        Uses nmap fingerprinting, nuclei IoT/camera templates, and searchsploit
        lookups plus a built-in CVE database for major manufacturers.

        Args:
            target: IP or hostname of the camera
            manufacturer: Known manufacturer (hikvision, dahua, axis, etc.) or empty to auto-detect
            firmware_version: Known firmware version string (optional)
            port: HTTP port for web interface (default: 80)
            additional_args: Extra nuclei arguments

        Returns:
            Known CVEs, nuclei scan results, searchsploit matches, and nmap fingerprint
        """
        data = {"target": target, "port": port}
        if manufacturer:
            data["manufacturer"] = manufacturer
        if firmware_version:
            data["firmware_version"] = firmware_version
        if additional_args:
            data["additional_args"] = additional_args
        logger.info(f"🔍 CCTV Firmware CVE scan: {target} (mfg={manufacturer or 'auto'})")
        result = redvector_client.safe_post("api/tools/cctv-firmware-cve", data)
        if result.get("success"):
            logger.info(f"✅ Found {result.get('known_cve_count', 0)} known CVEs for {target}")
        else:
            logger.error(f"❌ CCTV Firmware CVE scan failed for {target}")
        return result

    @mcp.tool()
    def cctv_config_audit(target: str, port: int = 80, additional_args: str = "") -> Dict[str, Any]:
        """
        Audit IP camera configuration and network exposure.

        Checks for ONVIF discovery, UPnP/SSDP, Telnet backdoors, unencrypted
        management (HTTP vs HTTPS), and SSH exposure.

        Args:
            target: IP or hostname of the camera
            port: HTTP port for web management (default: 80)
            additional_args: Extra nmap arguments

        Returns:
            Audit findings with risk levels per check and overall risk assessment
        """
        data = {"target": target, "port": port}
        if additional_args:
            data["additional_args"] = additional_args
        logger.info(f"⚙️ CCTV Config Audit: {target}")
        result = redvector_client.safe_post("api/tools/cctv-config-audit", data)
        if result.get("success"):
            logger.info(f"✅ Config audit complete: overall risk = {result.get('overall_risk', 'unknown')}")
        else:
            logger.error(f"❌ CCTV Config Audit failed for {target}")
        return result

    # ── Autonomous CCTV Systems (5 engines, 13 routes) ──────────────────

    @mcp.tool()
    def autonomous_cctv_pipeline(target: str, stealth_level: str = "normal", ports: str = "") -> Dict[str, Any]:
        """
        Run a full 8-stage autonomous CCTV assessment pipeline.

        Stages: discovery → fingerprint → default-cred audit → RTSP probe →
        firmware CVE scan → config audit → risk consolidation → final report.

        Args:
            target: IP, hostname, or CIDR range of the camera(s)
            stealth_level: Scan intensity - quiet, normal, or aggressive
            ports: Comma-separated ports to scan (empty = common camera ports)

        Returns:
            Full pipeline results with per-stage findings and overall risk score
        """
        data: Dict[str, Any] = {"target": target, "stealth_level": stealth_level}
        if ports:
            data["ports"] = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
        logger.info(f"🎯 CCTV Full Pipeline: {target} (stealth={stealth_level})")
        result = redvector_client.safe_post("api/autonomous/cctv-pipeline", data)
        if result.get("success"):
            logger.info(f"✅ Pipeline complete for {target} - stages: {result.get('stages_completed', '?')}")
        else:
            logger.error(f"❌ CCTV pipeline failed for {target}")
        return result

    @mcp.tool()
    def autonomous_cctv_quick_scan(target: str) -> Dict[str, Any]:
        """
        Quick CCTV scan - discovery and fingerprint only.

        Runs only the first two pipeline stages for rapid reconnaissance.

        Args:
            target: IP, hostname, or CIDR range of the camera(s)

        Returns:
            Discovery results and fingerprint data
        """
        data = {"target": target}
        logger.info(f"⚡ CCTV Quick Scan: {target}")
        result = redvector_client.safe_post("api/autonomous/cctv-quick-scan", data)
        if result.get("success"):
            logger.info(f"✅ Quick scan complete for {target}")
        else:
            logger.error(f"❌ CCTV quick scan failed for {target}")
        return result

    @mcp.tool()
    def autonomous_cctv_segmentation(target: str, corporate_ranges: str = "", gateway: str = "") -> Dict[str, Any]:
        """
        Analyze camera network segmentation from corporate networks.

        Checks reachability of sensitive services (SMB, RDP, LDAP, Kerberos,
        databases) from the camera's network to assess isolation.

        Args:
            target: IP of the camera or camera subnet
            corporate_ranges: Comma-separated corporate IP ranges to test against
            gateway: Gateway IP to check routing through

        Returns:
            Segmentation findings, reachable services, and best-practice comparison
        """
        data: Dict[str, Any] = {"target": target}
        if corporate_ranges:
            data["corporate_ranges"] = [r.strip() for r in corporate_ranges.split(",") if r.strip()]
        if gateway:
            data["gateway"] = gateway
        logger.info(f"🔒 CCTV Segmentation Analysis: {target}")
        result = redvector_client.safe_post("api/autonomous/cctv-segmentation", data)
        if result.get("success"):
            logger.info(f"✅ Segmentation analysis complete for {target}")
        else:
            logger.error(f"❌ CCTV segmentation analysis failed for {target}")
        return result

    @mcp.tool()
    def autonomous_cctv_segmentation_services() -> Dict[str, Any]:
        """
        List sensitive services checked during segmentation analysis.

        Returns:
            Service names, ports, and descriptions
        """
        logger.info("📋 Listing CCTV segmentation sensitive services")
        result = redvector_client.safe_post("api/autonomous/cctv-segmentation-services", {})
        return result

    @mcp.tool()
    def autonomous_cctv_onvif_enum(target: str, port: int = 80, username: str = "admin", password: str = "admin") -> Dict[str, Any]:
        """
        Deep ONVIF protocol enumeration of an IP camera.

        Probes device info, user list, network config, PTZ capabilities,
        media profiles, and WS-Discovery endpoints.

        Args:
            target: IP or hostname of the camera
            port: ONVIF service port (default: 80)
            username: ONVIF username (default: admin)
            password: ONVIF password (default: admin)

        Returns:
            Enumerated ONVIF data by action category
        """
        data = {"target": target, "port": port, "username": username, "password": password}
        logger.info(f"📡 ONVIF Enumeration: {target}:{port}")
        result = redvector_client.safe_post("api/autonomous/cctv-onvif-enum", data)
        if result.get("success"):
            logger.info(f"✅ ONVIF enumeration complete for {target}")
        else:
            logger.error(f"❌ ONVIF enumeration failed for {target}")
        return result

    @mcp.tool()
    def autonomous_cctv_onvif_actions() -> Dict[str, Any]:
        """
        List all ONVIF actions available for enumeration.

        Returns:
            ONVIF action names, paths, and descriptions
        """
        logger.info("📋 Listing ONVIF actions")
        result = redvector_client.safe_post("api/autonomous/cctv-onvif-actions", {})
        return result

    @mcp.tool()
    def autonomous_cctv_scorecard(target: str, assessment_data: str = "") -> Dict[str, Any]:
        """
        Generate a weighted CCTV exposure scorecard with compliance mapping.

        Scores 8 dimensions (default creds, firmware, encryption, segmentation,
        RTSP, firmware age, ONVIF, physical) and maps to NIST CSF, ISO 27001,
        PCI DSS frameworks.

        Args:
            target: IP or hostname of the camera
            assessment_data: JSON string of prior assessment data to enrich scoring (optional)

        Returns:
            Per-dimension scores, overall risk rating, compliance mapping, remediation priorities
        """
        data: Dict[str, Any] = {"target": target}
        if assessment_data:
            import json as _json
            try:
                data["assessment_data"] = _json.loads(assessment_data)
            except _json.JSONDecodeError:
                data["assessment_data"] = {}
        logger.info(f"📊 CCTV Exposure Scorecard: {target}")
        result = redvector_client.safe_post("api/autonomous/cctv-scorecard", data)
        if result.get("success"):
            logger.info(f"✅ Scorecard generated: overall = {result.get('overall_risk', 'unknown')}")
        else:
            logger.error(f"❌ CCTV scorecard failed for {target}")
        return result

    @mcp.tool()
    def autonomous_cctv_scorecard_dimensions() -> Dict[str, Any]:
        """
        List all scoring dimensions and compliance frameworks.

        Returns:
            Dimension names, weights, and linked compliance frameworks
        """
        logger.info("📋 Listing CCTV scorecard dimensions")
        result = redvector_client.safe_post("api/autonomous/cctv-scorecard-dimensions", {})
        return result

    @mcp.tool()
    def autonomous_cctv_stream_analyze(target: str, port: int = 554, manufacturer: str = "generic", paths: str = "") -> Dict[str, Any]:
        """
        Analyze RTSP/HTTP streams - codec, resolution, encryption, and security findings.

        Enumerates available streams, detects codecs (H.264/H.265/MJPEG),
        checks for encryption, and reports security findings.

        Args:
            target: IP or hostname of the camera
            port: RTSP port (default: 554)
            manufacturer: Camera manufacturer for path selection (default: generic)
            paths: Comma-separated RTSP paths to probe (empty = auto-detect)

        Returns:
            Stream details, codec info, resolution, encryption status, security findings
        """
        data: Dict[str, Any] = {"target": target, "port": port, "manufacturer": manufacturer}
        if paths:
            data["paths"] = [p.strip() for p in paths.split(",") if p.strip()]
        logger.info(f"🎬 CCTV Stream Analysis: {target}:{port}")
        result = redvector_client.safe_post("api/autonomous/cctv-stream-analyze", data)
        if result.get("success"):
            logger.info(f"✅ Stream analysis complete for {target}")
        else:
            logger.error(f"❌ CCTV stream analysis failed for {target}")
        return result

    @mcp.tool()
    def autonomous_cctv_stream_evidence(target: str, port: int = 554, path: str = "/Streaming/Channels/1", duration: int = 5) -> Dict[str, Any]:
        """
        Capture stream evidence snapshot for pentest documentation.

        Records a brief segment of the stream metadata and packet analysis
        as proof-of-access for the engagement report.

        Args:
            target: IP or hostname of the camera
            port: RTSP port (default: 554)
            path: RTSP stream path (default: /Streaming/Channels/1)
            duration: Capture duration in seconds (default: 5)

        Returns:
            Evidence metadata, timestamps, stream characteristics
        """
        data = {"target": target, "port": port, "path": path, "duration": duration}
        logger.info(f"📸 CCTV Evidence Capture: {target}:{port}{path} ({duration}s)")
        result = redvector_client.safe_post("api/autonomous/cctv-stream-evidence", data)
        if result.get("success"):
            logger.info(f"✅ Evidence captured for {target}")
        else:
            logger.error(f"❌ CCTV evidence capture failed for {target}")
        return result

    @mcp.tool()
    def autonomous_cctv_stream_protocols() -> Dict[str, Any]:
        """
        List supported streaming protocols and codecs.

        Returns:
            Protocol names, default ports, and supported codec list
        """
        logger.info("📋 Listing CCTV stream protocols")
        result = redvector_client.safe_post("api/autonomous/cctv-stream-protocols", {})
        return result

    # ── Autonomous CCTV Anti-Lockout Engine (7 routes) ──────────────────

    @mcp.tool()
    def autonomous_cctv_antilockout_spray(target: str, manufacturer: str = "generic", proxies: str = "", max_per_ip: int = 2) -> Dict[str, Any]:
        """
        Distributed source rotation credential spray to bypass IP lockout.

        Rotates source IPs across SOCKS proxies so each IP stays under the
        camera's lockout threshold (e.g., 2 attempts per IP, then rotate).

        Args:
            target: IP or hostname of the camera
            manufacturer: Camera manufacturer (hikvision, dahua, axis, etc.)
            proxies: Comma-separated SOCKS5 proxy addresses (empty = direct only)
            max_per_ip: Maximum login attempts per source IP (default: 2)

        Returns:
            Spray results, successful logins, batch schedule, and lockout policy
        """
        data: Dict[str, Any] = {"target": target, "manufacturer": manufacturer, "max_per_ip": max_per_ip}
        if proxies:
            data["proxies"] = [p.strip() for p in proxies.split(",") if p.strip()]
        logger.info(f"🔄 Anti-Lockout Spray: {target} (mfg={manufacturer}, max_per_ip={max_per_ip})")
        result = redvector_client.safe_post("api/autonomous/cctv-antilockout-spray", data)
        if result.get("success"):
            logger.info(f"✅ Spray complete: {result.get('successful_count', 0)} hits from {result.get('credentials_tested', 0)} tested")
        else:
            logger.error(f"❌ Anti-lockout spray failed for {target}")
        return result

    @mcp.tool()
    def autonomous_cctv_antilockout_throttle(target: str, manufacturer: str = "generic", max_attempts: int = 10) -> Dict[str, Any]:
        """
        Low-and-slow timing-aware credential throttle.

        Spaces login attempts just under the camera's lockout threshold with
        adaptive cooldowns between batches.

        Args:
            target: IP or hostname of the camera
            manufacturer: Camera manufacturer for policy lookup
            max_attempts: Maximum total attempts to schedule (default: 10)

        Returns:
            Attempt schedule with cooldown timings, first batch results, policy details
        """
        data = {"target": target, "manufacturer": manufacturer, "max_attempts": max_attempts}
        logger.info(f"⏱️ Anti-Lockout Throttle: {target} (mfg={manufacturer}, max={max_attempts})")
        result = redvector_client.safe_post("api/autonomous/cctv-antilockout-throttle", data)
        if result.get("success"):
            logger.info(f"✅ Throttle schedule: {result.get('total_batches', 0)} batches, ~{result.get('estimated_total_time_seconds', 0)}s total")
        else:
            logger.error(f"❌ Anti-lockout throttle failed for {target}")
        return result

    @mcp.tool()
    def autonomous_cctv_antilockout_crossproto(target: str, manufacturer: str = "generic", port: int = 80) -> Dict[str, Any]:
        """
        Cross-protocol credential testing on independent auth endpoints.

        Tests credentials on RTSP, ONVIF, Telnet, SSH, SNMP - protocols that
        often have separate (or no) lockout counters from HTTP web login.

        Args:
            target: IP or hostname of the camera
            manufacturer: Camera manufacturer for policy lookup
            port: Primary HTTP port (default: 80)

        Returns:
            Per-protocol availability, credential test results, successful logins
        """
        data = {"target": target, "manufacturer": manufacturer, "port": port}
        logger.info(f"🔀 Anti-Lockout Cross-Protocol: {target} (mfg={manufacturer})")
        result = redvector_client.safe_post("api/autonomous/cctv-antilockout-crossproto", data)
        if result.get("success"):
            logger.info(f"✅ Cross-protocol: {result.get('protocols_independent', 0)} independent protocols, {result.get('successful_count', 0)} hits")
        else:
            logger.error(f"❌ Anti-lockout cross-protocol failed for {target}")
        return result

    @mcp.tool()
    def autonomous_cctv_antilockout_fingerprint(target: str, manufacturer: str = "generic", port: int = 80) -> Dict[str, Any]:
        """
        Fingerprint lockout policy, find bypass CVEs, and test reset vectors.

        Probes the exact lockout behavior, checks for known authentication
        bypass CVEs, and identifies reset vectors (ONVIF reboot, UPnP, config leaks).

        Args:
            target: IP or hostname of the camera
            manufacturer: Camera manufacturer (or 'generic' to auto-detect)
            port: HTTP port (default: 80)

        Returns:
            Actual lockout threshold, bypass CVEs, reset vectors, config leak endpoints
        """
        data = {"target": target, "manufacturer": manufacturer, "port": port}
        logger.info(f"🔍 Anti-Lockout Fingerprint: {target} (mfg={manufacturer})")
        result = redvector_client.safe_post("api/autonomous/cctv-antilockout-fingerprint", data)
        if result.get("success"):
            bypasses = result.get("bypass_cve_count", 0)
            leaks = result.get("config_leak_count", 0)
            logger.info(f"✅ Fingerprint: threshold={result.get('actual_lockout_threshold', '?')}, {bypasses} bypass CVEs, {leaks} config leaks")
        else:
            logger.error(f"❌ Anti-lockout fingerprint failed for {target}")
        return result

    @mcp.tool()
    def autonomous_cctv_antilockout_passive(target: str, manufacturer: str = "generic", port: int = 80, duration: int = 30) -> Dict[str, Any]:
        """
        Passive credential harvesting - zero login attempts, zero lockout risk.

        Extracts credentials from config backup endpoints, firmware dumps,
        UPnP descriptions, unauthenticated RTSP streams, and HTTP headers.

        Args:
            target: IP or hostname of the camera
            manufacturer: Camera manufacturer for targeted endpoint lists
            port: HTTP port (default: 80)
            duration: Suggested sniff duration in seconds (default: 30)

        Returns:
            Harvested credentials, passive findings, sniff commands for manual use
        """
        data = {"target": target, "manufacturer": manufacturer, "port": port, "duration": duration}
        logger.info(f"🕵️ Anti-Lockout Passive Harvest: {target} (mfg={manufacturer})")
        result = redvector_client.safe_post("api/autonomous/cctv-antilockout-passive", data)
        if result.get("success"):
            logger.info(f"✅ Passive harvest: {result.get('total_credentials_harvested', 0)} creds, {result.get('total_findings', 0)} findings")
        else:
            logger.error(f"❌ Anti-lockout passive harvest failed for {target}")
        return result

    @mcp.tool()
    def autonomous_cctv_antilockout_strategies() -> Dict[str, Any]:
        """
        List all anti-lockout strategies with descriptions and risk levels.

        Returns:
            Strategy names, descriptions, lockout risk levels, and route paths
        """
        logger.info("📋 Listing CCTV anti-lockout strategies")
        result = redvector_client.safe_post("api/autonomous/cctv-antilockout-strategies", {})
        return result

    @mcp.tool()
    def autonomous_cctv_antilockout_policies() -> Dict[str, Any]:
        """
        List known manufacturer lockout policies (threshold, duration, scope).

        Returns:
            Per-manufacturer lockout thresholds, windows, durations, and known bypass CVEs
        """
        logger.info("📋 Listing CCTV lockout policies")
        result = redvector_client.safe_post("api/autonomous/cctv-antilockout-policies", {})
        return result

    # ========================================================================
    # SYSTEM 22: FIRMWARE BACKDOOR & SUPPLY CHAIN ATTACK ENGINE
    # ========================================================================

    @mcp.tool()
    def autonomous_cctv_firmware_backdoor_scan(target: str, manufacturer: str = "generic", port: int = 80) -> Dict[str, Any]:
        """
        Scan camera for known manufacturer backdoors (magic strings, auth bypasses, hidden accounts).

        Args:
            target: Target camera IP or hostname
            manufacturer: Camera manufacturer (hikvision, dahua, axis, generic)
            port: HTTP port (default 80)

        Returns:
            Backdoor vectors tested, vulnerabilities found, critical findings
        """
        logger.info(f"🔓 Scanning firmware backdoors on {target}")
        result = redvector_client.safe_post("api/autonomous/cctv-firmware-backdoor-scan", {"target": target, "manufacturer": manufacturer, "port": port})
        return result

    @mcp.tool()
    def autonomous_cctv_firmware_debug_ports(target: str) -> Dict[str, Any]:
        """
        Scan for hidden debug interfaces and diagnostic ports on camera.

        Args:
            target: Target camera IP or hostname

        Returns:
            Debug ports scanned, open ports found, service banners
        """
        logger.info(f"🔍 Scanning debug ports on {target}")
        result = redvector_client.safe_post("api/autonomous/cctv-firmware-debug-ports", {"target": target})
        return result

    @mcp.tool()
    def autonomous_cctv_firmware_extract_creds(target: str, manufacturer: str = "generic", port: int = 80) -> Dict[str, Any]:
        """
        Extract hardcoded credentials from firmware/config download endpoints.

        Args:
            target: Target camera IP or hostname
            manufacturer: Camera manufacturer (hikvision, dahua, axis, generic)
            port: HTTP port (default 80)

        Returns:
            Endpoints probed, credentials extracted, firmware patterns matched
        """
        logger.info(f"🔑 Extracting firmware credentials from {target}")
        result = redvector_client.safe_post("api/autonomous/cctv-firmware-extract-creds", {"target": target, "manufacturer": manufacturer, "port": port})
        return result

    @mcp.tool()
    def autonomous_cctv_firmware_supply_chain(target: str, manufacturer: str = "generic", port: int = 80) -> Dict[str, Any]:
        """
        Check for supply chain compromise indicators (rogue certs, modified firmware, proxy configs).

        Args:
            target: Target camera IP or hostname
            manufacturer: Camera manufacturer (hikvision, dahua, axis, generic)
            port: HTTP port (default 80)

        Returns:
            Indicators checked, compromise detections, risk level assessment
        """
        logger.info(f"🔗 Checking supply chain integrity on {target}")
        result = redvector_client.safe_post("api/autonomous/cctv-firmware-supply-chain", {"target": target, "manufacturer": manufacturer, "port": port})
        return result

    @mcp.tool()
    def autonomous_cctv_firmware_backdoors_list() -> Dict[str, Any]:
        """
        List all known firmware backdoor vectors, debug ports, and supply chain indicators.

        Returns:
            Backdoor vectors by manufacturer, debug ports, firmware credential patterns
        """
        logger.info("📋 Listing firmware backdoor vectors")
        result = redvector_client.safe_post("api/autonomous/cctv-firmware-backdoors-list", {})
        return result

    # ========================================================================
    # SYSTEM 23: CLOUD & P2P TUNNEL EXPLOITATION ENGINE
    # ========================================================================

    @mcp.tool()
    def autonomous_cctv_cloud_p2p_scan(target: str, manufacturer: str = "generic") -> Dict[str, Any]:
        """
        Scan for active P2P/cloud relay protocols (ThroughTek Kalay, Hik-Connect, DMSS).

        Args:
            target: Target camera IP or hostname
            manufacturer: Camera manufacturer (hikvision, dahua, generic)

        Returns:
            P2P protocols detected, cloud indicators, active protocols list
        """
        logger.info(f"☁️ Scanning P2P protocols on {target}")
        result = redvector_client.safe_post("api/autonomous/cctv-cloud-p2p-scan", {"target": target, "manufacturer": manufacturer})
        return result

    @mcp.tool()
    def autonomous_cctv_cloud_p2p_uid_enum(target: str, manufacturer: str = "generic", uid_prefix: str = None, sample_size: int = 10) -> Dict[str, Any]:
        """
        Enumerate P2P UIDs for the target camera platform.

        Args:
            target: Target camera IP or hostname
            manufacturer: Camera manufacturer (hikvision, dahua, generic)
            uid_prefix: Optional UID prefix to use for enumeration
            sample_size: Number of UIDs to generate/test (default 10)

        Returns:
            UIDs generated and tested, resolution results, UID patterns
        """
        logger.info(f"🔢 Enumerating P2P UIDs for {target}")
        payload = {"target": target, "manufacturer": manufacturer, "sample_size": sample_size}
        if uid_prefix:
            payload["uid_prefix"] = uid_prefix
        result = redvector_client.safe_post("api/autonomous/cctv-cloud-p2p-uid-enum", payload)
        return result

    @mcp.tool()
    def autonomous_cctv_cloud_p2p_api_test(target: str, manufacturer: str = "generic", port: int = 80) -> Dict[str, Any]:
        """
        Test cloud API endpoints for authentication weaknesses and unauthenticated access.

        Args:
            target: Target camera IP or hostname
            manufacturer: Camera manufacturer (hikvision, dahua, generic)
            port: HTTP port (default 80)

        Returns:
            API endpoints tested, unauthenticated endpoints found, detailed results
        """
        logger.info(f"🌐 Testing cloud API on {target}")
        result = redvector_client.safe_post("api/autonomous/cctv-cloud-p2p-api-test", {"target": target, "manufacturer": manufacturer, "port": port})
        return result

    @mcp.tool()
    def autonomous_cctv_cloud_p2p_intercept(target: str, duration: int = 30) -> Dict[str, Any]:
        """
        Generate P2P tunnel interception commands for traffic capture and analysis.

        Args:
            target: Target camera IP or hostname
            duration: Capture duration in seconds (default 30)

        Returns:
            Intercept commands for tcpdump/wireshark, tunnel capture strategies
        """
        logger.info(f"📡 Generating P2P intercept commands for {target}")
        result = redvector_client.safe_post("api/autonomous/cctv-cloud-p2p-intercept", {"target": target, "duration": duration})
        return result

    @mcp.tool()
    def autonomous_cctv_cloud_p2p_providers() -> Dict[str, Any]:
        """
        List all known P2P protocols, cloud APIs, and UID patterns.

        Returns:
            P2P protocol details, cloud API endpoints, UID brute-force patterns
        """
        logger.info("📋 Listing P2P/cloud providers")
        result = redvector_client.safe_post("api/autonomous/cctv-cloud-p2p-providers", {})
        return result

    # ========================================================================
    # SYSTEM 24: VIDEO FEED TAMPERING & PTZ HIJACK ENGINE
    # ========================================================================

    @mcp.tool()
    def autonomous_cctv_video_tamper_ptz_hijack(target: str, manufacturer: str = "generic", port: int = 80) -> Dict[str, Any]:
        """
        Attempt PTZ control hijack to redirect camera view away from target area.

        Args:
            target: Target camera IP or hostname
            manufacturer: Camera manufacturer (hikvision, dahua, onvif, generic)
            port: HTTP port (default 80)

        Returns:
            PTZ actions tested, accessible controls, hijack feasibility
        """
        logger.info(f"🎯 Attempting PTZ hijack on {target}")
        result = redvector_client.safe_post("api/autonomous/cctv-video-tamper-ptz-hijack", {"target": target, "manufacturer": manufacturer, "port": port})
        return result

    @mcp.tool()
    def autonomous_cctv_video_tamper_alerts(target: str, manufacturer: str = "generic", port: int = 80) -> Dict[str, Any]:
        """
        Probe alert/notification suppression capability (motion detection, email, alarms).

        Args:
            target: Target camera IP or hostname
            manufacturer: Camera manufacturer (hikvision, dahua, generic)
            port: HTTP port (default 80)

        Returns:
            Alerts tested, suppressible count, full suppression feasibility
        """
        logger.info(f"🔕 Probing alert suppression on {target}")
        result = redvector_client.safe_post("api/autonomous/cctv-video-tamper-alerts", {"target": target, "manufacturer": manufacturer, "port": port})
        return result

    @mcp.tool()
    def autonomous_cctv_video_tamper_timestamps(target: str, manufacturer: str = "generic", port: int = 80) -> Dict[str, Any]:
        """
        Probe NTP/time manipulation endpoints for timestamp falsification.

        Args:
            target: Target camera IP or hostname
            manufacturer: Camera manufacturer (hikvision, dahua, onvif, generic)
            port: HTTP port (default 80)

        Returns:
            Time endpoints tested, accessible endpoints, falsification capability
        """
        logger.info(f"⏰ Probing timestamp manipulation on {target}")
        result = redvector_client.safe_post("api/autonomous/cctv-video-tamper-timestamps", {"target": target, "manufacturer": manufacturer, "port": port})
        return result

    @mcp.tool()
    def autonomous_cctv_video_tamper_replay(target: str, manufacturer: str = "generic", port: int = 80) -> Dict[str, Any]:
        """
        Generate video replay/injection attack plan with tool commands.

        Args:
            target: Target camera IP or hostname
            manufacturer: Camera manufacturer (hikvision, dahua, generic)
            port: HTTP port (default 80)

        Returns:
            Attack plans for replay/injection/motion-blind/wipe, RTSP stream status
        """
        logger.info(f"🎬 Generating video replay plan for {target}")
        result = redvector_client.safe_post("api/autonomous/cctv-video-tamper-replay", {"target": target, "manufacturer": manufacturer, "port": port})
        return result

    @mcp.tool()
    def autonomous_cctv_video_tamper_techniques() -> Dict[str, Any]:
        """
        List all video tampering techniques, PTZ endpoints, and alert suppression methods.

        Returns:
            Replay techniques, PTZ manufacturers, alert endpoints, NTP endpoints
        """
        logger.info("📋 Listing video tamper techniques")
        result = redvector_client.safe_post("api/autonomous/cctv-video-tamper-techniques", {})
        return result

    # ========================================================================
    # SYSTEM 25: ZERO-DAY ATTACK DISCOVERY ENGINE
    # ========================================================================

    @mcp.tool()
    def autonomous_cctv_zeroday_discover(target: str, port: int = 80, manufacturer: str = "generic", depth: str = "normal") -> Dict[str, Any]:
        """
        Discover potential zero-day vulnerabilities in IP cameras via fuzzing and probing.
        Supports single IP or IP ranges (CIDR, comma-separated, dash ranges).

        Args:
            target: Target camera IP, hostname, or IP range (e.g. 192.168.1.0/24)
            port: HTTP port (default 80)
            manufacturer: Camera manufacturer (hikvision, dahua, axis, generic)
            depth: Scan depth - 'normal' for endpoint probing, 'deep' for full parameter fuzzing

        Returns:
            Attack surfaces tested, zero-day findings, severity counts, audit log
        """
        logger.info(f"🔬 Zero-day discovery scan on {target}:{port} (depth={depth})")
        result = redvector_client.safe_post("api/autonomous/cctv-zeroday-discover", {"target": target, "port": port, "manufacturer": manufacturer, "depth": depth})
        return result

    @mcp.tool()
    def autonomous_cctv_zeroday_surfaces() -> Dict[str, Any]:
        """
        List all known zero-day attack surfaces and vulnerability signatures.

        Returns:
            Attack surfaces (HTTP CGI, ISAPI, RTSP, ONVIF, UPnP), zero-day signatures
        """
        logger.info("📋 Listing zero-day attack surfaces")
        result = redvector_client.safe_post("api/autonomous/cctv-zeroday-surfaces", {})
        return result

    # ========================================================================
    # SYSTEM 26: SHODAN CAMERA DISCOVERY ENGINE
    # ========================================================================

    @mcp.tool()
    def autonomous_cctv_shodan_search(query: str = "", dork_name: str = "", limit: int = 20) -> Dict[str, Any]:
        """
        Search Shodan for exposed cameras using pre-built dorks or custom query.

        Args:
            query: Custom Shodan search query (optional if dork_name is provided)
            dork_name: Pre-built dork name (e.g. hikvision_all, dahua_unauth, generic_rtsp)
            limit: Maximum results to return (default 20, max 100)

        Returns:
            Cameras found with IP, port, banner info
        """
        logger.info(f"🔍 Shodan camera search (dork={dork_name}, query={query})")
        result = redvector_client.safe_post("api/autonomous/cctv-shodan-search", {"query": query, "dork_name": dork_name, "limit": limit})
        return result

    @mcp.tool()
    def autonomous_cctv_shodan_vulnerable(target: str, port: int = 80, manufacturer: str = "generic") -> Dict[str, Any]:
        """
        Scan target camera for outdated firmware and map to known CVEs via Shodan.
        Supports single IP or IP ranges.

        Args:
            target: Target camera IP, hostname, or IP range
            port: HTTP port (default 80)
            manufacturer: Camera manufacturer (hikvision, dahua, axis, generic)

        Returns:
            Firmware info, matched CVEs, risk level, Shodan host data
        """
        logger.info(f"🔎 Shodan vulnerable camera check for {target}")
        result = redvector_client.safe_post("api/autonomous/cctv-shodan-vulnerable", {"target": target, "port": port, "manufacturer": manufacturer})
        return result

    @mcp.tool()
    def autonomous_cctv_shodan_dorks() -> Dict[str, Any]:
        """
        List all pre-built Shodan camera search dorks and vulnerable firmware database.

        Returns:
            22+ Shodan dorks by manufacturer, vulnerable firmware versions with CVE mappings
        """
        logger.info("📋 Listing Shodan camera dorks")
        result = redvector_client.safe_post("api/autonomous/cctv-shodan-dorks", {})
        return result

    # ========================================================================
    # SYSTEM 27: PROXY-ROTATION BRUTE-FORCE ENGINE
    # ========================================================================

    @mcp.tool()
    def autonomous_cctv_proxy_bruteforce(target: str, port: int = 80, manufacturer: str = "generic",
                                         proxies: list = None, attempts_before_rotate: int = 4,
                                         max_attempts: int = 0, protocol: str = "http",
                                         rtsp_port: int = 554, rtsp_path: str = None,
                                         proxy_file: str = None) -> Dict[str, Any]:
        """
        Execute credential brute-force with automatic proxy rotation every N attempts.
        Automatically changes source IP to evade lockout during brute-force attacks.
        Supports both HTTP and RTSP protocols. Reads proxies from text file.

        Args:
            target: Target camera IP, hostname, or IP range
            port: HTTP port (default 80)
            manufacturer: Camera manufacturer (hikvision, dahua, generic)
            proxies: List of proxy URLs (auto-fetched if not provided)
            attempts_before_rotate: Rotate proxy every N attempts (default 4)
            max_attempts: Maximum total attempts (0 = unlimited, default 0)
            protocol: Attack protocol - 'http' or 'rtsp' (default 'http')
            rtsp_port: RTSP port (default 554, used when protocol='rtsp')
            rtsp_path: RTSP stream path (auto-detected from manufacturer if not set)
            proxy_file: Path to proxy list text file (one proxy per line)

        Returns:
            Credentials tested, successful logins, proxy rotation stats, per-attempt results
        """
        logger.info(f"🔄 Proxy-rotation brute-force on {target} (protocol={protocol}, rotate every {attempts_before_rotate})")
        payload = {"target": target, "port": port, "manufacturer": manufacturer,
                   "attempts_before_rotate": attempts_before_rotate, "max_attempts": max_attempts,
                   "protocol": protocol, "rtsp_port": rtsp_port}
        if proxies:
            payload["proxies"] = proxies
        if rtsp_path:
            payload["rtsp_path"] = rtsp_path
        if proxy_file:
            payload["proxy_file"] = proxy_file
        result = redvector_client.safe_post("api/autonomous/cctv-proxy-bruteforce", payload)
        return result

    @mcp.tool()
    def autonomous_cctv_proxy_verify(proxies: list = None) -> Dict[str, Any]:
        """
        Verify a list of proxies are alive and usable for brute-force rotation.

        Args:
            proxies: List of proxy URLs to verify (auto-fetched if not provided)

        Returns:
            Proxies tested, alive count, per-proxy status
        """
        logger.info("✅ Verifying proxy pool")
        payload = {}
        if proxies:
            payload["proxies"] = proxies
        result = redvector_client.safe_post("api/autonomous/cctv-proxy-verify", payload)
        return result

    @mcp.tool()
    def autonomous_cctv_proxy_config() -> Dict[str, Any]:
        """
        List proxy rotation configuration and available proxy sources.

        Returns:
            Rotation config (attempts before rotate, timeouts), proxy sources, proxy types
        """
        logger.info("📋 Listing proxy rotation config")
        result = redvector_client.safe_post("api/autonomous/cctv-proxy-config", {})
        return result

    # ── SYSTEM 28: Hydra RTSP Proxy-Rotating Brute-Force ─────────────

    @mcp.tool()
    def autonomous_cctv_hydra_rtsp(target: str, rtsp_port: int = 554,
                                    manufacturer: str = "generic",
                                    credentials: list = None,
                                    proxy_file: str = None,
                                    attempts_before_rotate: int = 4) -> Dict[str, Any]:
        """
        Hydra-based RTSP brute-force with automatic proxy rotation.
        Reads proxies from a text file, health-checks them first, skips dead
        ones, and rotates to the next live proxy every N attempts.

        Args:
            target: Target camera IP, hostname, or IP range
            rtsp_port: RTSP port (default 554)
            manufacturer: Camera manufacturer (hikvision, dahua, axis, generic)
            credentials: Optional list of [user, pass] credential pairs
            proxy_file: Path to proxy list text file (one proxy per line)
            attempts_before_rotate: Rotate proxy every N attempts (default 4)

        Returns:
            Credentials tested, successful logins, proxy stats, audit log
        """
        logger.info(f"🔥 Hydra RTSP proxy-brute-force on {target}:{rtsp_port}")
        payload = {"target": target, "rtsp_port": rtsp_port,
                   "manufacturer": manufacturer,
                   "attempts_before_rotate": attempts_before_rotate}
        if credentials:
            payload["credentials"] = credentials
        if proxy_file:
            payload["proxy_file"] = proxy_file
        result = redvector_client.safe_post("api/autonomous/cctv-hydra-rtsp", payload)
        return result

    @mcp.tool()
    def autonomous_cctv_hydra_rtsp_verify(proxy_file: str = None) -> Dict[str, Any]:
        """
        Verify and clean proxy list - load from file, test each proxy,
        return live vs dead proxies.

        Args:
            proxy_file: Path to proxy list text file

        Returns:
            Live proxies, dead proxies, totals
        """
        logger.info("🧹 Hydra RTSP - verifying proxy list")
        payload = {}
        if proxy_file:
            payload["proxy_file"] = proxy_file
        result = redvector_client.safe_post("api/autonomous/cctv-hydra-rtsp-verify", payload)
        return result

    @mcp.tool()
    def autonomous_cctv_hydra_rtsp_config() -> Dict[str, Any]:
        """
        List Hydra RTSP engine configuration and default settings.

        Returns:
            Engine config, default proxy file path, supported proxy types
        """
        logger.info("📋 Hydra RTSP engine config")
        result = redvector_client.safe_post("api/autonomous/cctv-hydra-rtsp-config", {})
        return result

    # ── SYSTEM 29: Camera Fingerprint Engine ─────────────────────────

    @mcp.tool()
    def autonomous_cctv_fingerprint(target: str, port: int = 80,
                                     rtsp_port: int = 554,
                                     manufacturer: str = None) -> Dict[str, Any]:
        """
        Fingerprint a CCTV camera - extract model, manufacturer, firmware
        version, authentication method, and RTSP stream paths.
        Supports Dahua, Hikvision, and Axis with auto-detection.

        Args:
            target: Target camera IP, hostname, or IP range
            port: HTTP port (default 80)
            rtsp_port: RTSP port (default 554)
            manufacturer: Manufacturer hint (auto-detected if omitted)

        Returns:
            Camera model, manufacturer, firmware version, auth method, RTSP paths, known CVEs
        """
        logger.info(f"🔍 Camera fingerprint for {target}")
        payload = {"target": target, "port": port, "rtsp_port": rtsp_port}
        if manufacturer:
            payload["manufacturer"] = manufacturer
        result = redvector_client.safe_post("api/autonomous/cctv-fingerprint", payload)
        return result

    @mcp.tool()
    def autonomous_cctv_fingerprint_manufacturers() -> Dict[str, Any]:
        """
        List supported camera manufacturers and fingerprint endpoints.

        Returns:
            Supported manufacturers, detection patterns, probe endpoints
        """
        logger.info("📋 Listing supported camera manufacturers")
        result = redvector_client.safe_post("api/autonomous/cctv-fingerprint-manufacturers", {})
        return result

    # ------------------------------------------------------------------
    # System 30 - Authentication Bypass Engine
    # ------------------------------------------------------------------

    @mcp.tool()
    def autonomous_cctv_auth_bypass(
        target: str,
        port: int = 80,
        manufacturer: str = None,
    ) -> Dict[str, Any]:
        """
        Test authentication bypass on CCTV camera firmware.
        Probes known unauthenticated endpoints for Dahua, Hikvision, Axis, and Provision-ISR.

        Args:
            target: Camera IP address or hostname (supports CIDR ranges)
            port: HTTP port (default 80)
            manufacturer: Specific manufacturer to test (dahua/hikvision/axis/provision-isr) or None for all

        Returns:
            Bypass results per endpoint, vulnerable endpoints list
        """
        logger.info(f"🔓 Auth bypass test for {target}")
        payload = {"target": target, "port": port}
        if manufacturer:
            payload["manufacturer"] = manufacturer
        result = redvector_client.safe_post("api/autonomous/cctv-auth-bypass", payload)
        return result

    @mcp.tool()
    def autonomous_cctv_auth_bypass_cve(
        target: str,
        port: int = 80,
        manufacturer: str = None,
    ) -> Dict[str, Any]:
        """
        Test known CVE-based authentication bypass techniques on CCTV cameras.

        Args:
            target: Camera IP address or hostname (supports CIDR ranges)
            port: HTTP port (default 80)
            manufacturer: Specific manufacturer or None for all

        Returns:
            CVE bypass test results, potentially vulnerable CVEs
        """
        logger.info(f"🔓 CVE auth bypass test for {target}")
        payload = {"target": target, "port": port}
        if manufacturer:
            payload["manufacturer"] = manufacturer
        result = redvector_client.safe_post("api/autonomous/cctv-auth-bypass-cve", payload)
        return result

    @mcp.tool()
    def autonomous_cctv_auth_bypass_endpoints() -> Dict[str, Any]:
        """
        List all known authentication bypass endpoints and CVEs per manufacturer.

        Returns:
            Supported manufacturers, bypass endpoints, known CVEs
        """
        logger.info("📋 Listing auth bypass endpoints")
        result = redvector_client.safe_post("api/autonomous/cctv-auth-bypass-endpoints", {})
        return result

    # ------------------------------------------------------------------
    # System 31 - Buffer Overflow RCE Engine
    # ------------------------------------------------------------------

    @mcp.tool()
    def autonomous_cctv_overflow_scan(
        target: str,
        port: int = 80,
        manufacturer: str = None,
    ) -> Dict[str, Any]:
        """
        Scan for buffer overflow vulnerabilities on CCTV camera web interfaces and CGI handlers.

        Args:
            target: Camera IP address or hostname (supports CIDR ranges)
            port: HTTP port (default 80)
            manufacturer: Specific manufacturer to test or None for all

        Returns:
            Overflow scan results, potentially vulnerable endpoints
        """
        logger.info(f"💥 Buffer overflow scan for {target}")
        payload = {"target": target, "port": port}
        if manufacturer:
            payload["manufacturer"] = manufacturer
        result = redvector_client.safe_post("api/autonomous/cctv-overflow-scan", payload)
        return result

    @mcp.tool()
    def autonomous_cctv_overflow_rce_cve(
        target: str,
        port: int = 80,
        manufacturer: str = None,
    ) -> Dict[str, Any]:
        """
        Check for known buffer overflow RCE CVEs on CCTV cameras.

        Args:
            target: Camera IP address or hostname (supports CIDR ranges)
            port: HTTP port (default 80)
            manufacturer: Specific manufacturer or None for all

        Returns:
            CVE check results, potentially vulnerable CVEs
        """
        logger.info(f"💥 Buffer overflow RCE CVE check for {target}")
        payload = {"target": target, "port": port}
        if manufacturer:
            payload["manufacturer"] = manufacturer
        result = redvector_client.safe_post("api/autonomous/cctv-overflow-rce-cve", payload)
        return result

    @mcp.tool()
    def autonomous_cctv_overflow_vectors() -> Dict[str, Any]:
        """
        List all known buffer overflow vectors and CVEs per manufacturer.

        Returns:
            Supported manufacturers, overflow CVEs, test endpoints
        """
        logger.info("📋 Listing buffer overflow vectors")
        result = redvector_client.safe_post("api/autonomous/cctv-overflow-vectors", {})
        return result

    # ── System 32 - Linux Privilege Escalation Tools ─────────────────

    @mcp.tool()
    def autonomous_linux_privesc_scan(target: str, ssh_user: str = "root",
                                      ssh_port: int = 22,
                                      ssh_key: str = "") -> Dict[str, Any]:
        """
        Full Linux privilege escalation scan (SUID, sudo, cron, kernel, permissions).

        Args:
            target: Target IP or hostname
            ssh_user: SSH user for remote execution (default: root)
            ssh_port: SSH port (default: 22)
            ssh_key: Path to SSH private key (optional)

        Returns:
            Comprehensive privilege escalation findings
        """
        logger.info(f"🔓 Full Linux privilege escalation scan on {target}")
        payload = {"target": target, "ssh_user": ssh_user, "ssh_port": ssh_port}
        if ssh_key:
            payload["ssh_key"] = ssh_key
        result = redvector_client.safe_post("api/autonomous/linux-privesc-scan", payload)
        return result

    @mcp.tool()
    def autonomous_linux_privesc_suid(target: str, ssh_user: str = "root",
                                      ssh_port: int = 22,
                                      ssh_key: str = "") -> Dict[str, Any]:
        """
        Enumerate SUID/SGID binaries and cross-reference with GTFOBins.

        Args:
            target: Target IP or hostname
            ssh_user: SSH user for remote execution (default: root)
            ssh_port: SSH port (default: 22)
            ssh_key: Path to SSH private key (optional)

        Returns:
            SUID/SGID binaries found, GTFOBins matches
        """
        logger.info(f"🔍 SUID/SGID scan on {target}")
        payload = {"target": target, "ssh_user": ssh_user, "ssh_port": ssh_port}
        if ssh_key:
            payload["ssh_key"] = ssh_key
        result = redvector_client.safe_post("api/autonomous/linux-privesc-suid", payload)
        return result

    @mcp.tool()
    def autonomous_linux_privesc_sudo(target: str, ssh_user: str = "root",
                                      ssh_port: int = 22,
                                      ssh_key: str = "") -> Dict[str, Any]:
        """
        Check sudo misconfigurations (NOPASSWD, wildcards, GTFOBins-abusable).

        Args:
            target: Target IP or hostname
            ssh_user: SSH user for remote execution (default: root)
            ssh_port: SSH port (default: 22)
            ssh_key: Path to SSH private key (optional)

        Returns:
            Sudo entries, dangerous misconfigurations, sudo version
        """
        logger.info(f"🔓 Sudo misconfiguration check on {target}")
        payload = {"target": target, "ssh_user": ssh_user, "ssh_port": ssh_port}
        if ssh_key:
            payload["ssh_key"] = ssh_key
        result = redvector_client.safe_post("api/autonomous/linux-privesc-sudo", payload)
        return result

    @mcp.tool()
    def autonomous_linux_privesc_cron(target: str, ssh_user: str = "root",
                                      ssh_port: int = 22,
                                      ssh_key: str = "") -> Dict[str, Any]:
        """
        Analyse cron jobs for writable scripts executed by root.

        Args:
            target: Target IP or hostname
            ssh_user: SSH user for remote execution (default: root)
            ssh_port: SSH port (default: 22)
            ssh_key: Path to SSH private key (optional)

        Returns:
            Cron job data, writable script paths
        """
        logger.info(f"⏰ Cron job analysis on {target}")
        payload = {"target": target, "ssh_user": ssh_user, "ssh_port": ssh_port}
        if ssh_key:
            payload["ssh_key"] = ssh_key
        result = redvector_client.safe_post("api/autonomous/linux-privesc-cron", payload)
        return result

    @mcp.tool()
    def autonomous_linux_privesc_kernel(target: str, ssh_user: str = "root",
                                        ssh_port: int = 22,
                                        ssh_key: str = "") -> Dict[str, Any]:
        """
        Check kernel version against known privilege escalation CVEs.

        Args:
            target: Target IP or hostname
            ssh_user: SSH user for remote execution (default: root)
            ssh_port: SSH port (default: 22)
            ssh_key: Path to SSH private key (optional)

        Returns:
            Kernel version, matching CVEs, Linux Exploit Suggester output
        """
        logger.info(f"🐧 Kernel exploit check on {target}")
        payload = {"target": target, "ssh_user": ssh_user, "ssh_port": ssh_port}
        if ssh_key:
            payload["ssh_key"] = ssh_key
        result = redvector_client.safe_post("api/autonomous/linux-privesc-kernel", payload)
        return result

    @mcp.tool()
    def autonomous_linux_privesc_permissions(target: str, ssh_user: str = "root",
                                             ssh_port: int = 22,
                                             ssh_key: str = "") -> Dict[str, Any]:
        """
        Scan for weak permissions, capabilities, and PATH abuse vectors.

        Args:
            target: Target IP or hostname
            ssh_user: SSH user for remote execution (default: root)
            ssh_port: SSH port (default: 22)
            ssh_key: Path to SSH private key (optional)

        Returns:
            Sensitive file permissions, world-writable files, capabilities
        """
        logger.info(f"📂 Permissions and capabilities scan on {target}")
        payload = {"target": target, "ssh_user": ssh_user, "ssh_port": ssh_port}
        if ssh_key:
            payload["ssh_key"] = ssh_key
        result = redvector_client.safe_post("api/autonomous/linux-privesc-permissions", payload)
        return result

    @mcp.tool()
    def autonomous_linux_privesc_tools(target: str, tool_name: str,
                                       ssh_user: str = "root",
                                       ssh_port: int = 22,
                                       ssh_key: str = "") -> Dict[str, Any]:
        """
        Deploy and run a privilege-escalation enumeration tool on target.

        Args:
            target: Target IP or hostname
            tool_name: Tool to deploy (linpeas, linenum, les, pspy, lse)
            ssh_user: SSH user for remote execution (default: root)
            ssh_port: SSH port (default: 22)
            ssh_key: Path to SSH private key (optional)

        Returns:
            Tool output from remote execution
        """
        logger.info(f"🛠️ Deploying {tool_name} on {target}")
        payload = {"target": target, "tool_name": tool_name,
                   "ssh_user": ssh_user, "ssh_port": ssh_port}
        if ssh_key:
            payload["ssh_key"] = ssh_key
        result = redvector_client.safe_post("api/autonomous/linux-privesc-tools", payload)
        return result

    @mcp.tool()
    def autonomous_linux_privesc_vectors() -> Dict[str, Any]:
        """
        List all supported privilege escalation vectors, CVEs, and tools.

        Returns:
            Escalation vectors, kernel CVEs, enumeration tools
        """
        logger.info("📋 Listing Linux privilege escalation vectors")
        result = redvector_client.safe_post("api/autonomous/linux-privesc-vectors", {})
        return result

    # ── System 33: Autonomous Offensive Chain Engine ──────────────────────

    @mcp.tool()
    def autonomous_offensive_chain(target: str, lhost: str = "10.10.14.5", lport: int = 4444,
                                   os_type: str = "linux", scan_type: str = "normal",
                                   domain: str = "corp.local") -> Dict[str, Any]:
        """Full autonomous offensive lifecycle - all 8 stages chained.
        Recon → exploit → escalate → persist → lateral → exfil → backdoor → cleanup.
        Args: target - IP/host. lhost - Attacker IP. lport - Listener port. os_type - linux/windows. scan_type - stealth/normal/aggressive.
        """
        logger.info(f"[CHAIN] Full offensive lifecycle against {target}")
        payload = {"target": target, "lhost": lhost, "lport": lport, "os_type": os_type, "scan_type": scan_type, "domain": domain}
        result = redvector_client.safe_post("api/autonomous/offensive-chain", payload)
        if result.get("success"):
            logger.info(f"✅ Chain complete: {result.get('stages_completed', 0)}/8 stages")
        else:
            logger.error("❌ Offensive chain failed")
        return result

    @mcp.tool()
    def autonomous_offensive_recon(target: str, scan_type: str = "normal") -> Dict[str, Any]:
        """Stage 1 - Autonomous reconnaissance: scan targets, enumerate services, detect technologies, identify weak exposures.
        Args: target - IP/CIDR/host. scan_type - stealth/normal/aggressive.
        """
        logger.info(f"[CHAIN-S1] Recon against {target}")
        result = redvector_client.safe_post("api/autonomous/offensive-recon", {"target": target, "scan_type": scan_type})
        return result

    @mcp.tool()
    def autonomous_offensive_exploit(target: str, lhost: str = "10.10.14.5", lport: int = 4444) -> Dict[str, Any]:
        """Stage 2 - Autonomous exploit: match CVEs, test auth bypass, attempt injection, run exploits, gain shell.
        Args: target - IP/URL. lhost - Attacker IP. lport - Listener port.
        """
        logger.info(f"[CHAIN-S2] Exploit against {target}")
        result = redvector_client.safe_post("api/autonomous/offensive-exploit", {"target": target, "lhost": lhost, "lport": lport})
        return result

    @mcp.tool()
    def autonomous_offensive_privesc(target: str, os_type: str = "linux") -> Dict[str, Any]:
        """Stage 3 - Autonomous privilege escalation: SUID/sudo/kernel/token abuse to root/SYSTEM.
        Args: target - IP/host. os_type - linux/windows.
        """
        logger.info(f"[CHAIN-S3] Privesc against {target}")
        result = redvector_client.safe_post("api/autonomous/offensive-privesc", {"target": target, "os_type": os_type})
        return result

    @mcp.tool()
    def autonomous_offensive_persistence(target: str, os_type: str = "linux",
                                         lhost: str = "10.10.14.5", lport: int = 4444) -> Dict[str, Any]:
        """Stage 4 - Autonomous persistence: cron, service, startup, SSH keys, registry, scheduled tasks.
        Args: target - IP/host. os_type - linux/windows. lhost - Attacker IP. lport - Listener port.
        """
        logger.info(f"[CHAIN-S4] Persistence on {target}")
        result = redvector_client.safe_post("api/autonomous/offensive-persistence", {"target": target, "os_type": os_type, "lhost": lhost, "lport": lport})
        return result

    @mcp.tool()
    def autonomous_offensive_lateral(target: str, domain: str = "corp.local",
                                     username: str = "admin", credential: str = "Password123") -> Dict[str, Any]:
        """Stage 5 - Autonomous lateral movement: scan internal network, reuse credentials, pivot to other hosts.
        Args: target - IP/host. domain - AD domain. username - Credential username. credential - Password/hash.
        """
        logger.info(f"[CHAIN-S5] Lateral from {target}")
        result = redvector_client.safe_post("api/autonomous/offensive-lateral", {"target": target, "domain": domain, "username": username, "credential": credential})
        return result

    @mcp.tool()
    def autonomous_offensive_exfiltration(target: str, c2_server: str = "10.10.14.5", c2_port: int = 8443) -> Dict[str, Any]:
        """Stage 6 - Autonomous data exfiltration: collect sensitive files, dump databases, compress, encrypt, prepare for C2 transmission.
        Args: target - IP/host. c2_server - C2 server IP. c2_port - C2 port.
        """
        logger.info(f"[CHAIN-S6] Exfil from {target}")
        result = redvector_client.safe_post("api/autonomous/offensive-exfiltration", {"target": target, "c2_server": c2_server, "c2_port": c2_port})
        return result

    @mcp.tool()
    def autonomous_offensive_backdoor(target: str, lhost: str = "10.10.14.5", lport: int = 4444,
                                      os_type: str = "linux") -> Dict[str, Any]:
        """Stage 7 - Autonomous backdoor: establish covert long-term access channels (SSH tunnels, DoH beacons, webshells, named pipes).
        Args: target - IP/host. lhost - Attacker IP. lport - Listener port. os_type - linux/windows.
        """
        logger.info(f"[CHAIN-S7] Backdoor on {target}")
        result = redvector_client.safe_post("api/autonomous/offensive-backdoor", {"target": target, "lhost": lhost, "lport": lport, "os_type": os_type})
        return result

    @mcp.tool()
    def autonomous_offensive_cleanup(target: str, os_type: str = "linux") -> Dict[str, Any]:
        """Stage 8 - Autonomous cleanup / anti-forensics: clear logs, remove artifacts, timestomp files, reduce forensic footprint.
        Args: target - IP/host. os_type - linux/windows.
        """
        logger.info(f"[CHAIN-S8] Cleanup on {target}")
        result = redvector_client.safe_post("api/autonomous/offensive-cleanup", {"target": target, "os_type": os_type})
        return result

    @mcp.tool()
    def autonomous_offensive_lifecycle() -> Dict[str, Any]:
        """Get metadata about all 8 offensive lifecycle stages - tools, chains, descriptions.
        """
        logger.info("[CHAIN] Lifecycle info")
        result = redvector_client.safe_post("api/autonomous/offensive-lifecycle", {})
        return result

    # ========================================================================
    # LLM INTEGRATION TOOLS (Ollama / OpenAI-compatible backends)
    # ========================================================================

    @mcp.tool()
    def llm_list_models() -> Dict[str, Any]:
        """List available LLM models from the connected backend (Ollama, etc.).
        Use this to discover which models are loaded and available for AI-powered analysis.
        """
        logger.info("[LLM] Listing models")
        return redvector_client.safe_get("api/llm/models")

    @mcp.tool()
    def llm_chat(prompt: str, model: str = "", system: str = "",
                 temperature: float = 0.7, max_tokens: int = 2048) -> Dict[str, Any]:
        """Chat with a local LLM model via Ollama (llama3, deepseek, qwen, mistral, etc.).
        Use for pentest planning, vulnerability analysis, exploit research, report writing.

        Args:
            prompt: Your question or instruction for the LLM
            model: Model name (e.g. llama3, deepseek-r1, qwen2.5). Leave empty for default
            system: Custom system prompt (default: RedVector security assistant)
            temperature: Creativity level 0.0-1.0 (lower = more focused)
            max_tokens: Maximum response length
        """
        logger.info(f"[LLM] Chat request | model={model or 'default'}")
        return redvector_client.safe_post("api/llm/chat", {
            "prompt": prompt, "model": model, "system": system,
            "temperature": temperature, "max_tokens": max_tokens
        })

    @mcp.tool()
    def llm_analyze_scan(scan_output: str, scan_type: str = "nmap",
                         model: str = "") -> Dict[str, Any]:
        """Analyze scan output (nmap, nuclei, etc.) using a local LLM for vulnerability assessment.

        Args:
            scan_output: Raw output from a security scan tool
            scan_type: Type of scan (nmap, nuclei, gobuster, nikto, etc.)
            model: Model name (leave empty for default)
        """
        logger.info(f"[LLM] Analyzing {scan_type} output")
        return redvector_client.safe_post("api/llm/analyze-scan", {
            "scan_output": scan_output, "scan_type": scan_type, "model": model
        })

    @mcp.tool()
    def llm_suggest_exploits(target_info: str, model: str = "") -> Dict[str, Any]:
        """Get exploit suggestions from a local LLM based on discovered target information.

        Args:
            target_info: Description of the target (services, versions, OS, open ports, etc.)
            model: Model name (leave empty for default)
        """
        logger.info("[LLM] Requesting exploit suggestions")
        return redvector_client.safe_post("api/llm/suggest-exploits", {
            "target_info": target_info, "model": model
        })

    @mcp.tool()
    def llm_write_report(findings: str, model: str = "") -> Dict[str, Any]:
        """Generate a professional pentest report section using a local LLM.

        Args:
            findings: Raw findings from the penetration test
            model: Model name (leave empty for default)
        """
        logger.info("[LLM] Generating report")
        return redvector_client.safe_post("api/llm/write-report", {
            "findings": findings, "model": model
        })

    @mcp.tool()
    def llm_config_get() -> Dict[str, Any]:
        """Get current LLM backend configuration (URL, model, timeout)."""
        return redvector_client.safe_get("api/llm/config")

    @mcp.tool()
    def llm_config_set(base_url: str = "", model: str = "",
                       api_key: str = "", timeout: int = 0) -> Dict[str, Any]:
        """Update LLM backend configuration at runtime.

        Args:
            base_url: LLM API URL (default: http://127.0.0.1:11434 for Ollama)
            model: Default model name to use
            api_key: API key for the backend
            timeout: Request timeout in seconds
        """
        data = {}
        if base_url:
            data["base_url"] = base_url
        if model:
            data["model"] = model
        if api_key:
            data["api_key"] = api_key
        if timeout:
            data["timeout"] = timeout
        logger.info(f"[LLM] Updating config: {list(data.keys())}")
        return redvector_client.safe_post("api/llm/config", data)

    return mcp

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the RedVector AI MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_REDVECTOR_SERVER,
                      help=f"RedVector AI API server URL (default: {DEFAULT_REDVECTOR_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--transport", type=str, default="stdio",
                      choices=["stdio", "sse", "streamable-http"],
                      help="MCP transport protocol (default: stdio). Use 'sse' for HTTP-based AI clients.")
    parser.add_argument("--mcp-port", type=int, default=8889,
                      help="Port for SSE/streamable-http transport (default: 8889)")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                      help="Host for SSE/streamable-http transport (default: 127.0.0.1)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()

def main():
    """Main entry point for the MCP server."""
    args = parse_args()

    # Configure logging based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("🔍 Debug logging enabled")

    # MCP compatibility: No banner output to avoid JSON parsing issues
    logger.info(f"🚀 Starting RedVector AI MCP Client v2.0")
    logger.info(f"🔗 Connecting to: {args.server}")

    try:
        # Initialize the RedVector AI client
        redvector_client = RedVectorClient(args.server, args.timeout)

        # Check server health and log the result
        health = redvector_client.check_health()
        if "error" in health:
            logger.warning(f"⚠️  Unable to connect to RedVector AI API server at {args.server}: {health['error']}")
            logger.warning("🚀 MCP server will start, but tool execution may fail")
        else:
            logger.info(f"🎯 Successfully connected to RedVector AI API server at {args.server}")
            logger.info(f"🏥 Server health status: {health['status']}")
            logger.info(f"📊 Version: {health.get('version', 'unknown')}")
            if not health.get("all_essential_tools_available", False):
                logger.warning("⚠️  Not all essential tools are available on the RedVector server")
                missing_tools = [tool for tool, available in health.get("tools_status", {}).items() if not available]
                if missing_tools:
                    logger.warning(f"❌ Missing tools: {', '.join(missing_tools[:5])}{'...' if len(missing_tools) > 5 else ''}")

        # Set up and run the MCP server
        mcp = setup_mcp_server(redvector_client)

        # Configure transport-specific settings
        if args.transport in ("sse", "streamable-http"):
            mcp.settings.host = args.mcp_host
            mcp.settings.port = args.mcp_port
            logger.info(f"🌐 MCP transport: {args.transport} on http://{args.mcp_host}:{args.mcp_port}")
        else:
            logger.info("🔌 MCP transport: stdio")

        logger.info("🚀 Starting RedVector AI MCP server")
        logger.info("🤖 Ready to serve AI agents with enhanced cybersecurity capabilities")
        mcp.run(transport=args.transport)
    except Exception as e:
        logger.error(f"💥 Error starting MCP server: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()

"""Scope manager — enforces bug bounty program boundaries.

Every tool call is checked against scope before execution.
Going out of scope in a bug bounty program = disqualified.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


@dataclass(frozen=True)
class BountyScope:
    """Defines the boundaries of a bug bounty program."""

    program_name: str = ""
    platform: str = "custom"  # hackerone, bugcrowd, custom
    in_scope_domains: tuple[str, ...] = ()
    in_scope_ips: tuple[str, ...] = ()
    in_scope_ports: tuple[int, ...] | None = None  # None = all ports
    out_of_scope_domains: tuple[str, ...] = ()
    out_of_scope_paths: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()
    max_rps: int = 10


class ScopeManager:
    """Validates targets against a defined bug bounty scope.

    Usage::

        scope = ScopeManager.from_yaml(Path("scope.yaml"))
        allowed, reason = scope.check_target("https://api.example.com/users")
        if not allowed:
            print(f"OUT OF SCOPE: {reason}")
    """

    def __init__(self, scope: BountyScope) -> None:
        self._scope = scope
        self._ip_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in scope.in_scope_ips:
            try:
                self._ip_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass

    @property
    def scope(self) -> BountyScope:
        return self._scope

    @property
    def max_rps(self) -> int:
        return self._scope.max_rps

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_target(self, target: str) -> tuple[bool, str]:
        """Check if a target string (URL, domain, or IP) is in scope.

        Returns:
            (allowed, reason) — reason explains *why* it was blocked.
        """
        if not target:
            return False, "Empty target"

        # Try to parse as URL first
        parsed = urlparse(target if "://" in target else f"https://{target}")
        hostname = parsed.hostname or target
        path = parsed.path or "/"
        port = parsed.port

        # 1. Check out-of-scope domains first (takes priority)
        if self._matches_domain_list(hostname, self._scope.out_of_scope_domains):
            return False, f"Domain '{hostname}' is explicitly out of scope"

        # 2. Check out-of-scope paths
        if self._matches_path_list(path, self._scope.out_of_scope_paths):
            return False, f"Path '{path}' is explicitly out of scope"

        # 3. Check if domain is in scope
        domain_ok = self._matches_domain_list(hostname, self._scope.in_scope_domains)

        # 4. Check if IP is in scope
        ip_ok = self._check_ip(hostname)

        if not domain_ok and not ip_ok:
            return False, f"Target '{hostname}' is not in scope (no matching domain or IP)"

        # 5. Check port scope
        if port is not None and self._scope.in_scope_ports is not None:
            if port not in self._scope.in_scope_ports:
                return False, f"Port {port} is not in scope (allowed: {list(self._scope.in_scope_ports)})"

        return True, "In scope"

    def is_in_scope(self, target: str) -> bool:
        """Simple boolean check."""
        allowed, _ = self.check_target(target)
        return allowed

    def check_url(self, url: str) -> tuple[bool, str]:
        """Alias for check_target — matches the plan's API."""
        return self.check_target(url)

    def check_ip(self, ip: str) -> bool:
        """Check if an IP address falls within in-scope CIDRs."""
        return self._check_ip(ip)

    # ------------------------------------------------------------------
    # Domain matching
    # ------------------------------------------------------------------

    @staticmethod
    def _matches_domain_list(hostname: str, patterns: tuple[str, ...]) -> bool:
        """Check if hostname matches any pattern (supports wildcards like *.example.com)."""
        hostname = hostname.lower().strip(".")
        for pattern in patterns:
            pattern = pattern.lower().strip(".")
            if pattern.startswith("*."):
                # *.example.com matches sub.example.com and example.com itself
                base = pattern[2:]
                if hostname == base or hostname.endswith(f".{base}"):
                    return True
            else:
                if hostname == pattern:
                    return True
        return False

    @staticmethod
    def _matches_path_list(path: str, patterns: tuple[str, ...]) -> bool:
        """Check if a URL path matches any out-of-scope path pattern."""
        for pattern in patterns:
            if pattern.endswith("*"):
                if path.startswith(pattern[:-1]):
                    return True
            elif fnmatch.fnmatch(path, pattern):
                return True
            elif path == pattern:
                return True
        return False

    # ------------------------------------------------------------------
    # IP matching
    # ------------------------------------------------------------------

    def _check_ip(self, host: str) -> bool:
        """Check if host (IP string) falls in any in-scope CIDR."""
        if not self._ip_networks:
            return False
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(addr in net for net in self._ip_networks)

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    @classmethod
    def from_yaml(cls, path: Path) -> ScopeManager:
        """Load scope definition from a YAML file."""
        with open(path) as f:
            raw: dict[str, Any] = yaml.safe_load(f) or {}

        in_scope = raw.get("in_scope", {})
        out_of_scope = raw.get("out_of_scope", {})

        scope = BountyScope(
            program_name=raw.get("program", ""),
            platform=raw.get("platform", "custom"),
            in_scope_domains=tuple(in_scope.get("domains", [])),
            in_scope_ips=tuple(in_scope.get("ips", [])),
            in_scope_ports=tuple(in_scope["ports"]) if "ports" in in_scope else None,
            out_of_scope_domains=tuple(out_of_scope.get("domains", [])),
            out_of_scope_paths=tuple(out_of_scope.get("paths", [])),
            rules=tuple(raw.get("rules", [])),
            max_rps=raw.get("max_rps", 10),
        )
        return cls(scope)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScopeManager:
        """Create from a plain dict (useful for API/programmatic use)."""
        in_scope = data.get("in_scope", {})
        out_of_scope = data.get("out_of_scope", {})

        scope = BountyScope(
            program_name=data.get("program", ""),
            platform=data.get("platform", "custom"),
            in_scope_domains=tuple(in_scope.get("domains", [])),
            in_scope_ips=tuple(in_scope.get("ips", [])),
            in_scope_ports=tuple(in_scope["ports"]) if "ports" in in_scope else None,
            out_of_scope_domains=tuple(out_of_scope.get("domains", [])),
            out_of_scope_paths=tuple(out_of_scope.get("paths", [])),
            rules=tuple(data.get("rules", [])),
            max_rps=data.get("max_rps", 10),
        )
        return cls(scope)

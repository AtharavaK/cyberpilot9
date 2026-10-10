"""
Security utilities for target validation and SSRF protection.
"""
import ipaddress
import os
import socket
from urllib.parse import urlparse
from typing import Tuple, Optional

# RFC 1918 private ranges + localhost + link-local + reserved
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT
    ipaddress.ip_network("192.0.0.0/24"),    # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("fc00::/7"),         # unique local IPv6
    ipaddress.ip_network("fe80::/10"),        # link-local IPv6
    ipaddress.ip_network("::1/128"),          # localhost IPv6
    ipaddress.ip_network("::ffff:0:0/96"),    # IPv4-mapped IPv6
]


def _resolve_host(hostname: str) -> Optional[str]:
    """Resolve a hostname to its first IPv4 address. Returns None on failure."""
    try:
        addrinfo = socket.getaddrinfo(hostname, None, socket.AF_INET)
        if addrinfo:
            return addrinfo[0][4][0]
    except (socket.gaierror, socket.herror, OSError):
        pass
    return None


def classify_target(target_url: str) -> Tuple[str, bool, Optional[str]]:
    """
    Validate a target URL and classify it.

    Returns: (host, is_private_or_local, resolved_ip_or_none)
      - host: hostname or IP string extracted from the URL
      - is_private_or_local: True if the target resolves to a private/internal IP
      - resolved_ip: the IPv4 address the hostname resolves to, or None
    Raises ValueError on malformed URLs or unresolvable hostnames.
    """
    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid target URL (need scheme + host): {target_url!r}")

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Only http/https targets are allowed, got {scheme!r}")

    host = parsed.netloc.split(":")[0]

    # Try to interpret the host as a literal IP first
    try:
        ip = ipaddress.ip_address(host)
        is_private = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        return (host, is_private, str(ip))
    except ValueError:
        pass  # not a literal IP - resolve it

    # Hostname - resolve and check
    resolved = _resolve_host(host)
    if resolved is None:
        raise ValueError(f"Could not resolve hostname: {host!r}")

    try:
        ip = ipaddress.ip_address(resolved)
    except ValueError:
        return (host, False, resolved)

    is_private = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    return (host, is_private, str(ip))


def validate_target(target_url: str, allow_private: bool = None) -> Tuple[bool, str]:
    """Validate a target URL for SSRF safety.

    Returns ``(is_valid, reason)`` where *is_valid* is True when the target
    is safe to scan and *reason* is an empty string on success or an
    explanation when the target is blocked.

    Parameters
    ----------
    target_url : str
        The target URL to validate.
    allow_private : bool or None
        If None (default), reads ``ZAP_ALLOW_PRIVATE_TARGETS`` from the
        environment at call time.  If True/False, uses the explicit value.
        Set to True only when you have explicit authorization to scan
        this network.
    """
    # Read env var at call time so tests with patch.dict work correctly
    if allow_private is None:
        allow_private = os.environ.get("ZAP_ALLOW_PRIVATE_TARGETS", "").lower() in (
            "true", "1", "yes"
        )
    try:
        host, is_private, resolved_ip = classify_target(target_url)
    except ValueError as e:
        return (False, str(e))

    if is_private and not allow_private:
        if resolved_ip:
            if ipaddress.ip_address(resolved_ip).is_loopback:
                return (False, "localhost address (blocked)")
            if ipaddress.ip_address(resolved_ip).is_private:
                return (False, "private IP range (blocked)")
            if ipaddress.ip_address(resolved_ip).is_link_local:
                return (False, "link-local address (blocked)")
        return (False, f"private or internal target (blocked): {host}")

    return (True, "")

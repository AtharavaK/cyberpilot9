"""
Security utilities for target validation and SSRF protection.
"""
import ipaddress
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

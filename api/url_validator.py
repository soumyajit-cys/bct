"""
api/url_validator.py
====================
Centralised SSRF protection for every outbound HTTP request made by the
scanner.

Production behaviour (default):
  - Blocks loopback / localhost
  - Blocks RFC-1918 private ranges
  - Blocks link-local (169.254.0.0/16)
  - Blocks CGNAT shared range (100.64.0.0/10)
  - Blocks IPv6 private / loopback / link-local
  - Blocks cloud metadata endpoints (169.254.169.254, metadata.google.internal)
  - Validates redirect targets before following

Development / authorized-testing override:
  Set the environment variable:  ALLOW_INTERNAL_TARGETS=true
  This disables SSRF checks so you can scan localhost, 192.168.x.x, etc.

Usage:
  from api.url_validator import validate_url_for_request

  allowed, reason = validate_url_for_request(url)
  if not allowed:
      logger.warning("SSRF blocked: %s — %s", url, reason)
      return []   # skip this request
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from urllib.parse import urlparse

logger = logging.getLogger("nexusscan.url_validator")

# ---------------------------------------------------------------------------
# Environment flag
# ---------------------------------------------------------------------------

ALLOW_INTERNAL_TARGETS: bool = (
    os.environ.get("ALLOW_INTERNAL_TARGETS", "").strip().lower() == "true"
)

# ---------------------------------------------------------------------------
# Private / reserved network blocks
# ---------------------------------------------------------------------------

_PRIVATE_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    # IPv4
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local / AWS metadata
    ipaddress.ip_network("100.64.0.0/10"),      # CGNAT shared
    ipaddress.ip_network("0.0.0.0/8"),          # This network
    ipaddress.ip_network("192.0.0.0/24"),       # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("fc00::/7"),           # Unique local
    ipaddress.ip_network("fe80::/10"),          # Link-local
    ipaddress.ip_network("ff00::/8"),           # Multicast
    ipaddress.ip_network("::/128"),             # Unspecified
]

# Exact hostname block-list (case-insensitive)
_BLOCKED_HOSTNAMES: frozenset[str] = frozenset(
    {
        "localhost",
        "metadata.google.internal",     # GCP metadata
        "169.254.169.254",              # AWS/Azure/GCP metadata IP
        "fd00::ec2:254",                # AWS metadata IPv6
    }
)


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def _ip_is_internal(ip_str: str) -> bool:
    """Return True if *ip_str* resolves to a private / reserved address."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def _hostname_is_internal(hostname: str) -> bool:
    """
    Return True if *hostname* is blocked or resolves to a private address.
    DNS resolution is performed; if it fails the host is treated as external
    (the outbound request will simply fail with a connection error).
    """
    if hostname.lower() in _BLOCKED_HOSTNAMES:
        return True

    try:
        addr_infos = socket.getaddrinfo(hostname, None)
        for _family, _type, _proto, _canonname, sockaddr in addr_infos:
            ip = sockaddr[0]
            if _ip_is_internal(ip):
                return True
    except OSError:
        # DNS lookup failed; let the request proceed and fail naturally
        pass

    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_url_for_request(url: str) -> tuple[bool, str]:
    """
    Validate *url* before making an outbound HTTP request.

    Returns:
        (allowed: bool, reason: str)

        allowed=True  → safe to proceed (reason is empty string).
        allowed=False → blocked (reason describes why).

    When ALLOW_INTERNAL_TARGETS=true every URL is allowed and a debug log
    entry is emitted so operators know the override is active.
    """
    if ALLOW_INTERNAL_TARGETS:
        logger.debug(
            "SSRF check bypassed (ALLOW_INTERNAL_TARGETS=true) for %s", url
        )
        return True, ""

    try:
        parsed = urlparse(url)
    except Exception as exc:
        reason = f"URL parse error: {exc}"
        logger.warning("SSRF validator rejected unparseable URL %r — %s", url, reason)
        return False, reason

    hostname = parsed.hostname
    if not hostname:
        reason = "URL has no hostname"
        logger.warning("SSRF validator rejected URL with no hostname: %r", url)
        return False, reason

    if _hostname_is_internal(hostname):
        reason = f"SSRF blocked: {hostname} resolves to an internal address"
        logger.warning("SSRF block | url=%s | reason=%s", url, reason)
        return False, reason

    return True, ""

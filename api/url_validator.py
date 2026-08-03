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
  - DNS-pinning: hostname is resolved ONCE at validation time; the caller
    receives the resolved IP and must use it for the actual request so that a
    second DNS response (DNS rebinding) cannot redirect traffic to an internal
    address.

Development / authorized-testing override:
  Set the environment variable:  ALLOW_INTERNAL_TARGETS=true
  This disables SSRF checks so you can scan localhost, 192.168.x.x, etc.

Usage (preferred – DNS-pinning safe):
  from api.url_validator import resolve_and_validate_url

  allowed, reason, resolved_ip = resolve_and_validate_url(url)
  if not allowed:
      logger.warning("SSRF blocked: %s — %s", url, reason)
      return []   # skip this request
  # pass resolved_ip to the transport layer (see scanner.py DNSPinningAdapter)

Legacy usage (no DNS-pinning, kept for compatibility):
  from api.url_validator import validate_url_for_request

  allowed, reason = validate_url_for_request(url)
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


def _resolve_hostname(hostname: str) -> list[str]:
    """
    Resolve *hostname* to a list of IP address strings.
    Returns an empty list if resolution fails.
    """
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
        return [sockaddr[0] for (_family, _type, _proto, _canonname, sockaddr) in addr_infos]
    except OSError:
        return []


def _hostname_is_internal(hostname: str) -> tuple[bool, list[str]]:
    """
    Return (is_internal, resolved_ips).

    is_internal=True  → hostname is blocked or resolves to a private address.
    resolved_ips      → list of IPs obtained during this single DNS call
                        (empty if resolution failed or host is in the static
                        block-list without needing a lookup).

    Callers MUST pin their HTTP connections to one of these IPs so that a
    subsequent DNS rebind cannot redirect traffic to an internal address.
    """
    if hostname.lower() in _BLOCKED_HOSTNAMES:
        return True, []

    resolved_ips = _resolve_hostname(hostname)

    if not resolved_ips:
        # DNS lookup failed; let the request proceed and fail naturally
        return False, []

    for ip in resolved_ips:
        if _ip_is_internal(ip):
            return True, resolved_ips

    return False, resolved_ips


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def resolve_and_validate_url(url: str) -> tuple[bool, str, str | None]:
    """
    Validate *url* before making an outbound HTTP request **and** return the
    pre-resolved IP address so the caller can pin the connection.

    DNS-pinning rationale
    ---------------------
    Calling ``socket.getaddrinfo`` at validation time and then letting
    ``requests`` do its own resolution later opens a DNS-rebinding window:
    the attacker's TTL expires between the two calls and the second DNS
    response points to an internal address.  By resolving once here and
    returning the IP, callers can bypass DNS entirely for the real request
    (see ``DNSPinningAdapter`` in scanner.py), closing that window.

    Returns:
        (allowed: bool, reason: str, resolved_ip: str | None)

        allowed=True  → safe to proceed; resolved_ip is the first non-internal
                        IP string (IPv4 or IPv6) to connect to.
        allowed=False → blocked; reason describes why; resolved_ip is None.

    When ALLOW_INTERNAL_TARGETS=true every URL is allowed, resolved_ip is None
    (no pinning – useful only in dev/test), and a debug log entry is emitted.
    """
    if ALLOW_INTERNAL_TARGETS:
        logger.debug(
            "SSRF check bypassed (ALLOW_INTERNAL_TARGETS=true) for %s", url
        )
        return True, "", None

    try:
        parsed = urlparse(url)
    except Exception as exc:
        reason = f"URL parse error: {exc}"
        logger.warning("SSRF validator rejected unparseable URL %r — %s", url, reason)
        return False, reason, None

    hostname = parsed.hostname
    if not hostname:
        reason = "URL has no hostname"
        logger.warning("SSRF validator rejected URL with no hostname: %r", url)
        return False, reason, None

    is_internal, resolved_ips = _hostname_is_internal(hostname)
    if is_internal:
        reason = f"SSRF blocked: {hostname} resolves to an internal address"
        logger.warning("SSRF block | url=%s | reason=%s", url, reason)
        return False, reason, None

    # Return the first resolved IP for the caller to pin to.
    resolved_ip = resolved_ips[0] if resolved_ips else None
    return True, "", resolved_ip


def validate_url_for_request(url: str) -> tuple[bool, str]:
    """
    Legacy two-value wrapper around ``resolve_and_validate_url``.

    Prefer ``resolve_and_validate_url`` for new call-sites so you get the
    pre-resolved IP and can use DNS pinning.

    Returns:
        (allowed: bool, reason: str)
    """
    allowed, reason, _ip = resolve_and_validate_url(url)
    return allowed, reason

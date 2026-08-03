"""
api/scanner.py
==============
Website Security Scanner Module

Performs rule-based security checks on a target URL so the combined finding
list feeds the risk-scorer.

Checks:
  - URL phishing heuristics (typosquatting, shorteners, suspicious TLDs, etc.)
  - Sensitive file exposure
  - Security header analysis
  - HTTPS redirect configuration
  - Directory listing detection
  - HTTP method analysis

SSRF protection is applied to every outbound request via url_validator.
"""

from __future__ import annotations

import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

try:
    from .phishing_heuristics import analyze_phishing_heuristics
except ImportError:
    from phishing_heuristics import analyze_phishing_heuristics

try:
    from .url_validator import validate_url_for_request, resolve_and_validate_url
except ImportError:
    from url_validator import validate_url_for_request, resolve_and_validate_url

logger = logging.getLogger("nexusscan.scanner")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/91.0.4472.124 Safari/537.36"
)
REQUEST_TIMEOUT  = 10  # seconds
REQUEST_DELAY    = 1   # seconds; only applied on 403/429 responses

SENSITIVE_PATHS = [
    "/.git/HEAD", "/.env", "/.htaccess", "/backup.zip", "/wp-config.php",
    "/appsettings.json", "/.DS_Store", "/phpinfo.php",
]

# ---------------------------------------------------------------------------
# DNS-pinning transport adapter
# ---------------------------------------------------------------------------

class _DNSPinningHTTPSAdapter(requests.adapters.HTTPAdapter):
    """
    A ``requests`` transport adapter that bypasses DNS at connection time.

    Motivation
    ----------
    ``url_validator.resolve_and_validate_url`` resolves the hostname *once* and
    verifies the resulting IP is not internal.  If we then let ``requests`` /
    urllib3 do their own DNS lookup for the actual TCP connection, an attacker
    with a very short TTL can serve a *different* A-record pointing to
    127.0.0.1 (DNS rebinding).  This adapter closes that window: it replaces
    the hostname in the URL with the already-validated IP *before* urllib3 ever
    talks to a resolver, and puts the original hostname back in the ``Host``
    header so TLS SNI and virtual hosting still work correctly.
    """

    def __init__(self, resolved_ip: str, hostname: str, **kwargs):
        self._resolved_ip = resolved_ip
        self._hostname    = hostname
        super().__init__(**kwargs)

    def send(self, request, **kwargs):  # type: ignore[override]
        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(request.url)
        # Substitute the hostname with the pinned IP.  Preserve the port if
        # one was explicitly specified in the original URL.
        port       = parsed.port
        netloc_ip  = f"[{self._resolved_ip}]" if ":" in self._resolved_ip else self._resolved_ip
        if port:
            netloc_ip = f"{netloc_ip}:{port}"

        pinned_url = urlunparse(parsed._replace(netloc=netloc_ip))
        request.url = pinned_url

        # Restore the original Host header so TLS SNI / vhosts work.
        request.headers["Host"] = self._hostname

        return super().send(request, **kwargs)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    return s


def _make_pinned_session(url: str, resolved_ip: str) -> requests.Session:
    """
    Build a ``requests.Session`` that pins all connections for *url* to
    *resolved_ip*, bypassing any further DNS lookups (DNS-rebinding defence).
    """
    from urllib.parse import urlparse
    parsed   = urlparse(url)
    hostname = parsed.hostname or ""
    adapter  = _DNSPinningHTTPSAdapter(resolved_ip=resolved_ip, hostname=hostname)
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    s.mount("https://", adapter)
    s.mount("http://",  adapter)
    return s


def _ssrf_guard(url: str) -> tuple[bool, str | None]:
    """
    Return (allowed, resolved_ip).

    allowed=True  → safe to proceed; resolved_ip is the IP to pin to (may be
                    None when ALLOW_INTERNAL_TARGETS=true).
    allowed=False → blocked; resolved_ip is None.
    """
    allowed, reason, resolved_ip = resolve_and_validate_url(url)
    if not allowed:
        logger.warning("Outbound request blocked | %s", reason)
    return allowed, resolved_ip


def normalize_url(url: str) -> str:
    """Ensure URL has a scheme and return base origin."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_sensitive_files(target_url: str) -> list[str]:
    findings: list[str] = []
    for path in SENSITIVE_PATHS:
        full_url = target_url + path
        allowed, resolved_ip = _ssrf_guard(full_url)
        if not allowed:
            continue
        session = _make_pinned_session(full_url, resolved_ip) if resolved_ip else _make_session()
        try:
            resp = session.get(
                full_url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )
            # 200/206 with a non-empty body → file genuinely served.
            # Body-length guard filters empty catch-all 200 responses from
            # CDNs that return 200 for every path with a JS redirect in the
            # body (those still have content, but we at least require > 0).
            if resp.status_code in (200, 206) and len(resp.content) > 0:
                findings.append(f"Exposed sensitive file: {full_url}")
                logger.info("Sensitive file exposed: %s", full_url)
            # 301/302 redirecting to a login/auth page is a common server
            # pattern that hides the file behind authentication rather than
            # returning 403 — the path still exists and is worth flagging.
            elif resp.status_code in (301, 302):
                location = resp.headers.get("Location", "").lower()
                if any(kw in location for kw in ("login", "auth", "signin", "sign-in")):
                    findings.append(
                        f"Sensitive file redirects to auth page (possible exposure): {full_url}"
                    )
                    logger.info("Sensitive file behind auth redirect: %s -> %s", full_url, location)
            if REQUEST_DELAY > 0 and resp.status_code in (403, 429):
                time.sleep(REQUEST_DELAY)
        except requests.RequestException as exc:
            logger.debug("Sensitive-file check failed for %s: %s", full_url, exc)
            continue
    return findings


def check_common_misconfigurations(target_url: str) -> list[str]:
    findings: list[str] = []
    allowed, resolved_ip = _ssrf_guard(target_url)
    if not allowed:
        return findings

    session = _make_pinned_session(target_url, resolved_ip) if resolved_ip else _make_session()
    try:
        root_resp = session.get(target_url, timeout=REQUEST_TIMEOUT)
        if "Index of /" in root_resp.text:
            findings.append("Directory listing enabled at root")
            logger.info("Directory listing found at %s", target_url)

        security_headers = {
            "Strict-Transport-Security": "Missing HSTS header",
            "Content-Security-Policy":   "Missing CSP header",
            "X-Content-Type-Options":    "Missing X-Content-Type-Options header",
            "X-Frame-Options":           "Missing X-Frame-Options header",
        }
        for header, message in security_headers.items():
            if header not in root_resp.headers:
                findings.append(message)

        options_resp = session.options(target_url, timeout=REQUEST_TIMEOUT)
        if "TRACE" in options_resp.headers.get("Allow", ""):
            findings.append("TRACE method enabled (potential XST vulnerability)")
            logger.warning("TRACE method enabled at %s", target_url)

        if REQUEST_DELAY > 0 and (
            root_resp.status_code in (403, 429)
            or options_resp.status_code in (403, 429)
        ):
            time.sleep(REQUEST_DELAY)

    except requests.RequestException as exc:
        logger.debug("Misconfiguration check error for %s: %s", target_url, exc)

    return findings


def check_https_redirect(target_url: str) -> list[str]:
    findings: list[str] = []
    if not target_url.startswith("http://"):
        return findings

    https_url = target_url.replace("http://", "https://", 1)

    allowed_https, resolved_ip_https = _ssrf_guard(https_url)
    if not allowed_https:
        return findings

    try:
        session_https = _make_pinned_session(https_url, resolved_ip_https) if resolved_ip_https else _make_session()
        session_https.get(
            https_url,
            timeout=REQUEST_TIMEOUT,
        )
    except Exception:
        findings.append("HTTPS version inaccessible")
        return findings

    allowed_http, resolved_ip_http = _ssrf_guard(target_url)
    if not allowed_http:
        return findings

    try:
        session_http = _make_pinned_session(target_url, resolved_ip_http) if resolved_ip_http else _make_session()
        resp = session_http.get(
            target_url,
            allow_redirects=False,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code not in (301, 302) or not resp.headers.get(
            "Location", ""
        ).startswith("https://"):
            findings.append("HTTP does not redirect to HTTPS")
    except Exception as exc:
        logger.debug("HTTPS redirect check error for %s: %s", target_url, exc)

    return findings



# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def scan_website(url: str) -> list[str]:
    """Run all rule-based checks concurrently for faster scan times."""
    normalized_url = normalize_url(url)
    logger.info("Scan started | url=%s | normalized=%s", url, normalized_url)

    checks = [
        lambda: analyze_phishing_heuristics(url),
        lambda: check_sensitive_files(normalized_url),
        lambda: check_common_misconfigurations(normalized_url),
        lambda: check_https_redirect(normalized_url),
    ]

    results: list[str] = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(c) for c in checks]
        for future in as_completed(futures):
            try:
                results.extend(future.result())
            except Exception as exc:
                logger.warning("Security check failed: %s", exc)

    logger.info(
        "Scan finished | url=%s | findings=%d",
        url, len(results),
    )

    return results if results else ["No critical vulnerabilities found"]

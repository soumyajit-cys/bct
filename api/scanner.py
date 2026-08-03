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
  - Breached domain verification (HIBP v3)
  - HTTP method analysis

SSRF protection is applied to every outbound request via url_validator.
"""

from __future__ import annotations

import json
import logging
import os
import time
from urllib.parse import urlparse

import requests

try:
    from .phishing_heuristics import analyze_phishing_heuristics
except ImportError:
    from phishing_heuristics import analyze_phishing_heuristics

try:
    from .url_validator import validate_url_for_request
except ImportError:
    from url_validator import validate_url_for_request

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
BREACHES_TIMEOUT = 15  # HIBP can be slow
REQUEST_DELAY    = 1   # seconds; only applied on 403/429 responses

SENSITIVE_PATHS = [
    "/.git/HEAD", "/.env", "/.htaccess", "/backup.zip", "/wp-config.php",
    "/appsettings.json", "/.DS_Store", "/phpinfo.php",
]

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    return s


def _ssrf_guard(url: str) -> bool:
    """
    Return True if the request is allowed.
    Logs and returns False if SSRF-blocked.
    """
    allowed, reason = validate_url_for_request(url)
    if not allowed:
        logger.warning("Outbound request blocked | %s", reason)
    return allowed


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
    session = _make_session()
    for path in SENSITIVE_PATHS:
        full_url = target_url + path
        if not _ssrf_guard(full_url):
            continue
        try:
            resp = session.get(
                full_url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )
            if resp.status_code == 200:
                findings.append(f"Exposed sensitive file: {full_url}")
                logger.info("Sensitive file exposed: %s", full_url)
            if REQUEST_DELAY > 0 and resp.status_code in (403, 429):
                time.sleep(REQUEST_DELAY)
        except requests.RequestException as exc:
            logger.debug("Sensitive-file check failed for %s: %s", full_url, exc)
            continue
    return findings


def check_common_misconfigurations(target_url: str) -> list[str]:
    findings: list[str] = []
    if not _ssrf_guard(target_url):
        return findings

    session = _make_session()
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

    if not _ssrf_guard(https_url):
        return findings

    try:
        requests.get(
            https_url,
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
    except Exception:
        findings.append("HTTPS version inaccessible")
        return findings

    if not _ssrf_guard(target_url):
        return findings

    try:
        resp = requests.get(
            target_url,
            headers={"User-Agent": USER_AGENT},
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


def check_breached_credentials(target_url: str) -> list[str]:
    """
    Check the domain against Have I Been Pwned v3 breach API.

    Requires:  HIBP_API_KEY environment variable (free key from haveibeenpwned.com).
    If the key is absent, returns an informational finding instead of silently
    skipping.
    """
    domain  = urlparse(target_url).netloc
    api_key = os.environ.get("HIBP_API_KEY", "").strip()

    if not api_key:
        logger.info("HIBP_API_KEY not set — breach check skipped for %s", domain)
        return ["HIBP breach check skipped (HIBP_API_KEY not configured)"]

    # Sanitise the domain to prevent URL injection into the HIBP query string.
    # Only allow hostname characters: alphanumeric, dot, hyphen.
    import re as _re
    safe_domain = _re.sub(r"[^a-zA-Z0-9.\x2d]", "", domain)
    if not safe_domain:
        logger.warning("HIBP check skipped — no safe domain extracted from %s", target_url)
        return ["HIBP breach check skipped (invalid domain)"]
    api_url = f"https://haveibeenpwned.com/api/v3/breaches?domain={safe_domain}"

    if not _ssrf_guard(api_url):
        return []

    headers = {
        "User-Agent":   USER_AGENT,
        "hibp-api-key": api_key,
    }

    try:
        resp = requests.get(api_url, headers=headers, timeout=BREACHES_TIMEOUT)

        if resp.status_code == 401:
            logger.error("HIBP API returned 401 — check HIBP_API_KEY value")
            return ["HIBP breach check failed (invalid API key)"]

        if resp.status_code == 429:
            logger.warning("HIBP API rate-limited for domain %s", domain)
            return ["HIBP breach check skipped (rate limited — retry later)"]

        if resp.status_code == 404:
            # HIBP returns 404 when no breaches are found
            return []

        if resp.status_code != 200:
            logger.warning("HIBP API unexpected status %d for %s", resp.status_code, domain)
            return [f"HIBP breach check failed (HTTP {resp.status_code})"]

        breaches = json.loads(resp.text)
        if breaches:
            names = [b["Name"] for b in breaches]
            logger.info("HIBP breaches found for %s: %s", domain, names)
            return [f"Domain breached in: {', '.join(names)}"]

    except json.JSONDecodeError as exc:
        logger.error("HIBP response parse error for %s: %s", domain, exc)
        return ["HIBP breach check failed (invalid response)"]
    except requests.RequestException as exc:
        logger.error("HIBP network error for %s: %s", domain, exc)
        return ["HIBP breach check failed (network error)"]
    except Exception as exc:
        logger.error("HIBP unexpected error for %s: %s", domain, exc)
        return ["HIBP breach check failed (unexpected error)"]

    return []


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def scan_website(url: str) -> list[str]:
    """Run all rule-based checks."""
    normalized_url = normalize_url(url)
    logger.info("Scan started | url=%s | normalized=%s", url, normalized_url)

    results: list[str] = []
    results.extend(analyze_phishing_heuristics(url))
    results.extend(check_sensitive_files(normalized_url))
    results.extend(check_common_misconfigurations(normalized_url))
    results.extend(check_https_redirect(normalized_url))
    results.extend(check_breached_credentials(normalized_url))

    logger.info(
        "Scan finished | url=%s | findings=%d",
        url, len(results),
    )

    return results if results else ["No critical vulnerabilities found"]

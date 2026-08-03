"""
api/phishing_heuristics.py
==========================
Rule-based URL phishing heuristics for NexusScan.

Ported from the frontend analyzer.  Runs purely on the URL string — no network
requests.  Each check returns a human-readable finding string that the shared
scorer (api/scoring.py) maps to risk points.

Checks:
  - Raw IPv4/IPv6 host
  - HTTPS absence
  - '@' credential-phishing marker
  - Unusually long URL
  - Hyphens in hostname + subdomain nesting
  - Typosquatting against known brands (Levenshtein similarity)
  - High-entropy first label (possible randomization)
  - Known URL shorteners
  - Suspicious TLDs
  - Suspicious keywords in path/query
  - Punycode hostname
  - Non-standard port
"""

from __future__ import annotations

import ipaddress
import logging
import math
import re
from urllib.parse import urlparse

logger = logging.getLogger("nexusscan.phishing_heuristics")

# ---------------------------------------------------------------------------
# Reference lists
# ---------------------------------------------------------------------------

KNOWN_BRANDS = [
    "paypal", "ebay", "amazon", "google", "facebook", "microsoft",
    "apple", "chase", "wellsfargo", "citibank", "netflix", "instagram",
    "linkedin", "twitter", "yahoo", "dropbox", "adobe", "steam",
    "bankofamerica", "americanexpress", "whatsapp", "outlook", "skype",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
    "tiny.cc", "lnkd.in", "kutt.it", "v.gd", "tny.im", "qr.ae",
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".club",
    ".click", ".link", ".buzz", ".work", ".loan", ".men", ".win",
    ".zip", ".country", ".kim", ".rest", ".download", ".online",
]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "account", "update", "verify",
    "secure", "banking", "password", "confirm", "wallet", "credential",
    "suspended", "unlock", "billing", "invoice", "reward", "gift",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _levenshtein(a: str, b: str) -> int:
    """Levenshtein edit distance between two strings."""
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(
                min(
                    prev[j] + 1,
                    cur[j - 1] + 1,
                    prev[j - 1] + (0 if ca == cb else 1),
                )
            )
        prev = cur
    return prev[-1]


def _entropy(text: str) -> float:
    """Shannon entropy (bits per character) of a string."""
    if not text:
        return 0.0
    total = len(text)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in (text.count(ch) for ch in set(text))
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_phishing_heuristics(raw_url: str) -> list[str]:
    """
    Run the rule-based heuristics on a URL.

    Returns a list of finding strings (empty when nothing is suspicious).
    """
    url = raw_url.strip()
    if not re.match(r"^\w+://", url):
        url = "http://" + url

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    findings: list[str] = []

    # ---- Raw IP address check ----
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 4:
            findings.append("Host is a raw IPv4 address")
        else:
            findings.append("Host is a raw IPv6 address")
    except ValueError:
        pass

    # ---- HTTPS check ----
    if parsed.scheme != "https":
        findings.append("URL is not using HTTPS")

    # ---- '@' symbol check ----
    if "@" in url:
        findings.append("URL contains an '@' symbol (possible credential phishing)")

    # ---- URL length check ----
    if len(url) > 75:
        findings.append("URL is very long (>75 characters)")
    elif len(url) > 50:
        findings.append("URL is unusually long (>50 characters)")

    # ---- Hyphens & subdomain nesting ----
    labels = [label for label in host.split(".") if label]
    first_label = labels[0] if labels else ""
    hyphen_count = first_label.count("-")
    subdomain_count = max(0, len(labels) - 2)

    if hyphen_count >= 2:
        findings.append("Hostname contains multiple hyphens")
    elif hyphen_count == 1:
        findings.append("Hostname contains a hyphen")

    if subdomain_count >= 3:
        findings.append("URL uses an excessive number of subdomains")
    elif subdomain_count == 2:
        findings.append("URL uses nested subdomains")

    # ---- Typosquat detection ----
    normalized_label = re.sub(r"^www\.", "", first_label)
    for brand in KNOWN_BRANDS:
        if normalized_label == brand:
            continue
        dist = _levenshtein(normalized_label, brand)
        max_len = max(len(normalized_label), len(brand))
        similarity = 1 - (dist / max_len) if max_len else 0
        if dist <= 2 and similarity >= 0.7:
            findings.append(f"Hostname resembles a known brand ({brand})")
            break

    # ---- Entropy check ----
    if len(first_label) >= 8 and _entropy(first_label) >= 3.8:
        findings.append("First hostname label has high entropy (possible randomization)")

    # ---- Shortener / suspicious TLD / suspicious keywords ----
    path_text = f"{parsed.path} {parsed.query}".lower()

    for shortener in URL_SHORTENERS:
        if shortener in host:
            findings.append("Uses a known URL shortener")
            break

    for suspicious_tld in SUSPICIOUS_TLDS:
        if host.endswith(suspicious_tld):
            findings.append(f"Uses a suspicious TLD ({suspicious_tld})")
            break

    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path_text]
    if keyword_hits:
        findings.append("Contains suspicious keywords: " + ", ".join(keyword_hits[:3]))

    # ---- Punycode / non-standard port ----
    if "xn--" in host:
        findings.append("Hostname uses punycode")

    try:
        port = parsed.port
    except ValueError:
        port = None
    if port and port not in (80, 443):
        findings.append("Uses a non-standard port")

    if findings:
        logger.info("Phishing heuristics | url=%s | hits=%d", raw_url, len(findings))

    return findings

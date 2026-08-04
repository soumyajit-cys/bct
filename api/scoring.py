"""
api/scoring.py
==============
Shared risk-scoring and analysis-text generation logic.

Imported by both:
  - api/index.py  (Vercel serverless entry-point)
  - app.py        (local Flask dev server)

Keeping this in a single place means any change to scoring or reporting
automatically applies to both deployment paths.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

# Scoring weights — recalibrated so informational/administrative findings
# (missing optional headers) do not inflate scores.
#
# Bands:   0–24 Low | 25–49 Moderate | 50–74 High | 75–100 Critical

_SCORE_RULES: list[tuple[str, int, str]] = [
    # pattern-in-finding          points  label
    ("Exposed sensitive file",    25,     "Exposed sensitive file"),
    ("TRACE method enabled",      15,     "TRACE method enabled"),
    ("Directory listing",         12,     "Directory listing exposed"),
    ("HTTP does not redirect",     8,     "Missing HTTPS redirect"),
    ("HTTPS version inaccessible", 8,     "HTTPS unavailable"),
    ("Missing HSTS",               6,     "Missing HSTS header"),
    ("Missing CSP",                5,     "Missing CSP header"),
    ("Missing X-Content-Type",     3,     "Missing X-Content-Type-Options"),
    ("Missing X-Frame",            3,     "Missing X-Frame-Options"),
    ("credentials",               20,     "Exposed credentials"),
    ("Exposed admin panel",       10,     "Exposed admin panel"),
    # ---- URL phishing heuristics (ported from the frontend analyzer) ----
    ("Host is a raw IPv4",        20,     "Raw IPv4 address host"),
    ("Host is a raw IPv6",        20,     "Raw IPv6 address host"),
    ("URL is not using HTTPS",    10,     "URL not using HTTPS"),
    ("URL contains an '@'",       15,     "Credential-phishing marker"),
    ("URL is very long",          30,     "Very long URL"),
    ("URL is unusually long",     20,     "Unusually long URL"),
    ("multiple hyphens",          12,     "Multiple hyphens in hostname"),
    ("contains a hyphen",          6,     "Hyphen in hostname"),
    ("excessive number of subdomains", 12, "Excessive subdomains"),
    ("nested subdomains",          8,     "Nested subdomains"),
    ("resembles a known brand",   25,     "Suspected typosquatting"),
    ("high entropy",              10,     "High-entropy hostname"),
    ("known URL shortener",       20,     "URL shortener used"),
    ("suspicious TLD",            15,     "Suspicious TLD"),
    ("punycode",                  15,     "Punycode hostname"),
    ("non-standard port",         10,     "Non-standard port"),
]

# Administrative/informational findings that should NOT raise the risk score.
_ZERO_SCORE_PATTERNS: tuple[str, ...] = (
    "No critical vulnerabilities",
)


def calculate_risk_score(findings: list[str]) -> tuple[int, list[dict]]:
    """
    Rule-based scoring.

    Returns:
        (score: int in [0, 100], breakdown: list[{finding, points, label}])
    """
    score = 0
    breakdown: list[dict] = []

    for f in findings:
        # ── Zero-score administrative/informational findings ────────────────
        if any(pat in f for pat in _ZERO_SCORE_PATTERNS):
            breakdown.append({"finding": f, "points": 0, "label": "Informational"})
            continue

        # ── Semi-dynamic rule: suspicious keywords scale with hit count ──────
        # Mirrors the original JS: points = min(20, 8 + hits * 4).
        if "Contains suspicious keywords" in f:
            hits = f.count(", ") + 1
            pts  = min(20, 8 + hits * 4)
            breakdown.append(
                {
                    "finding": f,
                    "points":  pts,
                    "label":   "Suspicious keywords",
                }
            )
            score += pts
            continue

        # ── Rule-based findings ─────────────────────────────────────────────
        matched = False
        for pattern, pts, label in _SCORE_RULES:
            if pattern in f or (pattern == "credentials" and pattern in f.lower()):
                breakdown.append({"finding": f, "points": pts, "label": label})
                score += pts
                matched = True
                break

        if not matched:
            # Unknown/other — small informational weight
            breakdown.append({"finding": f, "points": 2, "label": "Other finding"})
            score += 2

    return min(score, 100), breakdown


def verdict_for_score(score: int) -> str:
    """Map a numeric score to the recalibrated four-tier verdict."""
    if score >= 75:
        return "Critical Risk"
    if score >= 50:
        return "High Risk"
    if score >= 25:
        return "Moderate Risk"
    return "Low Risk"


# ---------------------------------------------------------------------------
# Analysis text
# ---------------------------------------------------------------------------

def generate_analysis(findings: list[str], risk_score: int) -> str:
    if not findings:
        return (
            "Threat Assessment\n\n"
            "No critical vulnerabilities detected.\n"
            "The target appears to follow baseline security practices.\n\n"
            "Recommendations\n"
            "* Schedule periodic re-scans as your infrastructure evolves\n"
            "* Implement all recommended security headers\n"
            "* Enable HSTS preloading for maximum transport security"
        )

    critical, warnings, recs = [], [], []
    for f in findings:
        if "Exposed sensitive file" in f:
            critical.append(f)
            recs.append("Remove or restrict access to exposed files immediately")
        elif "Directory listing" in f:
            warnings.append(f)
            recs.append("Disable directory listing in your web server configuration")
        elif "Missing" in f:
            warnings.append(f)
            recs.append("Implement missing security headers (see OWASP Secure Headers Project)")
        elif "URL is not using HTTPS" in f:
            warnings.append(f)
            recs.append("Do not enter credentials on pages served over plain HTTP")
        elif "HTTPS" in f or "HTTP does not" in f:
            warnings.append(f)
            recs.append("Configure a permanent 301 redirect from HTTP to HTTPS")
        elif "TRACE method" in f:
            critical.append(f)
            recs.append("Disable the TRACE HTTP method in your server configuration")
        elif "raw IPv4" in f or "raw IPv6" in f or "URL contains an '@'" in f:
            critical.append(f)
            recs.append("Avoid interacting with URLs hosted on raw IP addresses")
        elif "resembles a known brand" in f:
            critical.append(f)
            recs.append("Verify the exact domain before entering credentials (possible typosquatting)")
        elif "URL shortener" in f:
            critical.append(f)
            recs.append("Expand shortened URLs with a preview service before visiting")
        elif "suspicious TLD" in f:
            warnings.append(f)
            recs.append("Treat suspicious top-level domains with caution")
        elif "punycode" in f:
            warnings.append(f)
            recs.append("Decode punycode hostnames before trusting the destination")
        elif "keywords" in f or "high entropy" in f or "hyphen" in f \
                or "subdomain" in f or "non-standard port" in f or "long" in f:
            warnings.append(f)
            recs.append("Verify the URL source before entering any personal information")
        else:
            warnings.append(f)

    lines: list[str] = ["Threat Assessment\n"]
    if critical:
        lines.append("CRITICAL ISSUES\n" + "\n".join(f"* {i}" for i in critical))
    if warnings:
        lines.append("\nSECURITY WARNINGS\n" + "\n".join(f"* {i}" for i in warnings))
    if recs:
        lines.append(
            "\nRECOMMENDED ACTIONS\n"
            + "\n".join(f"* {r}" for r in dict.fromkeys(recs))
        )

    if risk_score >= 75:
        lines.append("\nCritical Risk — immediate remediation required.")
    elif risk_score >= 50:
        lines.append("\nHigh Risk — significant issues demand prompt attention.")
    elif risk_score >= 25:
        lines.append("\nModerate Risk — schedule remediation within your next sprint.")
    else:
        lines.append("\nLow Risk — address flagged items during routine maintenance.")

    lines.append(
        "\n\nGENERAL BEST PRACTICES\n"
        "* Keep all software and dependencies up to date\n"
        "* Deploy a Web Application Firewall (WAF)\n"
        "* Run automated vulnerability scans on every deployment\n"
        "* Use strong TLS 1.2+ with modern cipher suites"
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Structured findings (replaces linkify_findings HTML-string approach)
# ---------------------------------------------------------------------------

def linkify_findings(findings: list[str]) -> list[dict]:
    """
    Return findings as structured dicts instead of HTML strings.

    Each dict has:
      "text"  – the full plain-text finding (safe for textContent assignment)
      "links" – list of URLs extracted from the text, in order of appearance

    The frontend renders links safely via createElement('a') + textContent,
    so no sanitiser bypass or XSS risk is possible.

    Previous behaviour (returning HTML anchor strings) caused sanitise() in the
    frontend to double-escape the tags, rendering them as visible text instead
    of clickable links.
    """
    processed: list[dict] = []
    url_re = re.compile(r"https?://\S+")

    for finding in findings:
        links = url_re.findall(finding)
        processed.append({"text": finding, "links": links})

    return processed

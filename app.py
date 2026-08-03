"""
NexusScan – Flask Application (local development server)
=========================================================
Serves the frontend and the /analyze threat-scanning endpoint.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path

from flask import Flask, render_template, request, jsonify, send_from_directory

# Allow `from api.xxx import ...` when running from the project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _load_local_env() -> None:
    """
    Lightweight `.env` loader for local development.
    Does not override variables already present in the process environment.
    """
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or key in os.environ:
            continue

        if (
            (value.startswith('"') and value.endswith('"'))
            or (value.startswith("'") and value.endswith("'"))
        ):
            value = value[1:-1]
        os.environ[key] = value


_load_local_env()

from api.scanner      import scan_website
from api.scoring      import calculate_risk_score, verdict_for_score, generate_analysis, linkify_findings
from api.rate_limiter import rate_limit_check
from api.llm_explainer import generate_explanation

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("nexusscan.app")

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__, static_folder="static", template_folder="templates")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("landing.html")


@app.route("/scan")
def scan_page():
    return render_template("index.html")


@app.route("/robots.txt")
def robots():
    return send_from_directory(app.static_folder, "robots.txt")


@app.route("/sitemap.xml")
def sitemap():
    return send_from_directory(
        app.static_folder, "sitemap.xml", mimetype="application/xml"
    )


@app.route("/analyze", methods=["POST"])
def analyze_url():
    # ── Rate limiting ────────────────────────────────────────────────────────
    allowed, rate_resp = rate_limit_check()
    if not allowed:
        return rate_resp  # type: ignore[return-value]

    url = ""
    try:
        data = request.get_json(force=True)
        url  = (data.get("url") or "").strip() if data else ""

        if not url:
            return jsonify({"error": "URL is required"}), 400

        logger.info("Scan request | url=%s", url)
        start_time = time.time()
        findings   = scan_website(url)
        elapsed    = time.time() - start_time

        risk_score, score_breakdown = calculate_risk_score(findings)
        verdict    = verdict_for_score(risk_score)
        is_risky   = risk_score >= 25
        analysis   = generate_analysis(findings, risk_score)
        processed  = linkify_findings(findings)
        scan_time  = f"{elapsed:.2f}s"

        # LLM plain-English explanation (non-blocking; falls back gracefully)
        ai_report  = generate_explanation(url, risk_score, verdict, findings, scan_time)

        logger.info(
            "Scan complete | url=%s | score=%d | verdict=%s | elapsed=%.2fs | llm_fallback=%s | fallback_reason=%s",
            url, risk_score, verdict, elapsed, ai_report.get("is_fallback", True), ai_report.get("fallback_reason"),
        )

        return jsonify(
            {
                "is_risky":          is_risky,
                "risk_score":        risk_score,
                "verdict":           verdict,
                "message":           f"Found {len(findings)} security finding(s)",
                "analysis":          analysis,
                "technical_details": processed,
                "score_breakdown":   score_breakdown,
                "scan_time":         scan_time,
                "ai_report":         ai_report,
            }
        )

    except Exception:
        logger.exception("Unhandled error during scan of %s", url or "unknown")
        return (
            jsonify(
                {
                    "error":      "Analysis failed",
                    "is_risky":   True,
                    "risk_score": 100,
                    "verdict":    "Scan Failed",
                    "message":    "An error occurred during scanning",
                }
            ),
            500,
        )


# ---------------------------------------------------------------------------
# Local development entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)

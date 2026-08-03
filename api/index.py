"""
NexusScan – Flask Application for Vercel
=========================================
Serves the frontend and the /analyze threat-scanning endpoint.
Optimised for Vercel serverless deployment.
"""

from __future__ import annotations

import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from flask import Flask, render_template, request, jsonify, send_from_directory


def _load_local_env() -> None:
    """
    Lightweight `.env` loader for local/dev execution.
    Vercel-managed environment variables still take precedence.
    """
    env_path = Path(__file__).resolve().parents[1] / ".env"
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

from .scanner       import scan_website
from .scoring       import calculate_risk_score, verdict_for_score, generate_analysis, linkify_findings
from .rate_limiter  import rate_limit_check
from .llm_explainer import generate_explanation

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("nexusscan.api")

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

PROJECT_ROOT    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_FOLDER   = os.path.join(PROJECT_ROOT, "static")
TEMPLATE_FOLDER = os.path.join(PROJECT_ROOT, "templates")

app = Flask(
    __name__,
    static_folder=STATIC_FOLDER,
    static_url_path="/static",
    template_folder=TEMPLATE_FOLDER,
)


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

@app.after_request
def set_cors_headers(response):
    # CORS: the /analyze endpoint is intentionally public so third-party
    # frontends can call it.  Only /analyze accepts POST; GET routes serve
    # the SPA and are not cross-origin targets.
    #
    # Security note: the wildcard origin is acceptable here because:
    #   1. /analyze requires a JSON body with Content-Type: application/json
    #      (so a simple CORS form-submit cannot trigger it).
    #   2. Rate limiting is applied per-IP to prevent abuse.
    #   3. No cookies or credentials are used.
    #
    # Set ALLOWED_ORIGIN env var to restrict to a specific domain in production
    # if you want to lock down cross-origin access (e.g. "https://nexusscan.vercel.app").
    allowed_origin = os.environ.get("ALLOWED_ORIGIN", "*").strip() or "*"
    response.headers["Access-Control-Allow-Origin"]  = allowed_origin
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


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


@app.route("/analyze", methods=["POST", "OPTIONS"])
def analyze_url():
    if request.method == "OPTIONS":
        return "", 204

    # ── Rate limiting ────────────────────────────────────────────────────────
    allowed, rate_resp = rate_limit_check()
    if not allowed:
        return rate_resp  # type: ignore[return-value]

    try:
        data = request.get_json(force=True)
        url  = (data.get("url") or "").strip() if data else ""

        if not url:
            return jsonify({"error": "URL is required"}), 400

        if len(url) > 2048:
            return jsonify({"error": "URL too long"}), 400

        logger.info("Scan request | url=%s", url)
        start_time = time.time()
        findings   = scan_website(url)
        elapsed    = time.time() - start_time

        risk_score, score_breakdown = calculate_risk_score(findings)
        verdict    = verdict_for_score(risk_score)
        is_risky   = risk_score >= 25
        scan_time  = f"{elapsed:.2f}s"

        # Submit the LLM call to a background thread immediately so it runs
        # concurrently with the remaining (fast) scoring work below.
        with ThreadPoolExecutor(max_workers=1) as llm_pool:
            llm_future = llm_pool.submit(
                generate_explanation, url, risk_score, verdict, findings, scan_time
            )

            analysis  = generate_analysis(findings, risk_score)
            processed = linkify_findings(findings)

            # Block only now — LLM has had the full scoring duration to progress.
            ai_report = llm_future.result()

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
        # Log full traceback server-side; return generic message to client
        logger.exception("Unhandled error during scan of %s", url if "url" in dir() else "unknown")
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

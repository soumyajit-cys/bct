# NexusScan

A Flask-based web security scanner that analyses any URL for exposed files, security misconfigurations, and known data breaches — then explains the results in plain English using an AI report layer.

**Live Application → [nexusscan.vercel.app](https://nexusscan.vercel.app/)**

---

## What It Does

Paste or scan any URL and NexusScan runs a full security audit in seconds:

- Checks for exposed sensitive files (`.env`, `.git`, `wp-config.php`, etc.)
- Runs URL phishing heuristics (typosquatting, URL shorteners, suspicious TLDs, raw-IP hosts, keyword traps)
- Analyses security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
- Detects directory listing, TRACE method exposure, and missing HTTPS redirects
- Looks up the domain against the Have I Been Pwned breach database
- Generates an AI-written plain-English report so non-technical users understand the results
- Accepts URLs via typed input, live camera QR scan, or uploaded QR image

---

## Pages & Routes

| Route | Purpose |
|---|---|
| `/` | Marketing landing page — features, how it works, call-to-action |
| `/scan` | The scanner — paste a URL, scan a QR code, view the report |
| `/analyze` | API endpoint (POST) — returns the scan result as JSON |
| `/robots.txt`, `/sitemap.xml` | SEO files |

---

## How to Use (Deployed)

1. Visit **[nexusscan.vercel.app](https://nexusscan.vercel.app/)**
2. Click **Start Scanning** (or navigate to `/scan`)
3. Enter the URL you want to scan, or use the QR scanner to scan a code
4. Click **Scan**
5. Read the verdict, risk score, technical findings, and the AI-generated plain-English report

---

## Local Development

```bash
# 1. Clone and enter the project
cd NEXUSSCAN-main

# 2. Create and activate a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the local dev server
python app.py
```

Then open **http://localhost:5000** — the landing page is served at `/` and the scanner at `/scan`.

### Optional environment variables

Create a `.env` file in the project root (loaded automatically by `app.py` and `api/index.py`):

| Variable | Purpose |
|---|---|
| `HIBP_API_KEY` | Enables the data breach lookup (free key from [haveibeenpwned.com](https://haveibeenpwned.com/)) |
| `LLM_PROVIDER` | AI report provider — `groq` (default), `openai`, or `gemini` |
| `LLM_API_KEY` | API key for the chosen LLM provider |
| `LLM_MODEL` | Optional model override for the provider |
| `ALLOWED_ORIGIN` | CORS origin for `/analyze` (defaults to `*`) |

Without keys, the breach lookup and AI report gracefully fall back to deterministic results — the scan still works.

---

## Features

### Security Scanning (Rule-Based)
Performs the following checks on every scan:

| Check | What It Catches |
|---|---|
| Sensitive file exposure | `.env`, `.git/HEAD`, `wp-config.php`, `phpinfo.php`, backup archives, etc. |
| Security headers | Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
| HTTPS enforcement | Sites that don't redirect HTTP → HTTPS, or have no HTTPS at all |
| Directory listing | Open index pages that expose file structure |
| TRACE method | Servers with TRACE enabled (Cross-Site Tracing vulnerability) |
| Data breach lookup | Domain checked against Have I Been Pwned v3 API |

### Risk Score & Verdict
Every finding is weighted by severity and summed into a 0–100 risk score:

| Band | Score | Verdict |
|---|---|---|
| Low | 0 – 24 | Safe |
| Moderate | 25 – 49 | Caution advised |
| High | 50 – 74 | Significant risk |
| Critical | 75 – 100 | Dangerous |

The report includes a score breakdown showing exactly which findings contributed points.

### AI Plain-English Report
An optional LLM layer (supporting **Groq**, **OpenAI**, and **Gemini**) translates the raw scan findings into a structured report with:
- Executive summary (for non-technical readers)
- Why the site was flagged
- Recommended actions
- Technical summary
- Confidence note

The verdict and risk score are **never modified** by the LLM — it only explains what the scanner already decided. If the LLM is unavailable, a fully deterministic rule-based explanation is shown instead.

### QR Code Scanner
URLs can be submitted by scanning a QR code directly in the browser — either via live camera or by uploading a QR image file. Powered by [html5-qrcode v2.3.8](https://github.com/mebjas/html5-qrcode).

### Scan History
Previous scans are stored locally in the browser (`localStorage`, max 20 entries) and can be reopened or cleared from the History section on the scanner page.

### Rate Limiting & SSRF Protection
- Per-IP rate limiting (default: 30 requests/minute), backed by Redis when available
- All outbound HTTP requests are SSRF-guarded — private IP ranges, loopback, cloud metadata endpoints, and link-local addresses are blocked

---

## UI / Design

- Professional light theme (Stripe/Linear-inspired): clean surfaces, subtle borders and shadows, single blue accent
- **Inter** for UI typography, **JetBrains Mono** for URLs and code
- Fully responsive — desktop, tablet, and mobile layouts
- Risk gauge rendered with **Chart.js**; no account or tracking required

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Charts | Chart.js 4 |
| QR Scanning | html5-qrcode v2.3.8 |
| Fonts | Inter · JetBrains Mono (Google Fonts) |
| Deployment | Vercel (serverless via `api/index.py`) |
| Rate Limiting | In-process memory (default) or Redis |
| Breach Lookup | Have I Been Pwned API v3 |
| AI Reports | Groq / OpenAI / Google Gemini (configurable) |

---

## Project Structure

```
NEXUSSCAN/
├── app.py                  # Flask entry-point (local dev)
├── vercel.json             # Vercel serverless config
├── .vercelignore           # Files excluded from Vercel deploys
├── requirements.txt        # Python dependencies (local dev)
├── api/
│   ├── index.py            # Vercel serverless entry-point
│   ├── requirements.txt    # Python dependencies (Vercel)
│   ├── scanner.py          # Rule-based security checks + scan orchestrator
│   ├── scoring.py          # Risk scoring, verdict and analysis logic
│   ├── llm_explainer.py    # AI plain-English report layer
│   ├── rate_limiter.py     # Per-IP rate limiting (memory + Redis)
│   └── url_validator.py    # SSRF protection for all outbound requests
├── templates/
│   ├── landing.html        # Marketing landing page (/)
│   └── index.html          # Scanner page (/scan)
└── static/
    ├── script.js           # Frontend logic + QR scanner module
    ├── style.css           # Main stylesheet (shared design system)
    ├── landing.css         # Landing page styles
    ├── robots.txt
    └── sitemap.xml
```

---

## API

`POST /analyze`

```json
{ "url": "https://example.com" }
```

Returns the risk score, verdict, score breakdown, technical findings, and the AI report (see `app.py` for the full response shape).

---

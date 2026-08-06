# NexusScan — Full Code Audit Report

**Date:** 2026-08-04
**Scope:** All source files in `bct/`
**Auditor:** Antigravity (AI Code Audit)

---

## Table of Contents

1. [Dead / Unused Code](#1-dead--unused-code)
2. [Logic Bugs and Correctness Issues](#2-logic-bugs-and-correctness-issues)
3. [Security Issues](#3-security-issues)
4. [Performance Issues](#4-performance-issues)
5. [Dependency / Configuration Issues](#5-dependency--configuration-issues)
6. [HTML / Frontend Issues](#6-html--frontend-issues)
7. [Code Quality and Maintainability](#7-code-quality-and-maintainability)
8. [Summary Table](#8-summary-table)

---

## 1. Dead / Unused Code

### 1.1 `validate_url_for_request` imported but never called

**File:** `api/scanner.py` Lines 36-38

`validate_url_for_request` is imported in both the try-block and the except-block (fallback
bare import), but **nothing in `scanner.py` ever calls it**. Only `resolve_and_validate_url`
is used (via `_ssrf_guard`). The legacy wrapper exists purely for external consumers.

**Fix:** Remove `validate_url_for_request` from both import lines in `scanner.py`.

---

### 1.2 `debounce()` utility defined but never used

**File:** `static/script.js` Line 933

`debounce` is defined as a global utility but is never called anywhere in the file. No event
handler or function references it.

**Fix:** Remove the function, or wire it to the URL input keydown handler.

---

### 1.3 `QRScanner.destroy()` not exposed in the module return value

**File:** `static/script.js` Lines 800-802

`destroy` is declared inside the QRScanner IIFE but NOT included in the returned public API
object (`return { init, closePanel }`). It is unreachable from outside the module.

**Fix:** Either add `destroy` to the return object, or remove the function entirely.

---

### 1.4 `#loadingLabel` HTML element never updated by JS

**File:** `templates/index.html` Line 234

The element has `id="loadingLabel"` but `script.js` never references this ID. The text is static.

**Fix:** Remove the `id="loadingLabel"` attribute, or add dynamic status updates to the loading UI.

---

### 1.5 `#scoreBreakdownBlock` HTML ID never targeted

**File:** `templates/index.html` Line 336

The outer wrapper of the score breakdown section has `id="scoreBreakdownBlock"`. JS only queries
the inner `#scoreBreakdown` div. The outer ID is never accessed by any JS.

**Fix:** Remove the unused `id="scoreBreakdownBlock"` attribute.

---

### 1.6 `provider_cfg` intermediate variable is unnecessary

**File:** `api/llm_explainer.py` Lines 674-675

```python
provider_cfg = _DEFAULTS[provider]
model_used = model_override or provider_cfg["model"]
```

`provider_cfg` is a redundant local used only to derive `model_used`. It can be inlined:
`model_used = model_override or _DEFAULTS[provider]["model"]`

---

### 1.7 `result` variable immediately returned — one extra line

**File:** `api/llm_explainer.py` Lines 693-694

```python
result = generate_fallback_explanation(payload, reason="response_unparseable")
return result
```

The variable serves no purpose. Fix: return the call directly.

---

### 1.8 `ALLOWED_ORIGIN` env var documented but never read

**File:** `app.py` and `.env.example`

`.env.example` (line 72) documents `ALLOWED_ORIGIN` for CORS control, and the README lists it
as a supported variable. However, `app.py` **never reads** `ALLOWED_ORIGIN` and never sets
`Access-Control-Allow-Origin` on any response. The variable is silently ignored.

**Fix:** Either implement CORS header injection in `set_security_headers()`, or remove the
variable from `.env.example` and README to stop misleading operators.

---

## 2. Logic Bugs and Correctness Issues

### 2.1 Rate limiter double-counts hits when Redis is unavailable

**File:** `api/rate_limiter.py` Line 150

```python
allowed, count = _check_redis(ip, _RPM) if _redis_ok else _check_in_memory(ip, _RPM)
```

`_check_redis()` already falls back to `_check_in_memory()` when `_redis_ok` is False (line 96).
This ternary causes `_check_in_memory` to be called **twice** when Redis is unavailable: once in
the `else` branch and once inside `_check_redis`. Each call registers one hit, so a single
request burns two slots — prematurely exhausting the rate limit.

**Fix:** Simplify to `allowed, count = _check_redis(ip, _RPM)` and rely on the fallback already
inside `_check_redis`.

---

### 2.2 HTTP URLs always flagged insecure even when HTTPS redirect exists

**File:** `api/phishing_heuristics.py` Lines 131-132

```python
if parsed.scheme != "https":
    findings.append("URL is not using HTTPS")
```

If the user submits `http://example.com`, the phishing check flags it as insecure regardless of
whether `check_https_redirect` would confirm HTTPS is correctly enforced. This causes false
positives and score inflation for legitimate sites that simply accept both schemes.

**Fix:** Suppress this finding when a successful HTTP-to-HTTPS redirect is confirmed by the
`check_https_redirect` check.

---

### 2.3 Per-request `ThreadPoolExecutor` wasteful thread creation

**File:** `app.py` Lines 137-146

A new `ThreadPoolExecutor` is created, used for one task, and destroyed on every request. This
incurs thread-creation overhead on every scan. The `with` block blocks until the future completes,
so parallelism benefit is limited to overlapping with `generate_analysis` only.

**Fix:** Use a module-level `ThreadPoolExecutor` that persists across requests.

---

### 2.4 `check_https_redirect` makes up to 4 DNS lookups per scan

**File:** `api/scanner.py` Lines 307-346

The function calls `_ssrf_guard` twice (each resolving DNS): once for the HTTPS URL and once for
the HTTP URL. The HTTPS response is discarded without reading headers.

**Fix:** Cache the SSRF guard result / resolved IP from the first call, or combine both checks
into a single request pair.

---

### 2.5 `sanitize_url_for_log` does not strip ANSI / control characters

**File:** `api/log_utils.py` Line 24

The docstring claims control characters like `\x07` are sanitized, but the implementation only
strips `\r` and `\n`. Characters like `\x1b` (ANSI ESC) remain and can be used to manipulate
terminal log output (log injection, CWE-117).

**Fix:**
```python
import re
return re.sub(r'[\x00-\x1f\x7f]', lambda m: repr(m.group(0))[1:-1], value)[:max_len]
```

---

### 2.6 Sensitive file probe futures awaited in submission order

**File:** `api/scanner.py` Lines 227-232

```python
futures = [pool.submit(probe, path, ...) for path in SENSITIVE_PATHS + ADMIN_PATHS]
results = [f.result() for f in futures]
```

Awaiting in submission order means a slow probe for path #1 blocks processing of already-completed
later probes. `as_completed` is already imported (line 25) and should be used here instead.

**Fix:** `results = [f.result() for f in as_completed(futures)]`

---

### 2.7 JS 5-tier scale vs Python 4-tier verdict — UI color mismatch

**File:** `static/script.js` Lines 901-907 vs `api/scoring.py` Lines 117-125

The frontend `getTier(score)` returns 5 tiers (safe/low/medium/high/critical, split at 90). The
backend `verdict_for_score` produces only 4 tiers (Low/Moderate/High/Critical, split at 75). A
score of 80 displays "Critical Risk" text but renders in the orange `high` color, not the red
`critical` color. The `critical` CSS tier is unreachable in practice.

**Fix:** Align the frontend to 4 tiers, or add a 5th backend tier (e.g., >= 90 = "Extreme Risk").

---

## 3. Security Issues

### 3.1 No Content-Security-Policy on the app's own responses

**File:** `app.py` Lines 75-81

`set_security_headers` sets X-Content-Type-Options, X-Frame-Options, and HSTS but **no CSP**.
The scanner flags missing CSP on scanned websites, yet serves its own HTML without one.

**Fix:** Add a CSP header appropriate for the app's resources (Google Fonts, Chart.js, html5-qrcode CDNs).

---

### 3.2 External CDN scripts loaded without Subresource Integrity (SRI)

**File:** `templates/index.html` Lines 467-468

```html
<script src="https://cdnjs.cloudflare.com/.../chart.umd.min.js"></script>
<script src="https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js"></script>
```

No `integrity="sha384-..."` attributes. CDN compromise or URL hijacking could silently inject
malicious JavaScript into every user's browser.

**Fix:** Add `integrity` and `crossorigin="anonymous"` attributes to both script tags.

---

### 3.3 `localhost:5000` hardcoded in canonical, OG, and JSON-LD tags

**Files:** Both templates (lines 9-15, 38-39)

All canonical URLs, Open Graph URLs, and JSON-LD document URLs are hardcoded to
`http://localhost:5000`. In production, this tells search engines and social media scrapers the
canonical URL is `localhost` — incorrect and leaks the dev port.

**Fix:** Use Jinja2: `<link rel="canonical" href="{{ request.host_url }}" />`

---

### 3.4 Flask dev server binds to `0.0.0.0` without production guidance

**File:** `app.py` Line 198

`app.run(debug=False, host="0.0.0.0", port=5000)` exposes the single-threaded dev server on all
interfaces if run on a public machine.

**Fix:** Document in README that `python app.py` is local-dev only, and provide a Gunicorn
startup command for production.

---

### 3.5 History `innerHTML` interpolation — latent XSS surface

**File:** `static/script.js` Lines 862-867

```js
el.innerHTML = `<div class="history-score ${tier}">${score}</div>...`;
```

`score` and `tier` are controlled values today, but the pattern is fragile — any future change
that introduces user-controlled data into these interpolations creates XSS.

**Recommendation:** Use individual `textContent` assignments per element instead of innerHTML
template literals.

---

## 4. Performance Issues

### 4.1 Levenshtein scan has no early-exit for long labels

**File:** `api/phishing_heuristics.py` Lines 162-169

Levenshtein distance is computed between the hostname label and all 23 known brands on every
request. For labels much longer than any brand, the distance will always exceed 2, so the
computation is wasted.

**Recommendation:** Add early-exit: `if abs(len(normalized_label) - len(brand)) > 2: continue`

---

### 4.2 `_windows` dict grows unboundedly under IP spoofing attacks

**File:** `api/rate_limiter.py` Lines 42, 52

Stale window entries are pruned only when the same IP makes another request. Under a sustained
attack from many unique spoofed IPs (via X-Forwarded-For), the dict grows without bound, causing
unbounded memory growth.

**Fix:** Add periodic global cleanup of all entries older than 60 seconds.

---

## 5. Dependency / Configuration Issues

### 5.1 Root `requirements.txt` hard-pins `requests==2.31.0`

**File:** `requirements.txt` Line 3

Root file pins `requests==2.31.0` (May 2023); `api/requirements.txt` uses `requests>=2.31.0`.
The two files can resolve to different versions depending on which is used.

**Fix:** Align both files to `requests>=2.31.0`.

---

### 5.2 `redis` listed as required but is fully optional at runtime

**Files:** Both `requirements.txt` files

`redis>=5.0.0` appears in both requirements files, but the import is lazy (inside `_init_redis()`)
and only active when `REDIS_URL` is set. Every deployment is forced to install it needlessly.

**Fix:** Mark redis as optional (comment, separate file, or extras group).

---

### 5.3 Two `requirements.txt` files with conflicting constraint styles

**Files:** `requirements.txt` vs `api/requirements.txt`

- Root uses hard pins: `Flask==2.3.3`, `requests==2.31.0`
- API uses flexible: `Flask>=2.3.3`, `requests>=2.31.0`

No documentation explains which file is for which deployment target.

**Fix:** Consolidate or document clearly in README.

---

### 5.4 `Werkzeug` pinned in root only

**File:** `requirements.txt` Line 2

`Werkzeug>=2.3.0` is in the root file but absent from `api/requirements.txt`. The Vercel
deployment may install an incompatible Werkzeug version.

**Fix:** Either remove the explicit pin (let Flask resolve it) or add it to both files.

---

## 6. HTML / Frontend Issues

### 6.1 `<main>` missing `id` in `landing.html`

**File:** `templates/landing.html` Line 84

`index.html` correctly has `<main id="main">` but `landing.html` has bare `<main>`. Minor
accessibility gap (breaks skip-to-content patterns).

---

### 6.2 QR tab visibility toggled via fragile ID substring matching

**File:** `static/script.js` Lines 623-625

```js
el.classList.toggle('hidden', !el.id.toLowerCase().includes(tab));
```

Visibility depends on whether the element ID *contains* the tab name as a substring. A future
element with an ID like "camera-hint" would be incorrectly toggled.

**Fix:** Use `data-tab` attributes on the tab content panels instead.

---

### 6.3 OG and Twitter image URLs use `http://` instead of `https://`

**Files:** Both templates, Line 15

Social media crawlers may reject HTTP images when the page is served over HTTPS.

---

### 6.4 `aria-valuenow` never updated on the progress bar

**File:** `templates/index.html` Lines 237-239

The `role="progressbar"` element has `aria-valuemin` and `aria-valuemax` but `aria-valuenow`
is never set by `setProgress()`. Screen readers cannot announce the current progress value.

**Fix:** In `setProgress(pct)`, also call `progressTrack.setAttribute('aria-valuenow', pct)`.

---

## 7. Code Quality and Maintainability

### 7.1 Fragile substring matching for finding classification

**File:** `api/scoring.py` Lines 102-107

```python
for pattern, pts, label in _SCORE_RULES:
    if pattern in f or (pattern == "credentials" and pattern in f.lower()):
```

The special-case lowercasing for "credentials" creates inconsistency. Free-form string matching
is fragile as patterns evolve.

**Recommendation:** Use a structured finding type (enum + dataclass) or regex patterns.

---

### 7.2 Duplicate severity classification logic

**Files:** `api/scoring.py` Lines 132-213 and `api/llm_explainer.py` Lines 158-174

`generate_analysis` and `_severity_of` both classify findings into severity categories using
independently-defined overlapping keyword lists. They can drift out of sync silently.

**Recommendation:** Extract a shared `classify_finding(finding: str) -> Severity` function.

---

### 7.3 `normalize_url` path-stripping is undocumented and asymmetric

**File:** `api/scanner.py` Lines 193-198

Phishing heuristics receive the original URL; file checks receive the normalized (path-stripped)
URL. This asymmetry is not documented and can confuse users.

**Recommendation:** Document this design choice and consider including the normalized URL in the
API response.

---

### 7.4 Magic number `25` duplicates the `verdict_for_score` threshold

**File:** `app.py` Line 132

```python
is_risky = risk_score >= 25
```

The threshold `25` is already encoded in `verdict_for_score`. If it changes, `app.py` will be
out of sync.

**Fix:** `is_risky = verdict != "Low Risk"`

---

### 7.5 `.env` loader crashes on non-UTF-8 encoding

**File:** `app.py` `_load_local_env()` function

`env_path.read_text(encoding="utf-8")` will raise `UnicodeDecodeError` if the `.env` file is
saved in a non-UTF-8 encoding, crashing the entire app at startup.

**Fix:** Wrap the `read_text` call in a try/except and log a warning on failure.

---

### 7.6 `api/__init__.py` is effectively empty

**File:** `api/__init__.py`

Contains only `# API package`. Acceptable for now, but future package-level setup should go here.

---

## 8. Summary Table

| # | Severity | File | Issue |
|---|----------|------|-------|
| 1.1 | Medium | `api/scanner.py` | `validate_url_for_request` imported but never called |
| 1.2 | Low | `static/script.js` | `debounce()` defined but never used |
| 1.3 | Low | `static/script.js` | `QRScanner.destroy()` not in return object — unreachable |
| 1.4 | Low | `templates/index.html` | `#loadingLabel` ID unused by JS |
| 1.5 | Low | `templates/index.html` | `#scoreBreakdownBlock` ID unused by JS |
| 1.6 | Low | `api/llm_explainer.py` | `provider_cfg` intermediate variable unnecessary |
| 1.7 | Low | `api/llm_explainer.py` | `result` variable immediately returned — dead assignment |
| 1.8 | HIGH | `app.py` / `.env.example` | `ALLOWED_ORIGIN` documented but never read — CORS not implemented |
| 2.1 | HIGH | `api/rate_limiter.py` | Double rate-limit hit per request when Redis is down |
| 2.2 | Medium | `api/phishing_heuristics.py` | HTTP URLs always flagged insecure even with HTTPS redirect |
| 2.3 | Low | `app.py` | Per-request `ThreadPoolExecutor` — wasteful thread creation |
| 2.4 | Low | `api/scanner.py` | `check_https_redirect` makes up to 4 DNS lookups per scan |
| 2.5 | Medium | `api/log_utils.py` | ANSI control chars not sanitized — log injection risk |
| 2.6 | Medium | `api/scanner.py` | Sensitive file futures awaited in submission order not completion order |
| 2.7 | Medium | `script.js` + `scoring.py` | 5-tier JS vs 4-tier Python verdict — UI color mismatch |
| 3.1 | HIGH | `app.py` | No Content-Security-Policy on own responses |
| 3.2 | HIGH | `templates/index.html` | CDN scripts have no Subresource Integrity (SRI) attributes |
| 3.3 | Medium | Both templates | `localhost:5000` hardcoded in canonical/OG/JSON-LD tags |
| 3.4 | Low | `app.py` | Dev server binds 0.0.0.0 — no production WSGI guidance |
| 3.5 | Low | `static/script.js` | `innerHTML` interpolation — latent XSS surface |
| 4.1 | Low | `api/phishing_heuristics.py` | Levenshtein scan has no early-exit for long labels |
| 4.2 | Medium | `api/rate_limiter.py` | `_windows` dict grows unboundedly under IP spoofing |
| 5.1 | Low | `requirements.txt` | Hard-pinned `requests==2.31.0` vs flexible in api/ |
| 5.2 | Low | Both requirements | `redis` required in deps but optional at runtime |
| 5.3 | Low | Both requirements | Inconsistent constraint styles across two requirements files |
| 5.4 | Low | `requirements.txt` | `Werkzeug` pinned in root only |
| 6.1 | Low | `templates/landing.html` | `<main>` missing `id` — minor accessibility gap |
| 6.2 | Low | `static/script.js` | QR tab toggling uses fragile ID substring matching |
| 6.3 | Low | Both templates | OG / Twitter image URLs use `http://` not `https://` |
| 6.4 | Low | `templates/index.html` | `aria-valuenow` never updated on progress bar |
| 7.1 | Medium | `api/scoring.py` | Fragile substring matching for finding classification |
| 7.2 | Low | `scoring.py` + `llm_explainer.py` | Duplicate severity classification logic in two files |
| 7.3 | Low | `api/scanner.py` | `normalize_url` path-stripping undocumented and asymmetric |
| 7.4 | Low | `app.py` | Magic number `25` duplicates `verdict_for_score` threshold |
| 7.5 | Medium | `app.py` | `.env` loader has no error handling for non-UTF-8 encoding |
| 7.6 | Info | `api/__init__.py` | Empty package init |

---

**Severity Legend**

| Level | Meaning |
|-------|---------|
| HIGH | Fix before production deployment |
| Medium | Fix in next sprint |
| Low | Cleanup / nice-to-fix |
| Info | Informational only |

---

*End of report — 36 issues found across 7 categories.*

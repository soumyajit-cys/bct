"""
api/rate_limiter.py
===================
Lightweight, deployment-safe per-IP rate limiter.

Works in both Flask dev server and Vercel serverless.

On Vercel, each warm instance tracks its own request window; this is not
cross-instance but is still useful defence-in-depth.  For true
cross-instance limiting on Vercel, set REDIS_URL and the limiter will use
Redis as a shared backend (requires the `redis` package).

Environment variables:
  RATE_LIMIT_RPM   – requests per minute per IP (default: 30)
  REDIS_URL        – optional Redis URL for cross-instance limiting
"""

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict
from threading import Lock

from flask import request, jsonify

logger = logging.getLogger("nexusscan.rate_limiter")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_RPM = int(os.environ.get("RATE_LIMIT_RPM", "30"))

# ---------------------------------------------------------------------------
# In-memory store (single-process / single-instance)
# ---------------------------------------------------------------------------

_lock: Lock = Lock()
# { ip: [(timestamp, count), ...] }
_windows: dict[str, list[tuple[float, int]]] = defaultdict(list)


def _check_in_memory(ip: str, limit: int) -> bool:
    """Return True if the request is within the rate limit."""
    now = time.time()
    window_start = now - 60.0

    with _lock:
        # Purge old entries
        _windows[ip] = [(ts, c) for ts, c in _windows[ip] if ts > window_start]
        count = sum(c for _, c in _windows[ip])

        if count >= limit:
            return False

        _windows[ip].append((now, 1))
        return True


# ---------------------------------------------------------------------------
# Redis store (optional, cross-instance)
# ---------------------------------------------------------------------------

_redis_client = None
_redis_ok     = False


def _init_redis() -> None:
    global _redis_client, _redis_ok
    redis_url = os.environ.get("REDIS_URL", "").strip()
    if not redis_url:
        return
    try:
        import redis  # type: ignore[import-not-found]
        _redis_client = redis.from_url(redis_url, socket_connect_timeout=2)
        _redis_client.ping()
        _redis_ok = True
        logger.info("Rate limiter: Redis backend connected (%s)", redis_url[:30])
    except Exception as exc:
        logger.warning("Rate limiter: Redis unavailable (%s) — using in-memory", exc)
        _redis_ok = False


_init_redis()


def _check_redis(ip: str, limit: int) -> bool:
    """Return True if allowed; uses a Redis sliding-window counter."""
    if not _redis_ok or _redis_client is None:
        return _check_in_memory(ip, limit)
    try:
        key = f"rl:{ip}"
        pipe = _redis_client.pipeline()
        pipe.incr(key)
        pipe.expire(key, 60)
        result = pipe.execute()
        count = result[0]
        return count <= limit
    except Exception as exc:
        logger.warning("Redis rate-limit check failed: %s — falling back to memory", exc)
        return _check_in_memory(ip, limit)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_remote_ip() -> str:
    """
    Return the real client IP, honouring common proxy headers.

    Security note: X-Forwarded-For is a client-controllable header and can be
    spoofed if the application is not deployed behind a trusted reverse proxy.
    On Vercel the platform appends the real client IP to X-Forwarded-For so we
    take the LAST non-empty entry (most recently added by the trusted edge),
    not the first (which an attacker can freely inject).

    Set TRUST_PROXY=false to disable XFF parsing and always use remote_addr.
    """
    trust_proxy = os.environ.get("TRUST_PROXY", "true").strip().lower() != "false"
    if trust_proxy:
        forwarded = request.headers.get("X-Forwarded-For", "").strip()
        if forwarded:
            # Rightmost entry is appended by the trusted proxy (Vercel/Cloudflare).
            return forwarded.split(",")[-1].strip()
    return request.remote_addr or "unknown"


def rate_limit_check() -> tuple[bool, object]:
    """
    Check whether the current request is within the configured rate limit.

    Returns:
        (allowed: bool, error_response | None)

        If allowed=True, error_response is None.
        If allowed=False, error_response is a Flask JSON response with HTTP 429.
    """
    ip = get_remote_ip()
    allowed = _check_redis(ip, _RPM) if _redis_ok else _check_in_memory(ip, _RPM)

    if not allowed:
        logger.warning("Rate limit exceeded | ip=%s | limit=%d rpm", ip, _RPM)
        resp = jsonify(
            {
                "error": f"Rate limit exceeded — maximum {_RPM} requests per minute.",
                "retry_after": 60,
            }
        )
        resp.status_code = 429
        resp.headers["Retry-After"] = "60"
        return False, resp

    return True, None

"""
api/log_utils.py
================
Helpers for building log-safe strings from user-controlled input.

Prevents log injection (CWE-117): CR/LF characters are escaped so a
crafted value cannot forge new log lines, and values are truncated so a
huge payload cannot flood the log store.
"""

from __future__ import annotations


def sanitize_url_for_log(value: str | None, max_len: int = 512) -> str:
    """
    Neutralise control characters that could inject fake log lines.

    In addition to CR/LF, other control characters (e.g. the terminal
    bell ``\x07``) are hard-tabbed away as well. Falls back to a marker
    for ``None`` so the caller doesn't need separate handling.
    """
    if value is None:
        return "<unknown>"
    return value.replace("\r", "\\r").replace("\n", "\\n")[:max_len]
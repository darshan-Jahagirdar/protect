"""Cleaning feed data. Everything from a feed is hostile until it passes through here.

Text is never "fixed" into meaning something else: it is trimmed, stripped of control
characters and capped. Ids, URLs and versions either match a strict format or are refused.
"""

import re
import unicodedata
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from app.engine.versions import parse_loose


class FeedDataError(ValueError):
    """One feed item failed our format checks. The item is skipped, the run carries on."""


TITLE_MAX = 300
TEXT_MAX = 4000
URL_MAX = 500

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
GHSA_RE = re.compile(r"^GHSA(?:-[0-9a-z]{4}){3}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
VECTOR_RE = re.compile(r"^CVSS:[34]\.[01](?:/[A-Za-z]{1,3}:[A-Za-z]{1,2}){1,40}$")


def _no_controls(text: str, keep_newlines: bool) -> str:
    out = []
    for ch in text:
        if ch in "\n\t" and keep_newlines:
            out.append(ch)
        elif unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp"):
            out.append(" ")  # line breaks, bidi overrides, zero-width characters
        else:
            out.append(ch)
    return "".join(out)


def title(value: Any) -> str:
    """One line, no control characters (a line break in a title broke alert emails)."""
    if not isinstance(value, str):
        raise FeedDataError("title is missing")
    text = " ".join(_no_controls(value, keep_newlines=False).split())
    if not text:
        raise FeedDataError("title is empty")
    return text[: TITLE_MAX - 1] + "…" if len(text) > TITLE_MAX else text


def text(value: Any, limit: int = TEXT_MAX) -> str | None:
    """Multi-line text such as an advisory description. Shown escaped, never as HTML."""
    if not isinstance(value, str):
        return None
    cleaned = _no_controls(value.replace("\r\n", "\n").replace("\r", "\n"), keep_newlines=True)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    if not cleaned:
        return None
    return cleaned[: limit - 1] + "…" if len(cleaned) > limit else cleaned


def http_url(value: Any) -> str | None:
    """Only absolute http(s) links with a host; anything else (javascript:, data:…) is dropped."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if len(value) > URL_MAX or any(ch.isspace() or ord(ch) < 32 for ch in value):
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    return value


def cve(value: Any) -> str | None:
    return value if isinstance(value, str) and CVE_RE.match(value) else None


def cvss_score(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if 0.0 <= value <= 10.0 else None


def cvss_vector(value: Any) -> str | None:
    return value if isinstance(value, str) and VECTOR_RE.match(value) else None


def version(value: Any) -> str | None:
    """A version string the engine can read, or None."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > 50 or parse_loose(value) is None:
        return None
    return value


def timestamp(value: Any) -> datetime | None:
    """ISO 8601 ("2026-10-21T13:34:25Z") or Wordfence's "2026-10-21 13:34:25" (UTC)."""
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)

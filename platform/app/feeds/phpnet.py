"""php.net: which PHP branches are supported and current, and the news feed (DESIGN.md §4.3).

- Releases JSON: the supported branches and the latest release of each. The GitHub feed uses
  the supported list to tell "old branch, no fix coming" from "the advisory doesn't say".
- News feed (Atom): an early signal. Security announcements are free text, so they become
  advisories waiting for review, with the versions named in them as a starting point. All
  security posts from one day are one advisory. They carry their own id only: CVE and GHSA
  ids they mention are listed in the text, so a news post never merges unrelated advisories.
"""

import json
import re
import xml.etree.ElementTree as ET
from datetime import timedelta
from typing import Any

from app.enums import ReviewStatus
from app.feeds import clean
from app.feeds.php_ranges import BranchFix, branch_of, build_ranges
from app.feeds.runner import FeedContext, FeedOutcome, state, store

RELEASES_SOURCE = "php-releases"
NEWS_SOURCE = "phpnet-news"
RELEASES_URL = "https://www.php.net/releases/?json&version={version}"
NEWS_URL = "https://www.php.net/feed.atom"
RELEASES_MAX_BYTES = 256 * 1024
NEWS_MAX_BYTES = 8 * 1024 * 1024
NEWS_WINDOW = timedelta(days=30)  # history comes from GitHub; news is only an early signal
_ATOM = "{http://www.w3.org/2005/Atom}"
_BRANCH_RE = re.compile(r"^\d{1,2}\.\d{1,2}$")
_RELEASE_RE = re.compile(r"^\d{1,2}\.\d{1,2}\.\d{1,3}$")
_PHP_VERSION_IN_TEXT = re.compile(r"\bPHP (\d{1,2}\.\d{1,2}\.\d{1,3})\b")
_BARE_VERSION_IN_TEXT = re.compile(r"(?<![\d.])(\d{1,2}\.\d{1,2}\.\d{1,3})(?![\d.])")
_IDS_IN_TEXT = re.compile(r"\b(CVE-\d{4}-\d{4,7}|GHSA(?:-[0-9a-z]{4}){3})\b")


def _get_json(ctx: FeedContext, url: str) -> Any:
    dl = ctx.fetch(url, max_bytes=RELEASES_MAX_BYTES)
    try:
        return json.loads(dl.read())
    finally:
        dl.close()


def refresh_releases(ctx: FeedContext, out: FeedOutcome) -> None:
    """Supported branches and the latest release of each, kept in feed_state."""
    top = _get_json(ctx, RELEASES_URL.format(version="8"))
    if not isinstance(top, dict) or not isinstance(top.get("supported_versions"), list):
        raise clean.FeedDataError("php.net releases JSON has no supported_versions list")
    supported = sorted(
        {v for v in top["supported_versions"] if isinstance(v, str) and _BRANCH_RE.match(v)},
        key=lambda v: branch_of(v) or (0, 0),
    )
    if not supported:
        raise clean.FeedDataError("php.net lists no supported PHP branches")
    latest: dict[str, str] = {}
    for branch in supported:
        info = _get_json(ctx, RELEASES_URL.format(version=branch))
        version = info.get("version") if isinstance(info, dict) else None
        if isinstance(version, str) and _RELEASE_RE.match(version):
            if branch_of(version) == branch_of(branch):
                latest[branch] = version
    st = state(ctx.session, RELEASES_SOURCE)
    new = {"supported": supported, "latest": latest}
    if st.data != new:
        st.data = new
        st.updated_at = ctx.now
        out.updated += 1


def run_releases(ctx: FeedContext, out: FeedOutcome) -> None:
    refresh_releases(ctx, out)


def _text(el: ET.Element | None) -> str:
    return "".join(el.itertext()) if el is not None else ""


def run_news(ctx: FeedContext, out: FeedOutcome) -> None:
    dl = ctx.fetch(NEWS_URL, max_bytes=NEWS_MAX_BYTES)
    try:
        # Python's parser (expat 2.4+) refuses entity-expansion bombs and never fetches
        # external entities.
        root = ET.fromstring(dl.read())  # noqa: S314 (see the comment above)
    except ET.ParseError as e:
        raise clean.FeedDataError("php.net news feed isn't valid XML") from e
    finally:
        dl.close()

    supported = state(ctx.session, RELEASES_SOURCE).data.get("supported")
    days: dict[str, list[dict[str, Any]]] = {}
    for entry in root.findall(f"{_ATOM}entry"):
        published = clean.timestamp(entry.findtext(f"{_ATOM}published"))
        if published is None or ctx.now - published > NEWS_WINDOW:
            continue
        title = entry.findtext(f"{_ATOM}title") or ""
        body = _text(entry.find(f"{_ATOM}content"))
        if "security" not in (title + " " + body).lower():
            continue
        link = next(
            (
                clean.http_url(link.get("href"))
                for link in entry.findall(f"{_ATOM}link")
                if "/archive/" in (link.get("href") or "")
            ),
            None,
        )
        days.setdefault(published.date().isoformat(), []).append(
            {"title": title, "body": body, "published": published, "link": link}
        )

    for day, entries in sorted(days.items()):
        try:
            data = parse_day(day, entries, supported)
        except clean.FeedDataError as e:
            out.rejected += 1
            out.notes.append(f"skipped news from {day}: {e}"[:200])
            continue
        store(ctx, out, NEWS_SOURCE, f"day:{day}", data, ReviewStatus.NEEDS_REVIEW)


def parse_day(
    day: str, entries: list[dict[str, Any]], supported: list[str] | None
) -> dict[str, Any]:
    entries = sorted(entries, key=lambda e: e["published"])
    # The headline: an advisory post if there is one, else the first post of the day.
    lead = next((e for e in entries if "security" in e["title"].lower()), entries[0])
    versions: set[str] = set()
    ids: set[str] = set()
    for e in entries:
        versions |= set(_PHP_VERSION_IN_TEXT.findall(e["title"]))
        versions |= set(_PHP_VERSION_IN_TEXT.findall(e["body"]))
        if "released" in e["title"].lower():
            versions |= set(_BARE_VERSION_IN_TEXT.findall(e["title"]))
        ids |= set(_IDS_IN_TEXT.findall(e["body"]))
    fixes: dict[tuple[int, int], BranchFix] = {}
    for v in versions:
        branch = branch_of(v)
        if branch is None or clean.version(v) is None:
            continue
        current = fixes.get(branch)
        if current is None or tuple(map(int, v.split("."))) > tuple(
            map(int, current.fixed.split("."))
        ):
            fixes[branch] = BranchFix(branch, v)
    ranges, _ = build_ranges(list(fixes.values()), supported) if fixes else ([], False)

    # The headline post first, then the others; ids up front so the length cap never hides them.
    ordered = [lead, *(e for e in entries if e is not lead)]
    text_parts = [
        f"{clean.title(e['title'])}\n{clean.text(e['body'], 1500) or ''}" for e in ordered
    ]
    summary = "\n\n".join(text_parts)
    if ids:
        summary = "Mentions: " + ", ".join(sorted(ids)) + "\n\n" + summary
    return {
        "title": "php.net: " + clean.title(lead["title"]),
        "aliases": [f"php.net-news:{day}"],
        "source_url": lead["link"],
        "summary_text": clean.text(summary),
        "published_at": entries[0]["published"],
        "review_reason": (
            "php.net news is free text: check the affected versions"
            + (f" (mentions {', '.join(sorted(ids))})" if ids else "")
        )[:1000],
        "affects": [
            {
                "component_key": "php",
                "ranges": ranges,
                "fixed_versions": sorted(f.fixed for f in fixes.values()),
            }
        ]
        if ranges
        else [],
    }

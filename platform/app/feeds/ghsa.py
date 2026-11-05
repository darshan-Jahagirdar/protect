"""GitHub security advisories for php/php-src: the primary source for PHP core (DESIGN.md §4.3).

Published by the PHP security team with one version range per release branch. Everything in
php-src (the engine, bundled extensions like ext-soap, PHP-FPM) ships in the PHP version
itself, so every advisory maps to the `php` component.

Ranges come in as confirmed only when every line reads cleanly and no supported branch is left
out (see app/feeds/php_ranges.py). Anything odd ("< 8.3.18" but "patched 8.3.19", free text)
goes to the review queue with our best reading filled in, never to "safe".
"""

import json
import re
from typing import Any
from urllib.parse import urlsplit

from app.enums import ReviewStatus
from app.feeds import clean, phpnet
from app.feeds.php_ranges import BranchFix, branch_of, build_ranges
from app.feeds.runner import FeedContext, FeedOutcome, state, store

SOURCE = "ghsa"
URL = (
    "https://api.github.com/repos/php/php-src/security-advisories"
    "?state=published&per_page=100&sort=updated&direction=desc"
)
HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
MAX_BYTES = 10 * 1024 * 1024
MAX_PAGES = 5
# Package names that are simply "PHP itself" (no extra note needed).
_CORE_NAMES = {"", "php", "php-src"}
_PACKAGE_RE = re.compile(r"^[A-Za-z0-9._-]{1,50}$")
_CONSTRAINT = re.compile(r"^\s*(<=|>=|<|>|=)?\s*(\d+\.\d+\.\d+)\s*$")
_NEXT_LINK = re.compile(r'<(https://api\.github\.com/[^>\s]+)>;\s*rel="next"')


def run(ctx: FeedContext, out: FeedOutcome) -> None:
    supported = state(ctx.session, phpnet.RELEASES_SOURCE).data.get("supported")
    if not supported:  # first run: learn the supported branches first, or everything is "unsure"
        phpnet.refresh_releases(ctx, FeedOutcome())
        supported = state(ctx.session, phpnet.RELEASES_SOURCE).data.get("supported")
    url: str | None = URL
    for _ in range(MAX_PAGES):
        if url is None:
            break
        dl = ctx.fetch(url, max_bytes=MAX_BYTES, headers=HEADERS)
        try:
            items = json.loads(dl.read())
            link = dl.headers.get("link", "")
        finally:
            dl.close()
        if not isinstance(items, list):
            raise clean.FeedDataError("GitHub returned something other than a list")
        for raw in items:
            ingest_one(ctx, out, raw, supported)
        m = _NEXT_LINK.search(link)
        url = (
            m.group(1)
            if m and urlsplit(m.group(1)).path.startswith("/repos/php/php-src/")
            else None
        )


def ingest_one(ctx: FeedContext, out: FeedOutcome, raw: Any, supported: list[str] | None) -> None:
    try:
        item_id, data, status = parse(raw, supported)
    except clean.FeedDataError as e:
        out.rejected += 1
        out.notes.append(f"skipped one advisory: {e}"[:200])
        return
    store(ctx, out, SOURCE, item_id, data, status)


def _parse_line(rng: Any, patched: Any) -> tuple[BranchFix | None, str | None, str | None]:
    """One "vulnerable_version_range" + "patched_versions" pair.

    Returns (fix, problem, note). A problem sends the advisory to review; a note is only
    added to its text."""
    if not isinstance(rng, str) or len(rng) > 200:
        return None, "a range isn't text", None
    shown = " ".join(rng.split())[:60]
    unreadable = f"couldn't read the range {shown!r}"
    parts = [_CONSTRAINT.match(p) for p in rng.split(",")]
    if not all(parts):
        return None, unreadable, None
    lower = [(m[1], m[2]) for m in parts if m and m[1] in (">", ">=")]
    upper = [(m[1], m[2]) for m in parts if m and m[1] in ("<", "<=")]
    if len(upper) != 1 or len(lower) > 1 or len(parts) != len(lower) + len(upper):
        return None, unreadable, None
    op, top = upper[0]
    branch = branch_of(top)
    if branch is None:
        return None, unreadable, None
    fixed = patched.strip() if isinstance(patched, str) else ""
    if fixed and (not re.fullmatch(r"\d+\.\d+\.\d+", fixed) or branch_of(fixed) != branch):
        return None, f"couldn't read the fixed version for {shown!r}", None

    introduced = None
    if lower:
        lop, low = lower[0]
        if branch_of(low) != branch:
            return None, f"the range {shown!r} spans branches", None
        if lop == ">":
            major, minor, release = (int(x) for x in low.split("."))
            low = f"{major}.{minor}.{release + 1}"
        introduced = low

    release = int(top.split(".")[2])
    if not fixed:  # no patched release named: the range itself is the answer
        if op == "<":
            return BranchFix(branch, top, introduced), None, None
        return BranchFix(branch, top, introduced, last_affected=top), None, None
    fixed_release = int(fixed.split(".")[2])
    first_safe = release if op == "<" else release + 1
    if fixed_release == first_safe:
        return BranchFix(branch, fixed, introduced), None, None
    if fixed_release > first_safe:
        # "< 8.3.18" but "patched 8.3.19": the later version is the careful reading. It can
        # only over-warn about 8.3.18, never call an affected version safe.
        return (
            BranchFix(branch, fixed, introduced),
            None,
            (
                f"GitHub's range {shown!r} and its fixed version {fixed} disagree; "
                f"Protect treats everything before {fixed} as affected."
            ),
        )
    return None, f"{shown!r} doesn't agree with its fixed version {fixed}", None


def _cvss(raw: dict[str, Any]) -> tuple[float | None, str | None]:
    severities = raw.get("cvss_severities") if isinstance(raw.get("cvss_severities"), dict) else {}
    for key in ("cvss_v3", "cvss_v4"):
        entry = severities.get(key) if isinstance(severities, dict) else None
        if isinstance(entry, dict):
            score = clean.cvss_score(entry.get("score"))
            if score is not None:
                return score, clean.cvss_vector(entry.get("vector_string"))
    old = raw.get("cvss") if isinstance(raw.get("cvss"), dict) else {}
    score = clean.cvss_score(old.get("score"))
    return score, clean.cvss_vector(old.get("vector_string")) if score is not None else None


def parse(raw: Any, supported: list[str] | None) -> tuple[str, dict[str, Any], ReviewStatus]:
    if not isinstance(raw, dict):
        raise clean.FeedDataError("an advisory isn't an object")
    ghsa = raw.get("ghsa_id")
    if not isinstance(ghsa, str) or not clean.GHSA_RE.match(ghsa):
        raise clean.FeedDataError("missing or malformed GHSA id")
    aliases = [ghsa]
    cve = clean.cve(raw.get("cve_id"))
    if cve:
        aliases.append(cve)

    problems: list[str] = []
    notes: list[str] = []
    fixes: list[BranchFix] = []
    packages: set[str] = set()
    vulns = raw.get("vulnerabilities")
    for v in vulns if isinstance(vulns, list) else []:
        if not isinstance(v, dict):
            problems.append("a range entry isn't an object")
            continue
        pkg = v.get("package", {}).get("name") if isinstance(v.get("package"), dict) else None
        if isinstance(pkg, str) and _PACKAGE_RE.match(pkg) and pkg.lower() not in _CORE_NAMES:
            packages.add(pkg)
        fix, problem, note = _parse_line(
            v.get("vulnerable_version_range"), v.get("patched_versions")
        )
        if fix is not None:
            fixes.append(fix)
        if problem:
            problems.append(problem)
        if note:
            notes.append(note)
    if len({f.branch for f in fixes}) != len(fixes):
        problems.append("a branch is listed twice")

    ranges, unsure = build_ranges(fixes, supported) if fixes else ([], False)
    if not fixes:
        problems.append("no version range could be read")
    if unsure:
        problems.append(
            "it doesn't say whether some supported PHP branches are affected"
            if supported
            else "the list of supported PHP branches isn't known yet"
        )

    score, vector = _cvss(raw)
    summary = clean.text(raw.get("description"))
    if packages:
        summary = (summary or "") + f"\n\nPart of PHP: {', '.join(sorted(packages))}"
    if notes:
        summary = (summary or "") + "\n\nNote from Protect: " + " ".join(notes)
    data: dict[str, Any] = {
        "title": "PHP: " + clean.title(raw.get("summary")),
        "aliases": aliases,
        "source_url": clean.http_url(raw.get("html_url")),
        "summary_text": summary,
        "cvss_score": score,
        "cvss_vector": vector,
        "published_at": clean.timestamp(raw.get("published_at")),
        "withdrawn": raw.get("withdrawn_at") is not None,
        "review_reason": ("; ".join(dict.fromkeys(problems)))[:1000] or None,
        "affects": [
            {
                "component_key": "php",
                "ranges": ranges,
                "fixed_versions": sorted(
                    {f.fixed for f in fixes if not f.last_affected}, key=_version_key
                ),
            }
        ]
        if ranges
        else [],
    }
    status = ReviewStatus.NEEDS_REVIEW if problems else ReviewStatus.CONFIRMED
    return ghsa, data, status


def _version_key(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))

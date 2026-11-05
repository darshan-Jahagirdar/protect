"""Storing advisories: replayed fixtures, manual entries and live feeds (DESIGN.md §4.3).

Who may change what:
- A replayed or hand-entered advisory, or one a person has reviewed, belongs to people. A feed
  only adds aliases and fills in blanks (a missing CVSS score, link or date); it never changes
  its version ranges, title or review status.
- Between feeds, a better source replaces a weaker one's data (GitHub and Wordfence carry
  machine-readable ranges; NVD and the php.net news feed don't). A weaker source only fills in
  blanks.
- "Known exploited" only ever goes from no to yes.
"""

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import utcnow
from app.engine.catalogue import is_valid_key
from app.engine.versions import parse_loose
from app.enums import ReviewStatus
from app.feeds import clean
from app.models import Advisory, AdvisoryAffect, Event, FeedItem, IncidentAdvisory, User
from app.settings import PLATFORM_DIR

FIXTURES_DIR = PLATFORM_DIR / "fixtures" / "advisories"

PERSON_SOURCES = frozenset({"manual", "replay"})
# How much each feed's data is trusted, for merging. Equal ranks replace each other.
SOURCE_RANK = {"phpnet-news": 1, "nvd": 2, "ghsa": 3, "wordfence": 3}
RANGE_KEYS = frozenset({"introduced", "fixed", "last_affected", "limit", "unsupported", "unsure"})


class AdvisoryDataError(ValueError):
    pass


def fixture_names() -> list[str]:
    return sorted(p.stem for p in FIXTURES_DIR.glob("*.json"))


def load_fixture(name: str) -> dict[str, Any]:
    if name not in fixture_names():  # also blocks path tricks like "../x"
        raise AdvisoryDataError(f"no advisory fixture named {name!r}")
    return json.loads((FIXTURES_DIR / f"{name}.json").read_text())


def _parse_time(value: str | datetime | None) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def find_by_aliases(session: Session, aliases: list[str]) -> Advisory | None:
    wanted = set(aliases)
    for adv in session.scalars(select(Advisory).order_by(Advisory.id)):
        if wanted & set(adv.aliases):
            return adv
    return None


def validate_ranges(ranges: Any) -> list[dict[str, Any]]:
    """OSV-style ranges (see app/engine/matcher.py). Bad data is refused, never repaired."""
    if not isinstance(ranges, list):
        raise AdvisoryDataError("ranges must be a list")
    for rng in ranges:
        if not isinstance(rng, dict) or not set(rng) <= RANGE_KEYS or "introduced" not in rng:
            raise AdvisoryDataError(f"bad range {rng!r}")
        bounds = [k for k in ("fixed", "last_affected", "limit") if k in rng]
        if len(bounds) > 1:
            raise AdvisoryDataError(f"range has more than one upper bound: {rng!r}")
        for key in ("introduced", *bounds):
            if not isinstance(rng[key], str) or parse_loose(rng[key]) is None:
                raise AdvisoryDataError(f"unreadable version in range: {rng!r}")
        for flag in ("unsupported", "unsure"):
            if flag in rng and (rng[flag] is not True or "limit" not in rng):
                raise AdvisoryDataError(f"{flag} needs an 'until' version: {rng!r}")
    return ranges


def has_unsure(affects: list[dict[str, Any]] | list[AdvisoryAffect]) -> bool:
    for affect in affects:
        ranges = affect["ranges"] if isinstance(affect, dict) else affect.ranges
        if any(r.get("unsure") for r in ranges):
            return True
    return False


def _validate_affects(affects: Any) -> list[dict[str, Any]]:
    if not isinstance(affects, list):
        raise AdvisoryDataError("affects must be a list")
    for affect in affects:
        if not is_valid_key(affect.get("component_key", "")):
            raise AdvisoryDataError(f"invalid component key {affect.get('component_key')!r}")
        validate_ranges(affect.get("ranges") or [])
    return affects


def group_key(advisory: Advisory) -> str | None:
    """Same components, same affected versions, same fix: one event (one PHP security release,
    one plugin update), so one incident. None for drills and advisories without ranges."""
    if advisory.drill or not advisory.affects:
        return None
    shape = sorted(
        (a.component_key, sorted(json.dumps(r, sort_keys=True) for r in a.ranges))
        for a in advisory.affects
    )
    return hashlib.sha256(json.dumps(shape).encode()).hexdigest()[:32]


def _set_affects(adv: Advisory, affects: list[dict[str, Any]]) -> None:
    adv.affects.clear()
    for affect in affects:
        adv.affects.append(
            AdvisoryAffect(
                component_key=affect["component_key"],
                ranges=affect.get("ranges") or [],
                fixed_versions=affect.get("fixed_versions") or [],
                distro_fixes=affect.get("distro_fixes") or {},
            )
        )


def upsert_advisory(
    session: Session,
    data: dict[str, Any],
    review_status: ReviewStatus = ReviewStatus.CONFIRMED,
) -> Advisory:
    """Replay or manual entry: create the advisory, or update the one sharing any alias."""
    aliases = list(dict.fromkeys(data.get("aliases") or []))
    if not aliases:
        raise AdvisoryDataError("an advisory needs at least one alias")
    affects = _validate_affects(data.get("affects") or [])

    adv = find_by_aliases(session, aliases)
    if adv is None:
        adv = Advisory(aliases=aliases)
        session.add(adv)
    else:
        adv.aliases = list(dict.fromkeys([*adv.aliases, *aliases]))

    try:
        adv.title = clean.title(data.get("title"))
    except clean.FeedDataError as e:
        raise AdvisoryDataError(str(e)) from e
    adv.source = data.get("source") or "manual"
    adv.source_url = clean.http_url(data.get("source_url"))
    adv.summary_text = data.get("summary_text")
    adv.cvss_score = data.get("cvss_score")
    adv.cvss_vector = data.get("cvss_vector")
    adv.network_unauthenticated = data.get("network_unauthenticated")
    adv.kev = bool(data.get("kev")) or adv.kev
    adv.exploited = bool(data.get("exploited"))
    adv.published_at = _parse_time(data.get("published_at"))
    adv.drill = bool(data.get("drill"))
    adv.review_status = review_status
    _set_affects(adv, affects)
    adv.group_key = None  # people-owned advisories group only by their aliases
    session.flush()
    return adv


# --- Live feeds -----------------------------------------------------------------------------


@dataclass(frozen=True)
class IngestResult:
    advisory: Advisory | None
    created: bool = False
    changed: bool = False  # anything matching or scoring depends on


def _hash(data: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()


def _matching_facts(adv: Advisory) -> str:
    return _hash(
        {
            "status": adv.review_status.value,
            "affects": sorted(
                (a.component_key, json.dumps(a.ranges, sort_keys=True)) for a in adv.affects
            ),
            "cvss": [adv.cvss_score, adv.cvss_vector],
            "kev": adv.kev,
        }
    )


def owned_by_people(adv: Advisory) -> bool:
    return adv.source in PERSON_SOURCES or adv.reviewed_at is not None


def ingest_feed_advisory(
    session: Session,
    source: str,
    item_id: str,
    data: dict[str, Any],
    review_status: ReviewStatus,
    kev_cves: frozenset[str] = frozenset(),
) -> IngestResult:
    """Store one cleaned feed item. Unchanged items are skipped without touching anything.

    `data` comes from a parser in app/feeds/ and has already been cleaned. It is validated
    again here, because this is the last stop before the engine sees it.
    """
    aliases = list(dict.fromkeys(data.get("aliases") or []))
    if not aliases:
        raise AdvisoryDataError("an advisory needs at least one alias")
    affects = _validate_affects(data.get("affects") or [])
    if has_unsure(affects) or not affects:
        review_status = ReviewStatus.NEEDS_REVIEW  # a person must settle these versions first

    content_hash = _hash({"data": data, "status": review_status.value})
    item = session.scalar(
        select(FeedItem).where(FeedItem.source == source, FeedItem.item_id == item_id)
    )
    now = utcnow()
    if item is not None and item.content_hash == content_hash:
        item.last_seen = now
        adv = session.get(Advisory, item.advisory_id) if item.advisory_id else None
        return IngestResult(adv)

    adv = session.get(Advisory, item.advisory_id) if item and item.advisory_id else None
    adv = adv or find_by_aliases(session, aliases)
    kev = bool(data.get("kev")) or bool(kev_cves & set(aliases))
    created = adv is None
    before = None if adv is None else _matching_facts(adv)

    if data.get("withdrawn"):
        if adv is not None and adv.source == source and not owned_by_people(adv):
            adv.review_status = ReviewStatus.REJECTED
            adv.review_reason = "withdrawn by the source"
        created = False
    elif adv is None:
        adv = Advisory(aliases=aliases, source=source, title=data["title"], kev=kev)
        session.add(adv)
        _replace_content(adv, source, data, affects, review_status)
    else:
        adv.aliases = list(dict.fromkeys([*adv.aliases, *aliases]))
        adv.kev = adv.kev or kev
        stronger = SOURCE_RANK.get(source, 0) >= SOURCE_RANK.get(adv.source, 0)
        if not owned_by_people(adv) and stronger:
            _replace_content(adv, source, data, affects, review_status)
        else:
            _fill_blanks(adv, data)

    session.flush()
    if adv is not None and not owned_by_people(adv):
        adv.group_key = group_key(adv) if adv.review_status is ReviewStatus.CONFIRMED else None
    if item is None:
        item = FeedItem(source=source, item_id=item_id, content_hash=content_hash)
        session.add(item)
    item.content_hash, item.last_seen = content_hash, now
    item.advisory_id = adv.id if adv is not None else None
    session.flush()
    changed = adv is not None and (created or before != _matching_facts(adv))
    return IngestResult(adv, created=created, changed=changed)


def _replace_content(
    adv: Advisory,
    source: str,
    data: dict[str, Any],
    affects: list[dict[str, Any]],
    review_status: ReviewStatus,
) -> None:
    adv.source = source
    adv.title = data["title"]
    adv.source_url = data.get("source_url")
    adv.summary_text = data.get("summary_text")
    adv.cvss_score = data.get("cvss_score")
    adv.cvss_vector = data.get("cvss_vector") if data.get("cvss_score") is not None else None
    adv.network_unauthenticated = None  # scoring reads the CVSS vector instead
    adv.published_at = data.get("published_at")
    adv.attribution = data.get("attribution")
    adv.review_status = review_status
    adv.review_reason = data.get("review_reason")
    _set_affects(adv, affects)


def _fill_blanks(adv: Advisory, data: dict[str, Any]) -> None:
    if adv.cvss_score is None and data.get("cvss_score") is not None:
        adv.cvss_score, adv.cvss_vector = data["cvss_score"], data.get("cvss_vector")
    adv.source_url = adv.source_url or data.get("source_url")
    adv.summary_text = adv.summary_text or data.get("summary_text")
    adv.published_at = adv.published_at or data.get("published_at")
    adv.attribution = adv.attribution or data.get("attribution")


def mark_known_exploited(session: Session, kev_cves: frozenset[str]) -> list[Advisory]:
    """CISA KEV: flag every advisory with a listed CVE. Returns the newly flagged ones."""
    flagged = []
    for adv in session.scalars(select(Advisory).where(Advisory.kev.is_(False))):
        if kev_cves & set(adv.aliases):
            adv.kev = True
            flagged.append(adv)
    session.flush()
    return flagged


# --- The review queue (needs_review advisories) -----------------------------------------------

# One line per range, for people: "php: from 8.4.0 fixed 8.4.24". See RANGE_HELP.
_LINE = re.compile(
    r"^(?P<key>\S+?):\s+from\s+(?P<introduced>\S+)"
    r"(?:\s+(?:fixed\s+(?P<fixed>\S+)|last\s+(?P<last_affected>\S+)"
    r"|until\s+(?P<limit>\S+)(?:\s+(?P<flag>unsupported|unsure))?))?\s*$"
)
RANGE_HELP = (
    "One line per affected range. 'php: from 8.4.0 fixed 8.4.24' means 8.4.0 up to (not "
    "including) 8.4.24 is affected. 'last 1.4.2' means 1.4.2 is the last affected version and "
    "no fix is known. 'until 8.2.0 unsupported' marks old branches that get no fix. A line with "
    "'unsure' must be settled before confirming: delete it if those versions aren't affected, "
    "or change it. Use 'from 0' for 'every version before'."
)


def ranges_to_text(advisory: Advisory) -> str:
    lines = []
    for affect in advisory.affects:
        for r in affect.ranges:
            line = f"{affect.component_key}: from {r.get('introduced', '0')}"
            if "fixed" in r:
                line += f" fixed {r['fixed']}"
            elif "last_affected" in r:
                line += f" last {r['last_affected']}"
            elif "limit" in r:
                line += f" until {r['limit']}"
                line += (
                    " unsure" if r.get("unsure") else " unsupported" if r.get("unsupported") else ""
                )
            lines.append(line)
    return "\n".join(lines)


def text_to_affects(text: str, keep: list[AdvisoryAffect] | None = None) -> list[dict[str, Any]]:
    """Parse the review form. Any line that doesn't fit the format is refused with its number."""
    by_key: dict[str, dict[str, Any]] = {}
    for n, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        m = _LINE.match(line)
        if m is None or not is_valid_key(m["key"]):
            raise AdvisoryDataError(f"Line {n} doesn't fit the format: {line[:80]!r}")
        rng: dict[str, Any] = {"introduced": m["introduced"]}
        for bound in ("fixed", "last_affected", "limit"):
            if m[bound]:
                rng[bound] = m[bound]
        if m["flag"]:
            rng[m["flag"]] = True
        try:
            validate_ranges([rng])
        except AdvisoryDataError as e:
            raise AdvisoryDataError(f"Line {n}: a version can't be read.") from e
        affect = by_key.setdefault(
            m["key"], {"component_key": m["key"], "ranges": [], "fixed_versions": []}
        )
        affect["ranges"].append(rng)
        if "fixed" in rng and rng["fixed"] not in affect["fixed_versions"]:
            affect["fixed_versions"].append(rng["fixed"])
    for old in keep or []:  # distro fix data isn't edited here; keep it
        if old.component_key in by_key:
            by_key[old.component_key]["distro_fixes"] = old.distro_fixes
    return list(by_key.values())


class ReviewError(ValueError):
    pass


def confirm_advisory(
    session: Session, advisory: Advisory, user: User, ranges_text: str, note: str | None
) -> None:
    """A person confirms the affected versions. Matching runs afterwards (the caller does it)."""
    if advisory.review_status is not ReviewStatus.NEEDS_REVIEW:
        raise ReviewError("This advisory isn't waiting for review.")
    try:
        affects = text_to_affects(ranges_text, keep=list(advisory.affects))
    except AdvisoryDataError as e:
        raise ReviewError(str(e)) from e
    if not affects:
        raise ReviewError("Add at least one affected range, or reject the advisory instead.")
    if has_unsure(affects):
        raise ReviewError(
            "Settle every 'unsure' line first: delete it if those versions aren't affected, "
            "or change it to 'fixed', 'last' or 'unsupported'."
        )
    _set_affects(advisory, affects)
    advisory.review_status = ReviewStatus.CONFIRMED
    advisory.reviewed_by, advisory.reviewed_at = user.id, utcnow()
    advisory.review_note = (note or "").strip()[:1000] or None
    session.flush()
    advisory.group_key = group_key(advisory)
    session.flush()


def reject_advisory(session: Session, advisory: Advisory, user: User, note: str | None) -> None:
    if advisory.review_status is not ReviewStatus.NEEDS_REVIEW:
        raise ReviewError("This advisory isn't waiting for review.")
    note = (note or "").strip()
    if not note:
        raise ReviewError("Please add a note saying why (for example: covered by GHSA-…).")
    advisory.review_status = ReviewStatus.REJECTED
    advisory.reviewed_by, advisory.reviewed_at = user.id, utcnow()
    advisory.review_note = note[:1000]
    session.flush()


def set_exploited(
    session: Session, advisory: Advisory, user: User, exploited: bool, note: str | None
) -> None:
    """A person records credible reports of exploitation (+30, DESIGN.md §4.6), or takes it
    back. Feeds never change this flag. The caller re-runs matching to rescore."""
    note = (note or "").strip()
    if not note:
        raise ReviewError("Please add a note saying where the reports come from.")
    if advisory.exploited == exploited:
        return
    advisory.exploited = exploited
    for link in session.scalars(
        select(IncidentAdvisory).where(IncidentAdvisory.advisory_id == advisory.id)
    ):
        session.add(
            Event(
                incident_id=link.incident_id,
                actor_user_id=user.id,
                type="exploited_reported" if exploited else "exploited_withdrawn",
                note=note[:1000],
                data={"aliases": advisory.aliases},
            )
        )
    session.flush()

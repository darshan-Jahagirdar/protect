"""Wordfence Intelligence (production feed): the primary source for WordPress core, plugins and
themes (DESIGN.md §4.3).

Terms (read 2026-11-04, "Wordfence Intelligence Terms and Conditions", updated 2026-01-26): free,
commercial use allowed, an API key from a wordfence.com account, kept private. Records carry
copyright notices (Defiant, and MITRE for CVE text); we keep them and show them with the
advisory.

The feed is the whole database in one JSON object (tens of MB), so it is read one record at a
time from a temporary file. Only records for WordPress core and for plugins and themes that
some site actually has are stored; the rest is skipped. A newly installed plugin is picked up
on the next hourly run.
"""

import codecs
import json
from collections.abc import Iterator
from typing import IO, Any

from sqlalchemy import select

from app.engine.catalogue import is_valid_key
from app.engine.versions import parse_loose
from app.enums import ReviewStatus
from app.feeds import clean
from app.feeds.runner import FeedContext, FeedOutcome, store
from app.models import SiteComponent

SOURCE = "wordfence"
URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
MAX_BYTES = 400 * 1024 * 1024
MAX_RECORD = 1024 * 1024  # one record bigger than this is refused
_TYPES = {"core": "wordpress", "plugin": "wp-plugin", "theme": "wp-theme"}


def run(ctx: FeedContext, out: FeedOutcome) -> None:
    key = ctx.settings.wordfence_api_key
    if key is None:  # the runner only starts this feed with a key
        raise clean.FeedDataError("no Wordfence API key")
    wanted = installed_keys(ctx)
    dl = ctx.fetch(
        URL, max_bytes=MAX_BYTES, headers={"Authorization": f"Bearer {key.get_secret_value()}"}
    )
    try:
        for record_id, record in iter_records(dl.body):
            if not relevant(record, wanted) or record.get("informational") is True:
                continue  # not ours, or "extremely limited or no real-world impact"
            try:
                item_id, data, status = parse(record_id, record)
            except clean.FeedDataError as e:
                out.rejected += 1
                if len(out.notes) < 5:
                    out.notes.append(f"skipped a record: {e}"[:200])
                continue
            store(ctx, out, SOURCE, item_id, data, status)
    finally:
        dl.close()


def installed_keys(ctx: FeedContext) -> set[str]:
    keys = set(ctx.session.scalars(select(SiteComponent.component_key).distinct()))
    return {k for k in keys if k.startswith(("wp-plugin:", "wp-theme:"))} | {"wordpress"}


def relevant(record: Any, wanted: set[str]) -> bool:
    if not isinstance(record, dict) or not isinstance(record.get("software"), list):
        return False
    for sw in record["software"]:
        if isinstance(sw, dict) and sw.get("type") in _TYPES:
            key = "wordpress" if sw["type"] == "core" else f"{_TYPES[sw['type']]}:{sw.get('slug')}"
            if key in wanted:
                return True
    return False


def iter_records(body: IO[bytes], chunk_size: int = 1024 * 1024) -> Iterator[tuple[str, Any]]:
    """Yield (key, value) from a top-level JSON object without loading the whole file."""
    body.seek(0)
    decode = codecs.getincrementaldecoder("utf-8")().decode  # characters can span chunks
    decoder = json.JSONDecoder()
    buf, pos, eof = "", 0, False

    def bad() -> clean.FeedDataError:
        return clean.FeedDataError("the Wordfence feed isn't a valid JSON object")

    def more() -> bool:
        nonlocal buf, pos, eof
        if eof:
            return False
        chunk = body.read(chunk_size)
        eof = not chunk
        try:
            buf = buf[pos:] + decode(chunk, final=eof)
        except UnicodeDecodeError as e:
            raise bad() from e
        pos = 0
        return not eof

    def peek() -> str:
        """The next character that isn't whitespace ("" at the end of the file)."""
        nonlocal pos
        while True:
            while pos < len(buf) and buf[pos] in " \t\r\n":
                pos += 1
            if pos < len(buf):
                return buf[pos]
            if not more():
                return ""

    def value() -> Any:
        nonlocal pos
        while True:
            try:
                obj, end = decoder.raw_decode(buf, pos)
            except json.JSONDecodeError:
                if len(buf) - pos > MAX_RECORD or not more():
                    raise bad() from None
                continue
            if end == len(buf) and more():  # a number could go on in the next chunk
                continue
            pos = end
            return obj

    if peek() != "{":
        raise bad()
    pos += 1
    first = True
    while True:
        if peek() == "}":
            return
        if not first:
            if peek() != ",":
                raise bad()
            pos += 1
            peek()
        first = False
        key = value()
        if not isinstance(key, str) or peek() != ":":
            raise bad()
        pos += 1
        peek()
        yield key, value()


def _ranges(sw: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """Wordfence {from_version, from_inclusive, to_version, to_inclusive} -> OSV-style ranges.
    Returns (ranges, fixed versions, problems)."""
    patched = [v for v in (clean.version(p) for p in sw.get("patched_versions") or []) if v]
    problems: list[str] = []
    ranges: list[dict[str, Any]] = []
    affected = sw.get("affected_versions")
    for label, r in affected.items() if isinstance(affected, dict) else []:
        if not isinstance(r, dict):
            problems.append("an affected range isn't an object")
            continue
        low, high = r.get("from_version"), r.get("to_version")
        rng: dict[str, Any] = {}
        if low == "*":
            rng["introduced"] = "0"
        elif clean.version(low):
            # An open lower end ("(1.0, …") can't be written exactly; including 1.0 itself only
            # errs towards "affected", never towards "safe".
            rng["introduced"] = low
        else:
            problems.append(f"couldn't read the range {str(label)[:40]!r}")
            continue
        if high == "*":
            pass  # every version from `introduced` on: no fix yet
        elif clean.version(high) is None:
            problems.append(f"couldn't read the range {str(label)[:40]!r}")
            continue
        elif r.get("to_inclusive") is True:
            top = parse_loose(high)
            later = [
                p
                for p in patched
                if (pv := parse_loose(p)) is not None and top is not None and pv > top
            ]
            if later:  # the first fixed release after the last affected one
                rng["fixed"] = min(later, key=lambda p: parse_loose(p))  # type: ignore[arg-type,return-value]
            else:
                rng["last_affected"] = high
        else:
            rng["fixed"] = high
        ranges.append(rng)
    return ranges, patched, problems


def parse(record_id: str, record: dict[str, Any]) -> tuple[str, dict[str, Any], ReviewStatus]:
    if not clean.UUID_RE.match(record_id or "") or record.get("id") != record_id:
        raise clean.FeedDataError("missing or malformed Wordfence id")
    if record.get("informational") is True:
        raise clean.FeedDataError("informational record (no real-world impact)")
    aliases = [f"wordfence:{record_id}"]
    cve = clean.cve(record.get("cve"))
    if cve:
        aliases.append(cve)

    problems: list[str] = []
    affects: dict[str, dict[str, Any]] = {}
    for sw in record.get("software") or []:
        if not isinstance(sw, dict) or sw.get("type") not in _TYPES:
            continue
        slug = sw.get("slug")
        key = "wordpress" if sw["type"] == "core" else f"{_TYPES[sw['type']]}:{slug}"
        if not isinstance(slug, str) or not is_valid_key(key):
            problems.append("a software slug isn't one Protect can match")
            continue
        ranges, patched, issues = _ranges(sw)
        problems += issues
        if not ranges:
            problems.append(f"no affected versions could be read for {key}")
            continue
        affect = affects.setdefault(key, {"component_key": key, "ranges": [], "fixed_versions": []})
        affect["ranges"] += ranges
        affect["fixed_versions"] += [p for p in patched if p not in affect["fixed_versions"]]

    cvss = record.get("cvss") if isinstance(record.get("cvss"), dict) else {}
    score = clean.cvss_score(cvss.get("score"))
    refs = record.get("references") if isinstance(record.get("references"), list) else []
    link = next(
        (u for u in (clean.http_url(r) for r in refs) if u and "wordfence.com/threat-intel/" in u),
        None,
    )
    data: dict[str, Any] = {
        "title": clean.title(record.get("title")),
        "aliases": aliases,
        "source_url": link,
        "summary_text": clean.text(record.get("description")),
        "cvss_score": score,
        "cvss_vector": clean.cvss_vector(cvss.get("vector")) if score is not None else None,
        "published_at": clean.timestamp(record.get("published")),
        "attribution": attribution(record.get("copyrights")),
        "review_reason": "; ".join(dict.fromkeys(problems))[:1000] or None,
        "affects": list(affects.values()),
    }
    status = ReviewStatus.NEEDS_REVIEW if problems or not affects else ReviewStatus.CONFIRMED
    return record_id, data, status


def attribution(copyrights: Any) -> str | None:
    """The copyright notices and licence links the record carries, as plain text."""
    if not isinstance(copyrights, dict):
        return None
    parts = []
    for holder in copyrights.values():
        if isinstance(holder, dict):
            notice = clean.text(holder.get("notice"), 200)
            url = clean.http_url(holder.get("license_url"))
            if notice:
                parts.append(notice + (f" Licence: {url}" if url else ""))
    return " · ".join(parts)[:1000] or None

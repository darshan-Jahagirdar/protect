"""Turning a validated report into stored data and the site's current inventory."""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.api.schemas import Report as ReportPayload
from app.db import utcnow
from app.engine.catalogue import is_valid_key
from app.engine.matcher import OsFacts, classify_php_build
from app.engine.versions import extract_version, parse_loose, parse_php
from app.models import Report, Site, SiteComponent
from app.services.enrollment import normalize_url
from app.services.incidents import rematch_site

log = logging.getLogger("protect.inventory")

_LIB_FIELDS = ("openssl", "curl", "libxml2", "pcre2", "icu", "imagemagick")


@dataclass(frozen=True)
class Component:
    key: str
    version_raw: str | None
    active: bool = True


@dataclass
class ApplyResult:
    stored: bool  # False when the report was identical to the last one
    report_id: int | None
    flags: list[str] = field(default_factory=list)
    skipped_keys: list[str] = field(default_factory=list)


def content_hash(report: ReportPayload) -> str:
    """Hash of everything except the send time, so identical hourly reports dedupe."""
    data = report.model_dump(mode="json", by_alias=True, exclude={"generated_at"})
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _server_name(software: str) -> str | None:
    words = software.split("/", 1)[0].split()
    return words[0].lower() if words else None


def components_from(report: ReportPayload) -> tuple[list[Component], list[str]]:
    """Build the inventory list. Returns (components, keys that were skipped as invalid)."""
    out: list[Component] = [Component("php", report.php.version)]
    out += [Component(f"php-ext:{e.name}", e.version) for e in report.php.extensions]
    for name in _LIB_FIELDS:
        value = getattr(report.libs, name)
        if value:
            out.append(Component(f"lib:{name}", value))
    out.append(Component("wordpress", report.wordpress.version))
    out += [Component(f"wp-plugin:{p.slug}", p.version, p.active) for p in report.plugins]
    out += [Component(f"wp-theme:{t.slug}", t.version, t.active) for t in report.themes]
    if report.db and report.db.engine != "unknown":
        out.append(Component(f"db:{report.db.engine}", report.db.version))
    server = _server_name(report.server.software or "")
    if server:
        out.append(Component(f"server:{server}", report.server.software))
    if report.os and report.os.id:
        out.append(Component(f"os:{report.os.id}", report.os.version_id))

    valid, skipped, seen = [], [], set()
    for c in out:
        if not is_valid_key(c.key):
            skipped.append(c.key)
        elif c.key not in seen:  # first one wins if a name repeats
            seen.add(c.key)
            valid.append(c)
    return valid, skipped


def _went_down(old: str | None, new: str | None, php: bool = False) -> bool:
    if php:
        a, b = parse_php(old), parse_php(new)
        return bool(a and b and b.upstream < a.upstream)
    va, vb = parse_loose(old), parse_loose(new)
    return bool(va and vb and vb < va)


def flags_for(report: ReportPayload, site: Site, previous: dict | None, now: datetime) -> list[str]:
    """Signs of an odd report. They don't reject it; they mark the site 'suspicious report'."""
    flags: list[str] = []
    try:
        if normalize_url(report.site_url) != site.url:
            flags.append("site_url_mismatch")
    except ValueError:
        flags.append("site_url_mismatch")

    php = parse_php(report.php.version)
    if not php or (php.major, php.minor, php.release) != (
        report.php.major,
        report.php.minor,
        report.php.release,
    ):
        flags.append("php_version_inconsistent")

    if previous:
        if _went_down(previous.get("php", {}).get("version"), report.php.version, php=True):
            flags.append("php_version_went_down")
        if _went_down(previous.get("wordpress", {}).get("version"), report.wordpress.version):
            flags.append("wordpress_version_went_down")

    generated = report.generated_at
    if generated.tzinfo is None or abs(generated - now) > timedelta(hours=24):
        flags.append("generated_at_far_from_now")
    return flags


def _rebuild_inventory(
    session: Session, site: Site, report: ReportPayload, now: datetime
) -> list[str]:
    components, skipped = components_from(report)
    os = OsFacts.from_report(report.os.model_dump() if report.os else None)
    existing = {c.component_key: c for c in site.components}

    for comp in components:
        distro = None
        if comp.key == "php":
            parsed = parse_php(comp.version_raw)
            distro = classify_php_build(parsed, os).value if parsed else None
        row = existing.pop(comp.key, None)
        if row is None:
            row = SiteComponent(site_id=site.id, component_key=comp.key, first_seen=now)
            site.components.append(row)
        row.version_raw = comp.version_raw
        row.version_parsed = {"normalized": extract_version(comp.key, comp.version_raw)}
        row.distro = distro
        row.active = comp.active
        row.last_seen = now

    for gone in existing.values():  # uninstalled since the last report
        site.components.remove(gone)
    return skipped


def apply_report(
    session: Session, site: Site, report: ReportPayload, now: datetime | None = None
) -> ApplyResult:
    now = now or utcnow()
    digest = content_hash(report)
    last = session.get(Report, site.last_report_id) if site.last_report_id else None

    if last is not None and last.content_hash == digest:
        site.last_report_at = now
        session.flush()
        return ApplyResult(stored=False, report_id=last.id)

    flags = flags_for(report, site, last.payload if last else None, now)
    row = Report(
        site_id=site.id,
        received_at=now,
        content_hash=digest,
        schema_version=report.schema_,
        plugin_version=report.plugin_version,
        payload=report.model_dump(mode="json", by_alias=True),
        flags=flags,
    )
    session.add(row)
    session.flush()

    site.last_report_id = row.id
    site.last_report_at = now
    if flags:
        site.suspicious = True
        log.warning("site %s sent an odd report: %s", site.id, ",".join(flags))

    skipped = _rebuild_inventory(session, site, report, now)
    if skipped:
        log.warning("site %s: skipped invalid component keys %s", site.id, skipped)
    session.flush()
    rematch_site(session, site)  # the inventory changed, so check it against advisories
    return ApplyResult(stored=True, report_id=row.id, flags=flags, skipped_keys=skipped)

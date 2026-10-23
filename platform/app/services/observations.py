"""Running the observer on a schedule, storing what it saw, and cross-checking it with the
plugin's report (DESIGN.md §4.9).

The cross-check is the point: a hacked plugin can lie about the PHP version, but it can't
change what the web server announces to every visitor. When the two disagree, people look.
"""

import logging
import re
from collections.abc import Callable
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db import utcnow
from app.engine.versions import parse_php
from app.enums import IncidentStatus, Priority, SiteStatus
from app.models import Case, Event, Incident, Observation, Site, SiteComponent
from app.observer.observe import ObservationResult, observe
from app.services.incidents import RESOLVED
from app.settings import Settings

log = logging.getLogger("protect.observer")

KEEP_FOR = timedelta(days=90)
TLS_WARN_WITHIN = timedelta(days=14)
_POWERED_BY_PHP = re.compile(r"PHP/(\d+\.\d+\.\d+)", re.IGNORECASE)

ObserveFn = Callable[..., ObservationResult]


def public_php_version(obs: Observation | None) -> str | None:
    m = _POWERED_BY_PHP.search(obs.powered_by or "") if obs else None
    return m.group(1) if m else None


def reported_php_version(session: Session, site: Site) -> str | None:
    comp = session.scalar(
        select(SiteComponent).where(
            SiteComponent.site_id == site.id, SiteComponent.component_key == "php"
        )
    )
    php = parse_php(comp.version_raw) if comp else None
    return f"{php.major}.{php.minor}.{php.release}" if php else None


def disagreement(session: Session, site: Site, obs: Observation | None) -> str | None:
    """A plain-English description when the public view and the report disagree."""
    public, reported = public_php_version(obs), reported_php_version(session, site)
    if public and reported and public != reported:
        return f"the web server announces PHP {public}, but the plugin reports PHP {reported}"
    return None


def latest_observation(session: Session, site: Site) -> Observation | None:
    return session.scalar(
        select(Observation).where(Observation.site_id == site.id).order_by(Observation.id.desc())
    )


def _rewriter(settings: Settings):  # type: ignore[no-untyped-def]
    """Docker demo only: connect to the internal address, but send the public Host header,
    so WordPress answers as it would to a visitor (and its redirects still make sense)."""
    mapping = settings.observer_rewrite_map

    def rewrite(url: str) -> tuple[str, str | None]:
        for public, internal in mapping.items():
            if url == public or url.startswith(public + "/"):
                return internal + url[len(public) :], urlsplit(public).netloc
        return url, None

    return rewrite


def _open_cases(session: Session, site: Site) -> list[Case]:
    return list(
        session.scalars(
            select(Case)
            .join(Incident)
            .where(
                Case.site_id == site.id,
                Incident.status != IncidentStatus.CLOSED,
                Case.exposure.not_in(RESOLVED),
            )
        )
    )


def observe_site(
    session: Session,
    site: Site,
    settings: Settings,
    now: datetime | None = None,
    observe_fn: ObserveFn = observe,
) -> Observation:
    now = now or utcnow()
    previous = latest_observation(session, site)
    was = disagreement(session, site, previous)
    result = observe_fn(site.url, allow_private=not settings.is_prod, rewrite=_rewriter(settings))
    obs = Observation(
        site_id=site.id,
        at=now,
        http_status=result.http_status,
        server_header=result.server_header,
        powered_by=result.powered_by,
        behind_cloudflare=result.behind_cloudflare,
        tls_expires_at=result.tls_expires_at,
        error=result.error,
    )
    session.add(obs)
    session.flush()
    now_says = disagreement(session, site, obs)
    if now_says and now_says != was:
        for case in _open_cases(session, site):
            session.add(
                Event(
                    incident_id=case.incident_id,
                    case_id=case.id,
                    at=now,
                    type="public_view_disagrees",
                    note=now_says,
                )
            )
        log.warning("site %s: %s", site.id, now_says)
    return obs


def _urgent_site_ids(session: Session) -> set[int]:
    return set(
        session.scalars(
            select(Case.site_id)
            .join(Incident)
            .where(
                Incident.status != IncidentStatus.CLOSED,
                Incident.priority.in_([Priority.P1, Priority.P2]),
                Case.exposure.not_in(RESOLVED),
            )
        )
    )


def observe_due(
    session: Session,
    settings: Settings,
    now: datetime | None = None,
    observe_fn: ObserveFn = observe,
) -> int:
    """Scheduler job: daily per site, every 30 minutes while a site is in a P1/P2 incident."""
    now = now or utcnow()
    urgent = _urgent_site_ids(session)
    done = 0
    for site in session.scalars(select(Site).where(Site.status == SiteStatus.ACTIVE)):
        last = latest_observation(session, site)
        every = (
            timedelta(minutes=settings.observer_urgent_interval_minutes)
            if site.id in urgent
            else timedelta(hours=settings.observer_interval_hours)
        )
        if last is None or now - last.at >= every:
            observe_site(session, site, settings, now, observe_fn)
            done += 1
    session.execute(delete(Observation).where(Observation.at < now - KEEP_FOR))
    session.flush()
    return done


def tls_warning(obs: Observation | None, now: datetime | None = None) -> str | None:
    if obs is None or obs.tls_expires_at is None:
        return None
    left = obs.tls_expires_at - (now or utcnow())
    if left <= timedelta(0):
        return "the HTTPS certificate has expired"
    if left <= TLS_WARN_WITHIN:
        return f"the HTTPS certificate expires in {left.days} day(s)"
    return None


def edge_status(obs: Observation | None) -> str:
    """For checklists: what the observer saw in front of the site."""
    if obs is None or obs.behind_cloudflare is None:
        return "The observer hasn't checked whether this site is behind Cloudflare yet."
    if obs.behind_cloudflare:
        return "The observer sees this site behind Cloudflare."
    return "The observer doesn't see Cloudflare in front of this site."


def run_observer(session_factory: Callable[[], Session], settings: Settings) -> None:
    with session_factory() as session:
        observe_due(session, settings)
        session.commit()

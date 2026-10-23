"""Matching advisories against sites, and keeping incidents and cases up to date
(DESIGN.md §4.5–4.7).

An incident is one real-world event (it can carry several advisories); a case is one site
component within one incident. Decisions about exposure come only from the rules engine.
People's decisions (fix claimed, false positive, accepted risk) are never overwritten here.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import utcnow
from app.engine.catalogue import ComponentKind, kind_of
from app.engine.matcher import AffectRule, Bucket, ComponentFacts, MatchResult, OsFacts
from app.engine.matcher import match_component as engine_match
from app.engine.scoring import ScoreInput, score
from app.enums import Exposure, IncidentStatus, Priority, ReviewStatus, SiteStatus
from app.models import (
    Advisory,
    AdvisoryAffect,
    Case,
    Event,
    Incident,
    IncidentAdvisory,
    Report,
    Site,
    SiteComponent,
)

# Exposure states the engine may change. Anything else was set by a person.
ENGINE_OWNED = {Exposure.VULNERABLE, Exposure.NEEDS_CHECK}
# States where the case is finished, unless the site becomes affected again.
DONE = {Exposure.VERIFIED, Exposure.NOT_AFFECTED}
# A person decided; keep it, only refresh the facts.
HUMAN_DECISION = {Exposure.FIX_CLAIMED, Exposure.FALSE_POSITIVE, Exposure.ACCEPTED_RISK}
# Cases that become VERIFIED on their own when a report shows the fix (or the component is
# gone). false_positive and not_affected stay as they are: nothing was ever wrong.
AUTO_VERIFY = {
    Exposure.VULNERABLE,
    Exposure.NEEDS_CHECK,
    Exposure.FIX_CLAIMED,
    Exposure.ACCEPTED_RISK,
}
# Nothing left to do on the site for these (the incident can move to monitoring).
RESOLVED = DONE | {Exposure.FALSE_POSITIVE, Exposure.ACCEPTED_RISK}

_BUCKET_TO_EXPOSURE = {
    Bucket.VULNERABLE: Exposure.VULNERABLE,
    Bucket.NEEDS_CHECK: Exposure.NEEDS_CHECK,
}

_KIND_TO_INCIDENT = {
    ComponentKind.PHP: "php-core",
    ComponentKind.WORDPRESS: "wp-core",
    ComponentKind.WP_PLUGIN: "wp-plugin",
    ComponentKind.WP_THEME: "wp-theme",
}
_INCIDENT_KIND_ORDER = ["php-core", "wp-core", "wp-plugin", "wp-theme", "lib"]
_PRIORITY_ORDER = [Priority.P1, Priority.P2, Priority.P3, Priority.P4]


@dataclass(frozen=True)
class Hit:
    site: Site
    component: SiteComponent
    affect: AdvisoryAffect
    result: MatchResult


def incident_kind(advisory: Advisory) -> str:
    kinds = {_KIND_TO_INCIDENT.get(kind_of(a.component_key), "lib") for a in advisory.affects}
    return next((k for k in _INCIDENT_KIND_ORDER if k in kinds), "lib")


def _site_os(session: Session, site: Site) -> OsFacts:
    report = session.get(Report, site.last_report_id) if site.last_report_id else None
    return OsFacts.from_report(report.payload.get("os") if report else None)


def match_site(session: Session, site: Site, advisory: Advisory) -> list[Hit]:
    """Run the engine for every component of this site the advisory mentions."""
    components = {c.component_key: c for c in site.components}
    os = _site_os(session, site)
    hits = []
    for affect in advisory.affects:
        comp = components.get(affect.component_key)
        if comp is None:
            continue  # not installed on this site
        rule = AffectRule(affect.component_key, affect.ranges, affect.distro_fixes)
        result = engine_match(
            ComponentFacts(comp.component_key, comp.version_raw, comp.active), rule, os
        )
        hits.append(Hit(site, comp, affect, result))
    return hits


def _event(
    session: Session,
    type_: str,
    incident: Incident,
    case: Case | None = None,
    note: str | None = None,
    **data: object,
) -> None:
    session.add(
        Event(
            incident_id=incident.id,
            case_id=case.id if case else None,
            type=type_,
            note=note,
            data=data,
        )
    )


def _open_incident_for(session: Session, advisory: Advisory) -> Incident | None:
    return session.scalar(
        select(Incident)
        .join(IncidentAdvisory, IncidentAdvisory.incident_id == Incident.id)
        .where(
            IncidentAdvisory.advisory_id == advisory.id, Incident.status != IncidentStatus.CLOSED
        )
    )


def _create_incident(session: Session, advisory: Advisory) -> Incident:
    incident = Incident(
        title=advisory.title,
        kind=incident_kind(advisory),
        priority=Priority.P4,  # raised from its cases below
        drill=advisory.drill,
    )
    session.add(incident)
    session.flush()
    session.add(IncidentAdvisory(incident_id=incident.id, advisory_id=advisory.id))
    _event(session, "incident_opened", incident, aliases=advisory.aliases)
    return incident


def _score_for(advisory: Advisory, hit: Hit, shielded: bool) -> tuple[int, Priority, list[str]]:
    s = score(
        ScoreInput(
            cvss_score=advisory.cvss_score,
            cvss_vector=advisory.cvss_vector,
            network_unauthenticated=advisory.network_unauthenticated,
            kev=advisory.kev,
            exploited=advisory.exploited,
            risk_tags=tuple(hit.site.risk_tags or ()),
            component_active=hit.component.active,
            shielded=shielded,
        )
    )
    return s.points, s.priority, list(s.reasons)


def _find_case(session: Session, incident: Incident, site_id: int, key: str) -> Case | None:
    return session.scalar(
        select(Case).where(
            Case.incident_id == incident.id, Case.site_id == site_id, Case.component_key == key
        )
    )


def _apply_hit(session: Session, incident: Incident, advisory: Advisory, hit: Hit) -> None:
    case = _find_case(session, incident, hit.site.id, hit.component.component_key)
    r = hit.result

    if r.bucket is Bucket.SAFE:
        if case is not None and case.exposure in AUTO_VERIFY:
            _verify(session, incident, case, note=r.reasons[0], version=r.version)
        return

    exposure = _BUCKET_TO_EXPOSURE[r.bucket]
    points, priority, reasons = _score_for(advisory, hit, case.shielded if case else False)

    if case is None:
        case = Case(
            incident=incident,  # via the relationship, so incident.cases stays current
            site_id=hit.site.id,
            component_key=hit.component.component_key,
            exposure=exposure,
            priority=priority,
            score=points,
            score_reasons=reasons,
        )
        session.add(case)
        _fill_facts(case, r)
        session.flush()
        _event(
            session,
            "case_opened",
            incident,
            case,
            note=r.reasons[0],
            exposure=exposure.value,
            score=points,
            priority=priority.value,
        )
        return

    before = (case.exposure, case.score, case.version_seen)
    reopened = case.exposure in DONE
    if case.exposure in ENGINE_OWNED or reopened:
        case.exposure = exposure
    # HUMAN_DECISION states are kept as they are.
    case.priority, case.score, case.score_reasons = priority, points, reasons
    _fill_facts(case, r)
    if reopened:
        _event(session, "case_reopened", incident, case, note=r.reasons[0], version=r.version)
    elif (case.exposure, case.score, case.version_seen) != before:
        _event(
            session,
            "case_updated",
            incident,
            case,
            note=r.reasons[0],
            exposure=case.exposure.value,
            score=points,
            version=r.version,
        )


def _fill_facts(case: Case, r: MatchResult) -> None:
    case.version_seen = r.version
    case.fixed_version = r.fixed_version
    case.unsupported_branch = r.unsupported_branch
    case.match_reasons = list(r.reasons)


def _verify(
    session: Session, incident: Incident, case: Case, note: str, version: str | None
) -> None:
    """The site's own report shows the fix (or the component is gone): verified."""
    before = case.exposure
    case.exposure = Exposure.VERIFIED
    case.version_seen = version
    case.match_reasons = [note]
    _event(session, "verified", incident, case, note=note, version=version, before=before.value)


def _verify_removed_components(session: Session, incident: Incident, sites: list[Site]) -> None:
    """Uninstalling the affected plugin or theme is a valid fix: verify those cases."""
    session.flush()
    by_id = {s.id: {c.component_key for c in s.components} for s in sites}
    for case in incident.cases:
        if case.site_id in by_id and case.component_key not in by_id[case.site_id]:
            if case.exposure in AUTO_VERIFY:
                _verify(
                    session,
                    incident,
                    case,
                    note=f"{case.component_key} is no longer installed",
                    version=None,
                )


def refresh_incident_status(session: Session, incident: Incident) -> None:
    """open -> monitoring when every site is resolved; back to open if one isn't any more.

    Closing is a person's decision (after client notices), never automatic.
    """
    session.flush()
    if incident.status is IncidentStatus.CLOSED or not incident.cases:
        return
    resolved = all(c.exposure in RESOLVED for c in incident.cases)
    if resolved and incident.status is IncidentStatus.OPEN:
        incident.status = IncidentStatus.MONITORING
        _event(
            session,
            "all_sites_resolved",
            incident,
            note="every affected site is verified or decided",
        )
    elif not resolved and incident.status is IncidentStatus.MONITORING:
        incident.status = IncidentStatus.OPEN
        _event(session, "incident_reopened", incident, note="a site is affected again")


def _refresh_incident_priority(session: Session, incident: Incident) -> None:
    session.flush()
    live = [c.priority for c in incident.cases if c.exposure not in DONE]
    if live:
        best = min(live, key=_PRIORITY_ORDER.index)
        if best != incident.priority:
            incident.priority = best


def apply_advisory(
    session: Session, advisory: Advisory, sites: list[Site] | None = None
) -> Incident | None:
    """Match one confirmed advisory against sites and open or update its incident.

    Returns the incident, or None when nothing is affected and no incident exists.
    """
    if advisory.review_status is not ReviewStatus.CONFIRMED:
        return None  # needs a human check of its version ranges first
    if sites is None:
        sites = list(session.scalars(select(Site).where(Site.status == SiteStatus.ACTIVE)))

    hits = [h for site in sites for h in match_site(session, site, advisory)]
    incident = _open_incident_for(session, advisory)
    if incident is None:
        if not any(h.result.bucket is not Bucket.SAFE for h in hits):
            return None
        incident = _create_incident(session, advisory)

    for hit in hits:
        _apply_hit(session, incident, advisory, hit)
    _verify_removed_components(session, incident, sites)
    _refresh_incident_priority(session, incident)
    refresh_incident_status(session, incident)
    session.flush()
    return incident


def rematch_site(session: Session, site: Site) -> list[Incident]:
    """Re-run every relevant confirmed advisory for one site (after a new report)."""
    if site.status is not SiteStatus.ACTIVE:
        return []
    keys = {c.component_key for c in site.components}
    with_open_cases = set(
        session.scalars(
            select(IncidentAdvisory.advisory_id)
            .join(Incident, Incident.id == IncidentAdvisory.incident_id)
            .join(Case, Case.incident_id == Incident.id)
            .where(Case.site_id == site.id, Incident.status != IncidentStatus.CLOSED)
        )
    )
    touched = []
    for advisory in session.scalars(
        select(Advisory).where(Advisory.review_status == ReviewStatus.CONFIRMED)
    ):
        if keys & {a.component_key for a in advisory.affects} or advisory.id in with_open_cases:
            incident = apply_advisory(session, advisory, [site])
            if incident is not None:
                touched.append(incident)
    return touched


FIX_VISIBLE_WITHIN = timedelta(hours=2)


def flag_unconfirmed_fixes(session: Session, now: datetime | None = None) -> int:
    """Fix claimed 2+ hours ago but the case still isn't verified: say so once (DESIGN §4.7).

    Usually means the host hasn't switched PHP yet, the server wasn't restarted, or the site
    has stopped reporting. Returns how many cases were flagged.
    """
    now = now or utcnow()
    flagged = 0
    for case in session.scalars(select(Case).where(Case.exposure == Exposure.FIX_CLAIMED)):
        claimed_at = session.scalar(
            select(Event.at)
            .where(Event.case_id == case.id, Event.type == "fix_claimed")
            .order_by(Event.id.desc())
        )
        if claimed_at is None or now - claimed_at < FIX_VISIBLE_WITHIN:
            continue
        already = session.scalar(
            select(Event.id).where(
                Event.case_id == case.id, Event.type == "fix_not_visible", Event.at >= claimed_at
            )
        )
        if already:
            continue
        site = session.get(Site, case.site_id)
        if site and site.last_report_at and site.last_report_at > claimed_at:
            note = f"reports since the fix was claimed still show {case.version_seen}"
        else:
            note = "no report from the site since the fix was claimed"
        session.add(
            Event(
                incident_id=case.incident_id,
                case_id=case.id,
                type="fix_not_visible",
                at=now,
                note=note,
            )
        )
        flagged += 1
    session.flush()
    return flagged


def fix_not_visible(session: Session, case: Case) -> bool:
    """Is this fix-claimed case currently flagged as not visible?"""
    if case.exposure is not Exposure.FIX_CLAIMED:
        return False
    return (
        _last_event_type_in(session, case, ("fix_claimed", "fix_not_visible")) == "fix_not_visible"
    )


def _last_event_type_in(session: Session, case: Case, types: tuple[str, ...]) -> str | None:
    return session.scalar(
        select(Event.type)
        .where(Event.case_id == case.id, Event.type.in_(types))
        .order_by(Event.id.desc())
    )

"""Deciding when to alert, escalating, the daily digest, and acknowledging
(DESIGN.md §4.8).

Alerting works from database state rather than from events, so a scheduler run that fails
halfway (mail server down) just tries again on the next run, and nothing is ever sent twice.
"""

import logging
from collections.abc import Callable
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.alerts import messages
from app.alerts.mailer import Mailer, Message
from app.alerts.messages import IncidentSummary
from app.db import utcnow
from app.enums import AlertChannel, Exposure, IncidentStatus, Priority
from app.models import Advisory, Alert, Event, Incident, IncidentAdvisory
from app.settings import Settings

log = logging.getLogger("protect.alerts")

URGENT = (Priority.P1, Priority.P2)
LOW = (Priority.P3, Priority.P4)
STILL_AFFECTED = {Exposure.VULNERABLE, Exposure.FIX_CLAIMED}


def summarize(session: Session, incident: Incident) -> IncidentSummary:
    """Counts of affected *sites* (not cases): a site counts once, as its worst state."""
    vulnerable = {c.site_id for c in incident.cases if c.exposure in STILL_AFFECTED}
    needs_check = {c.site_id for c in incident.cases if c.exposure is Exposure.NEEDS_CHECK}
    aliases: list[str] = []
    for adv in session.scalars(
        select(Advisory)
        .join(IncidentAdvisory, IncidentAdvisory.advisory_id == Advisory.id)
        .where(IncidentAdvisory.incident_id == incident.id)
    ):
        aliases += [a for a in adv.aliases if a not in aliases]
    return IncidentSummary(
        incident_id=incident.id,
        title=incident.title,
        priority=incident.priority,
        drill=incident.drill,
        aliases=tuple(aliases),
        vulnerable=len(vulnerable),
        needs_check=len(needs_check - vulnerable),
    )


def _open_incidents(session: Session, priorities: tuple[Priority, ...]) -> list[Incident]:
    return list(
        session.scalars(
            select(Incident)
            .where(Incident.status != IncidentStatus.CLOSED, Incident.priority.in_(priorities))
            .order_by(Incident.created_at)
        )
    )


def _alerts(session: Session, incident: Incident) -> list[Alert]:
    return list(
        session.scalars(select(Alert).where(Alert.incident_id == incident.id).order_by(Alert.id))
    )


def _send(
    session: Session,
    mailer: Mailer,
    incident: Incident,
    to: list[str],
    group: str,
    kind: str,
    summary: IncidentSummary,
    subject_body: tuple[str, str],
    now: datetime,
) -> Alert | None:
    if not to:
        log.warning(
            "no %s recipients configured; %s alert for %s not sent", group, kind, incident.id
        )
        return None
    subject, body = subject_body
    try:
        mailer.send(Message(tuple(to), subject, body))
    except Exception:  # retried on the next scheduler run
        log.exception("sending %s alert for incident %s failed", kind, incident.id)
        return None
    alert = Alert(
        incident_id=incident.id,
        channel=AlertChannel.EMAIL,
        kind=kind,
        priority=incident.priority,
        sites_count=summary.affected,
        recipients_group=group,
        sent_at=now,
    )
    session.add(alert)
    session.add(
        Event(
            incident_id=incident.id,
            type="alert_sent",
            at=now,
            data={"kind": kind, "group": group, "sites": summary.affected},
        )
    )
    session.flush()
    return alert


def send_due_alerts(
    session: Session, mailer: Mailer, settings: Settings, now: datetime | None = None
) -> int:
    """P1/P2 incidents: alert when new, and again when more sites are affected."""
    now = now or utcnow()
    sent = 0
    for incident in _open_incidents(session, URGENT):
        summary = summarize(session, incident)
        if summary.affected == 0:
            continue
        previous = [a for a in _alerts(session, incident) if a.kind in ("new", "update")]
        if not previous:
            text = messages.new_incident(summary, settings.base_url)
            kind = "new"
        else:
            last = max(a.sites_count for a in previous)
            if summary.affected <= last:
                continue
            text = messages.more_sites(summary, last, settings.base_url)
            kind = "update"
        if _send(
            session,
            mailer,
            incident,
            settings.alert_recipient_list,
            "responders",
            kind,
            summary,
            text,
            now,
        ):
            sent += 1
    return sent


def escalate_unacknowledged(
    session: Session, mailer: Mailer, settings: Settings, now: datetime | None = None
) -> int:
    """No ack within the timeout: alert the backup person, or the responders again."""
    now = now or utcnow()
    deadline = now - timedelta(minutes=settings.ack_timeout_minutes)
    sent = 0
    for incident in _open_incidents(session, URGENT):
        alerts = _alerts(session, incident)
        if is_acknowledged(session, incident) or any(a.kind == "escalation" for a in alerts):
            continue
        overdue = [a for a in alerts if a.kind in ("new", "update") and a.sent_at <= deadline]
        if not overdue:
            continue
        summary = summarize(session, incident)
        backup = settings.backup_recipient_list
        to, group = (backup, "backup") if backup else (settings.alert_recipient_list, "responders")
        text = messages.unacknowledged(summary, settings.ack_timeout_minutes, settings.base_url)
        if _send(session, mailer, incident, to, group, "escalation", summary, text, now):
            for a in overdue:
                a.escalated_at = now
            sent += 1
    return sent


def send_digest(
    session: Session, mailer: Mailer, settings: Settings, now: datetime | None = None
) -> int:
    """One daily email listing open P3/P4 incidents. Returns how many it listed."""
    summaries = [
        s for s in (summarize(session, i) for i in _open_incidents(session, LOW)) if s.affected > 0
    ]
    if not summaries or not settings.alert_recipient_list:
        return 0
    subject, body = messages.digest(summaries, settings.base_url)
    try:
        mailer.send(Message(tuple(settings.alert_recipient_list), subject, body))
    except Exception:
        log.exception("sending the daily digest failed")
        return 0
    return len(summaries)


def acknowledge(
    session: Session, incident: Incident, user_id: int | None, now: datetime | None = None
) -> bool:
    """Someone is on it. Stops escalation. Returns False if it was already acknowledged."""
    now = now or utcnow()
    if is_acknowledged(session, incident):
        return False
    for a in _alerts(session, incident):
        a.acked_at = now
        a.acked_by = user_id
    session.add(Event(incident_id=incident.id, type="acknowledged", at=now, actor_user_id=user_id))
    session.flush()
    return True


def is_acknowledged(session: Session, incident: Incident) -> bool:
    """Acknowledgement belongs to the incident, so it also counts if it came before any email."""
    session.flush()
    return (
        session.scalar(
            select(Event.id).where(Event.incident_id == incident.id, Event.type == "acknowledged")
        )
        is not None
    )


def run_alert_cycle(
    session_factory: Callable[[], Session], mailer: Mailer, settings: Settings
) -> None:
    """The every-minute scheduler job."""
    with session_factory() as session:
        send_due_alerts(session, mailer, settings)
        escalate_unacknowledged(session, mailer, settings)
        session.commit()


def run_digest(session_factory: Callable[[], Session], mailer: Mailer, settings: Settings) -> None:
    with session_factory() as session:
        send_digest(session, mailer, settings)

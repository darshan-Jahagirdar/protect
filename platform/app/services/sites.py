"""Removing a site: when a client leaves, or a site was added by mistake."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.enums import IncidentStatus, SiteStatus
from app.models import Case, EnrollmentCode, Incident, Site
from app.services.incidents import RESOLVED


class SiteRemovalError(Exception):
    """Removal refused. The message is shown to the person who asked."""


def unresolved_cases(session: Session, site: Site) -> int:
    return (
        session.scalar(
            select(func.count())
            .select_from(Case)
            .join(Incident)
            .where(
                Case.site_id == site.id,
                Incident.status != IncidentStatus.CLOSED,
                Case.exposure.not_in(RESOLVED),
            )
        )
        or 0
    )


def remove_site(session: Session, site: Site) -> None:
    """Stop watching a site. Its reports are refused, it can't enroll again, and it drops out
    of matching, the observer and the overview. Its history (reports, cases, events) stays.

    Refused while the site has an unresolved case in an open incident: removing it must never
    hide a problem nobody has dealt with.
    """
    if site.status is SiteStatus.REMOVED:
        raise SiteRemovalError(f"site #{site.id} is already removed")
    open_cases = unresolved_cases(session, site)
    if open_cases:
        raise SiteRemovalError(
            f"site #{site.id} has {open_cases} unresolved case(s) in open incidents; "
            "resolve or decide them on the dashboard first"
        )
    site.status = SiteStatus.REMOVED
    site.public_key = None  # its plugin can no longer sign anything we accept
    for code in session.scalars(
        select(EnrollmentCode).where(
            EnrollmentCode.site_id == site.id, EnrollmentCode.used_at.is_(None)
        )
    ):
        session.delete(code)
    session.flush()

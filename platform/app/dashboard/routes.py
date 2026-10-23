"""Dashboard pages. Server-rendered Jinja (autoescape on) plus HTMX.

There's no login yet (step 8). Until then, pages that show site details or change anything
answer only outside prod, so a production deploy can't expose them by accident.
"""

from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_session
from app.enums import IncidentStatus, SiteStatus
from app.models import Event, Incident, Site
from app.services.alerting import acknowledge, is_acknowledged, summarize

templates = Jinja2Templates(directory=Path(__file__).resolve().parent / "templates")
router = APIRouter()


def dev_only(request: Request) -> None:
    """Placeholder gate until the dashboard login exists (step 8)."""
    if request.app.state.settings.is_prod:
        raise HTTPException(status_code=404)


def same_origin(request: Request) -> None:
    """Basic cross-site request protection for form posts, until CSRF tokens (step 8)."""
    origin = request.headers.get("origin") or request.headers.get("referer")
    if origin is None:
        return
    base = urlsplit(request.app.state.settings.base_url)
    got = urlsplit(origin)
    if (got.scheme, got.netloc) != (base.scheme, base.netloc) and got.netloc != request.url.netloc:
        raise HTTPException(status_code=403)


SessionDep = Annotated[Session, Depends(get_session)]


@router.get("/", response_class=HTMLResponse)
def overview(request: Request, session: SessionDep) -> HTMLResponse:
    active_sites = session.scalar(
        select(func.count()).select_from(Site).where(Site.status == SiteStatus.ACTIVE)
    )
    open_incidents = session.scalar(
        select(func.count()).select_from(Incident).where(Incident.status != IncidentStatus.CLOSED)
    )
    return templates.TemplateResponse(
        request,
        "overview.html",
        {"active_sites": active_sites or 0, "open_incidents": open_incidents or 0},
    )


def _incident_or_404(session: Session, incident_id: str) -> Incident:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404)
    return incident


@router.get(
    "/incidents/{incident_id}", response_class=HTMLResponse, dependencies=[Depends(dev_only)]
)
def incident_page(request: Request, incident_id: str, session: SessionDep) -> HTMLResponse:
    incident = _incident_or_404(session, incident_id)
    events = session.scalars(
        select(Event).where(Event.incident_id == incident.id).order_by(Event.id)
    ).all()
    return templates.TemplateResponse(
        request,
        "incident.html",
        {
            "incident": incident,
            "summary": summarize(session, incident),
            "acknowledged": is_acknowledged(session, incident),
            "cases": sorted(incident.cases, key=lambda c: (-c.score, c.site_id)),
            "events": events,
        },
    )


@router.post("/incidents/{incident_id}/ack", dependencies=[Depends(dev_only), Depends(same_origin)])
def incident_ack(incident_id: str, session: SessionDep) -> RedirectResponse:
    incident = _incident_or_404(session, incident_id)
    acknowledge(session, incident, user_id=None)  # user comes with the login in step 8
    session.commit()
    return RedirectResponse(f"/incidents/{incident.id}", status_code=303)

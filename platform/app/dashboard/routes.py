"""Dashboard pages. Server-rendered Jinja (autoescape on) plus HTMX. No auth yet: dev only."""

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_session
from app.enums import IncidentStatus, SiteStatus
from app.models import Incident, Site

templates = Jinja2Templates(directory=Path(__file__).resolve().parent / "templates")
router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def overview(request: Request, session: Annotated[Session, Depends(get_session)]) -> HTMLResponse:
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

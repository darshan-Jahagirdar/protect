"""Dashboard pages (DESIGN.md §4.13). Server-rendered Jinja with autoescape on, plain forms.

Every page needs a signed-in team member. Every form post carries a CSRF token and must come
from our own site. Roles: viewer (read), responder (act on incidents), admin (sites, users).
"""

from datetime import timedelta
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.dashboard.auth import (
    AdminDep,
    ResponderDep,
    ViewerDep,
    check_csrf,
    clear_session_cookie,
    safe_next,
    set_session_cookie,
)
from app.db import get_session, utcnow
from app.enums import (
    Compromise,
    Exposure,
    HostType,
    IncidentStatus,
    Priority,
    ReviewStatus,
    SiteStatus,
    UserRole,
)
from app.models import Advisory, AuditLog, Case, Event, Incident, Report, Site, User
from app.services import cases as case_actions
from app.services.advisories import fixture_names, load_fixture, upsert_advisory
from app.services.alerting import acknowledge, is_acknowledged, summarize
from app.services.enrollment import create_site, issue_code
from app.services.findings import latest_findings
from app.services.incidents import apply_advisory, fix_not_visible, rematch_site
from app.services.observations import (
    disagreement,
    latest_observation,
    observe_site,
    public_php_version,
    tls_warning,
)

templates = Jinja2Templates(directory=Path(__file__).resolve().parent / "templates")
router = APIRouter()

SessionDep = Annotated[Session, Depends(get_session)]
CSRF = [Depends(check_csrf)]
STALE_AFTER = timedelta(hours=3)
RISK_TAGS = ("ecommerce", "personal_data")
MESSAGES = {  # fixed texts only: nothing user-supplied is reflected from the URL
    "acknowledged": "Acknowledged. Escalation is stopped.",
    "saved": "Saved.",
    "replayed": "Advisory replayed and matched against every active site.",
    "replayed_none": "Advisory replayed: no active site is affected.",
    "user_added": "Team member added.",
    "user_disabled": "Team member disabled.",
    "closed": "Incident closed.",
    "observed": "Public homepage viewed.",
}


def page(request: Request, name: str, ctx: dict[str, Any], status: int = 200) -> HTMLResponse:
    viewer = getattr(request.state, "viewer", None)
    msg = MESSAGES.get(request.query_params.get("msg", ""))
    return templates.TemplateResponse(
        request, name, {"viewer": viewer, "message": msg, **ctx}, status_code=status
    )


def _audit(
    session: Session, user: User | None, action: str, target: str | None = None, **data: object
) -> None:
    session.add(
        AuditLog(actor_user_id=user.id if user else None, action=action, target=target, data=data)
    )


def _get(session: Session, model: type, key: object) -> Any:
    obj = session.get(model, key)
    if obj is None:
        raise HTTPException(status_code=404)
    return obj


def _dev_only(request: Request) -> None:
    if request.app.state.settings.is_prod:
        raise HTTPException(status_code=404)  # prod signs in through Cloudflare Access (P4)


# --- Sign in / out ------------------------------------------------------------------------


@router.get("/login", response_class=HTMLResponse, dependencies=[Depends(_dev_only)])
def login_page(request: Request, session: SessionDep, next: str = "/") -> HTMLResponse:
    users = session.scalars(
        select(User).where(User.disabled_at.is_(None)).order_by(User.display_name)
    ).all()
    return page(request, "login.html", {"users": users, "next": safe_next(next)})


@router.post("/login", dependencies=[Depends(_dev_only)])
def login(
    request: Request,
    session: SessionDep,
    user_id: Annotated[int, Form()],
    next: Annotated[str, Form()] = "/",
) -> Response:
    origin = request.headers.get("origin")
    if origin is not None and origin.split("://", 1)[-1] != request.url.netloc:
        raise HTTPException(status_code=403)
    user = session.get(User, user_id)
    if user is None or user.disabled_at is not None:
        raise HTTPException(status_code=403)
    _audit(session, user, "login", method="dev")
    session.commit()
    response = RedirectResponse(safe_next(next), status_code=303)
    set_session_cookie(response, request.app.state.settings, user.id)
    return response


@router.post("/logout", dependencies=CSRF)
def logout(viewer: ViewerDep, session: SessionDep) -> Response:
    _audit(session, viewer.user, "logout")
    session.commit()
    response = RedirectResponse("/login", status_code=303)
    clear_session_cookie(response)
    return response


# --- Overview ---------------------------------------------------------------------------------


def _stale(site: Site) -> bool:
    return site.last_report_at is None or utcnow() - site.last_report_at > STALE_AFTER


@router.get("/", response_class=HTMLResponse)
def overview(request: Request, viewer: ViewerDep, session: SessionDep) -> HTMLResponse:
    incidents = session.scalars(
        select(Incident)
        .where(Incident.status != IncidentStatus.CLOSED)
        .order_by(Incident.priority, Incident.created_at.desc())
    ).all()
    rows = [(i, summarize(session, i), is_acknowledged(session, i)) for i in incidents]
    active = session.scalars(select(Site).where(Site.status == SiteStatus.ACTIVE)).all()
    return page(
        request,
        "overview.html",
        {
            "rows": rows,
            "unacked_urgent": sum(
                1
                for i, s, acked in rows
                if i.priority in (Priority.P1, Priority.P2) and not acked and s.affected
            ),
            "active_sites": len(active),
            "stale": [s for s in active if _stale(s)],
            "suspicious": [s for s in active if s.suspicious],
            "fixes_not_visible": sum(
                1
                for c in session.scalars(select(Case).where(Case.exposure == Exposure.FIX_CLAIMED))
                if fix_not_visible(session, c)
            ),
            "warning_sites": [
                s for s in active if any(f.is_warning for f in latest_findings(session, s))
            ],
            "disagree_sites": [
                s for s in active if disagreement(session, s, latest_observation(session, s))
            ],
            "needs_review": session.scalar(
                select(func.count())
                .select_from(Advisory)
                .where(Advisory.review_status == ReviewStatus.NEEDS_REVIEW)
            )
            or 0,
        },
    )


# --- Sites ------------------------------------------------------------------------------------


def _sites_context(session: Session) -> dict[str, Any]:
    sites = session.scalars(select(Site).order_by(Site.business_name)).all()
    open_cases = dict(
        session.execute(
            select(Case.site_id, func.count())
            .join(Incident)
            .where(
                Incident.status != IncidentStatus.CLOSED,
                Case.exposure.in_(
                    [Exposure.VULNERABLE, Exposure.NEEDS_CHECK, Exposure.FIX_CLAIMED]
                ),
            )
            .group_by(Case.site_id)
        ).all()
    )
    return {
        "sites": sites,
        "open_cases": open_cases,
        "host_types": list(HostType),
        "stale": {s.id for s in sites if _stale(s)},
    }


@router.get("/sites", response_class=HTMLResponse)
def sites_page(request: Request, viewer: ViewerDep, session: SessionDep) -> HTMLResponse:
    return page(request, "sites.html", _sites_context(session))


@router.post("/sites", response_class=HTMLResponse, dependencies=CSRF)
def add_site(
    request: Request,
    viewer: AdminDep,
    session: SessionDep,
    business_name: Annotated[str, Form(max_length=200)],
    url: Annotated[str, Form(max_length=500)],
    host_type: Annotated[HostType, Form()],
) -> HTMLResponse:
    error = None
    try:
        site = create_site(session, business_name, url, host_type)
    except ValueError:
        error = "That doesn't look like an http(s) URL."
    except IntegrityError:
        error = "A site with that URL already exists."
    if error:
        session.rollback()
        return page(request, "sites.html", {**_sites_context(session), "error": error}, 400)
    code = issue_code(session, site, request.app.state.settings.enrollment_code_ttl_hours)
    _audit(session, viewer.user, "site_added", str(site.id))
    session.commit()
    return site_view(request, viewer, session, site, new_code=code)


def site_view(
    request: Request, viewer: ViewerDep, session: Session, site: Site, new_code: str | None = None
) -> HTMLResponse:
    report = session.get(Report, site.last_report_id) if site.last_report_id else None
    site_cases = session.scalars(
        select(Case).where(Case.site_id == site.id).order_by(Case.created_at.desc())
    ).all()
    return page(
        request,
        "site.html",
        {
            "site": site,
            "report": report,
            "cases": site_cases,
            "new_code": new_code,
            "stale": _stale(site),
            "host_types": list(HostType),
            "risk_tags": RISK_TAGS,
            "components": sorted(site.components, key=lambda c: c.component_key),
            "code_hours": request.app.state.settings.enrollment_code_ttl_hours,
            "findings": latest_findings(session, site),
            "observation": (obs := latest_observation(session, site)),
            "disagrees": disagreement(session, site, obs),
            "tls_warning": tls_warning(obs),
            "public_php": public_php_version(obs),
        },
    )


@router.get("/sites/{site_id}", response_class=HTMLResponse)
def site_page(request: Request, site_id: int, viewer: ViewerDep, session: SessionDep):
    return site_view(request, viewer, session, _get(session, Site, site_id))


@router.post("/sites/{site_id}/code", response_class=HTMLResponse, dependencies=CSRF)
def site_new_code(request: Request, site_id: int, viewer: AdminDep, session: SessionDep):
    site = _get(session, Site, site_id)
    if site.status is SiteStatus.REMOVED:
        raise HTTPException(status_code=400)
    code = issue_code(session, site, request.app.state.settings.enrollment_code_ttl_hours)
    _audit(session, viewer.user, "enrollment_code_issued", str(site.id))
    session.commit()
    return site_view(request, viewer, session, site, new_code=code)


@router.post("/sites/{site_id}/settings", dependencies=CSRF)
async def site_settings(request: Request, site_id: int, viewer: AdminDep, session: SessionDep):
    site = _get(session, Site, site_id)
    form = await request.form()
    try:
        site.host_type = HostType(str(form.get("host_type", "unknown")))
    except ValueError as e:
        raise HTTPException(status_code=400) from e
    site.host_name = (str(form.get("host_name") or "").strip()[:100]) or None
    site.server_group = (str(form.get("server_group") or "").strip()[:100]) or None
    site.risk_tags = [t for t in RISK_TAGS if form.get(f"risk_{t}") == "on"]
    _audit(
        session,
        viewer.user,
        "site_settings",
        str(site.id),
        host_type=site.host_type.value,
        risk_tags=site.risk_tags,
    )
    session.flush()
    rematch_site(session, site)  # risk tags change scores
    session.commit()
    return RedirectResponse(f"/sites/{site.id}?msg=saved", status_code=303)


@router.post("/sites/{site_id}/allow-mu", dependencies=CSRF)
def site_allow_mu(
    site_id: int, viewer: AdminDep, session: SessionDep, path: Annotated[str, Form(max_length=400)]
) -> Response:
    site = _get(session, Site, site_id)
    if path not in site.mu_plugin_allowlist:
        site.mu_plugin_allowlist = [*site.mu_plugin_allowlist, path]
        _audit(session, viewer.user, "mu_plugin_allowed", str(site.id), path=path)
        session.commit()
    return RedirectResponse(f"/sites/{site.id}?msg=saved#file-checks", status_code=303)


@router.post("/sites/{site_id}/observe", dependencies=CSRF)
def site_observe(
    request: Request, site_id: int, viewer: ResponderDep, session: SessionDep
) -> Response:
    """View the site's public homepage now (one GET /, headers only)."""
    site = _get(session, Site, site_id)
    observe_site(session, site, request.app.state.settings, observe_fn=request.app.state.observe)
    _audit(session, viewer.user, "observed", str(site.id))
    session.commit()
    return RedirectResponse(f"/sites/{site.id}?msg=observed#public-view", status_code=303)


# --- Incidents ------------------------------------------------------------------------------


@router.get("/incidents", response_class=HTMLResponse)
def incidents_page(request: Request, viewer: ViewerDep, session: SessionDep) -> HTMLResponse:
    incidents = session.scalars(select(Incident).order_by(Incident.created_at.desc())).all()
    rows = [(i, summarize(session, i), is_acknowledged(session, i)) for i in incidents]
    return page(request, "incidents.html", {"rows": rows})


@router.get("/incidents/{incident_id}", response_class=HTMLResponse)
def incident_page(request: Request, incident_id: str, viewer: ViewerDep, session: SessionDep):
    return incident_view(request, session, _get(session, Incident, incident_id))


def incident_view(
    request: Request, session: Session, incident: Incident, error: str | None = None
) -> HTMLResponse:
    events = session.scalars(
        select(Event).where(Event.incident_id == incident.id).order_by(Event.id)
    ).all()
    return page(
        request,
        "incident.html",
        {
            "incident": incident,
            "summary": summarize(session, incident),
            "acknowledged": is_acknowledged(session, incident),
            "cases": sorted(incident.cases, key=lambda c: (-c.score, c.site_id)),
            "events": events,
            "users": {u.id: u.display_name for u in session.scalars(select(User))},
            "notices_missing": case_actions.notices_missing(incident),
            "error": error,
        },
        status=400 if error else 200,
    )


@router.post("/incidents/{incident_id}/close", response_class=HTMLResponse, dependencies=CSRF)
async def incident_close(
    request: Request, incident_id: str, viewer: ResponderDep, session: SessionDep
):
    incident = _get(session, Incident, incident_id)
    form = await request.form()
    try:
        case_actions.close_incident(session, incident, viewer.user, str(form.get("note", "")))
    except case_actions.CaseActionError as e:
        session.rollback()
        return incident_view(request, session, _get(session, Incident, incident_id), error=str(e))
    session.commit()
    return RedirectResponse(f"/incidents/{incident.id}?msg=closed", status_code=303)


@router.post("/incidents/{incident_id}/ack", dependencies=CSRF)
def incident_ack(incident_id: str, viewer: ResponderDep, session: SessionDep) -> Response:
    incident = _get(session, Incident, incident_id)
    acknowledge(session, incident, user_id=viewer.user.id)
    session.commit()
    return RedirectResponse(f"/incidents/{incident.id}?msg=acknowledged", status_code=303)


# --- Cases ---------------------------------------------------------------------------------


def case_view(request: Request, session: Session, case: Case, error: str | None = None):
    template, rows = case_actions.checklist(session, case)
    events = session.scalars(select(Event).where(Event.case_id == case.id).order_by(Event.id)).all()
    return page(
        request,
        "case.html",
        {
            "case": case,
            "site": session.get(Site, case.site_id),
            "incident": case.incident,
            "template": template,
            "checklist": rows,
            "events": events,
            "error": error,
            "users": {u.id: u.display_name for u in session.scalars(select(User))},
            "decisions": [Exposure.FALSE_POSITIVE, Exposure.ACCEPTED_RISK, Exposure.NOT_AFFECTED],
            "fix_not_visible": fix_not_visible(session, case),
            "warnings": [f for f in latest_findings(session, case.site) if f.is_warning],
            "disagrees": disagreement(session, case.site, latest_observation(session, case.site)),
            "compromise_values": list(Compromise),
        },
        status=400 if error else 200,
    )


@router.get("/cases/{case_id}", response_class=HTMLResponse)
def case_page(request: Request, case_id: int, viewer: ViewerDep, session: SessionDep):
    return case_view(request, session, _get(session, Case, case_id))


@router.post("/cases/{case_id}/action", response_class=HTMLResponse, dependencies=CSRF)
async def case_action(request: Request, case_id: int, viewer: ResponderDep, session: SessionDep):
    case = _get(session, Case, case_id)
    form = await request.form()
    action, note = str(form.get("action", "")), str(form.get("note", ""))
    user = viewer.user
    try:
        if action == "claim_fix":
            case_actions.claim_fix(session, case, user, note)
        elif action == "verify":
            case_actions.verify_manually(session, case, user, note)
        elif action in {d.value for d in case_actions.DECISIONS}:
            case_actions.decide(session, case, user, Exposure(action), note)
        elif action == "undo":
            case_actions.undo_decision(session, case, user)
        elif action in ("shield_on", "shield_off"):
            case_actions.set_shield(session, case, user, action == "shield_on", note)
        elif action == "compromise":
            case_actions.set_compromise(
                session, case, user, Compromise(str(form.get("value", "none"))), note
            )
        else:
            raise HTTPException(status_code=400)
    except (case_actions.CaseActionError, ValueError) as e:
        session.rollback()
        msg = str(e) if isinstance(e, case_actions.CaseActionError) else "Unknown value."
        return case_view(request, session, _get(session, Case, case_id), error=msg)
    session.commit()
    return RedirectResponse(f"/cases/{case.id}?msg=saved", status_code=303)


@router.post("/cases/{case_id}/checklist", response_class=HTMLResponse, dependencies=CSRF)
async def case_checklist(request: Request, case_id: int, viewer: ResponderDep, session: SessionDep):
    case = _get(session, Case, case_id)
    form = await request.form()
    try:
        case_actions.tick(
            session,
            case,
            viewer.user,
            str(form.get("item_key", "")),
            form.get("done") == "1",
            str(form.get("note", "")),
        )
    except case_actions.CaseActionError as e:
        session.rollback()
        return case_view(request, session, case, error=str(e))
    session.commit()
    return RedirectResponse(f"/cases/{case.id}#checklist", status_code=303)


# --- Advisories --------------------------------------------------------------------------------


@router.get("/advisories", response_class=HTMLResponse)
def advisories_page(request: Request, viewer: ViewerDep, session: SessionDep) -> HTMLResponse:
    advisories = session.scalars(select(Advisory).order_by(Advisory.created_at.desc())).all()
    return page(request, "advisories.html", {"advisories": advisories, "fixtures": fixture_names()})


@router.post("/advisories/replay", dependencies=CSRF)
def advisory_replay(
    viewer: ResponderDep, session: SessionDep, name: Annotated[str, Form()]
) -> Response:
    if name not in fixture_names():
        raise HTTPException(status_code=400)
    advisory = upsert_advisory(session, load_fixture(name))
    incident = apply_advisory(session, advisory)
    _audit(session, viewer.user, "advisory_replayed", name)
    session.commit()
    if incident is None:
        return RedirectResponse("/advisories?msg=replayed_none", status_code=303)
    return RedirectResponse(f"/incidents/{incident.id}?msg=replayed", status_code=303)


# --- Team members ------------------------------------------------------------------------------


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request, viewer: AdminDep, session: SessionDep) -> HTMLResponse:
    users = session.scalars(select(User).order_by(User.display_name)).all()
    return page(request, "users.html", {"users": users, "roles": list(UserRole)})


@router.post("/users", dependencies=CSRF)
def add_user(
    viewer: AdminDep,
    session: SessionDep,
    email: Annotated[str, Form(max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")],
    display_name: Annotated[str, Form(min_length=1, max_length=100)],
    role: Annotated[UserRole, Form()],
) -> Response:
    user = User(email=email.strip().lower(), display_name=display_name.strip(), role=role)
    session.add(user)
    try:
        session.flush()
    except IntegrityError as e:
        session.rollback()
        raise HTTPException(status_code=400) from e
    _audit(session, viewer.user, "user_added", user.email, role=role.value)
    session.commit()
    return RedirectResponse("/users?msg=user_added", status_code=303)


@router.post("/users/{user_id}/disable", dependencies=CSRF)
def disable_user(user_id: int, viewer: AdminDep, session: SessionDep) -> Response:
    user = _get(session, User, user_id)
    if user.id == viewer.user.id:
        raise HTTPException(status_code=400)  # don't lock yourself out
    user.disabled_at = utcnow()
    _audit(session, viewer.user, "user_disabled", user.email)
    session.commit()
    return RedirectResponse("/users?msg=user_disabled", status_code=303)

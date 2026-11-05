"""Dashboard pages (DESIGN.md §4.13). Server-rendered Jinja with autoescape on, plain forms.

Every page needs a signed-in team member. Every form post carries a CSRF token and must come
from our own site. Roles: viewer (read), responder (act on incidents), admin (sites, users).
"""

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.ai import service as ai_service
from app.ai.providers import AIError
from app.dashboard.auth import (
    AdminDep,
    ResponderDep,
    ViewerDep,
    check_csrf,
    clear_session_cookie,
    safe_next,
    secret_bytes,
    set_session_cookie,
)
from app.dashboard.credentials import (
    PASSWORD_MAX,
    check_totp,
    decrypt_secret,
    encrypt_secret,
    hash_password,
    is_locked,
    new_totp_secret,
    otpauth_uri,
    password_problem,
    qr_data_uri,
    record_failure,
    setup_link,
    setup_token_matches,
    start_setup,
    token_hash,
    verify_password,
)
from app.db import get_session, utcnow
from app.enums import (
    Compromise,
    Exposure,
    HostType,
    IncidentStatus,
    Priority,
    RefusedReason,
    ReviewStatus,
    SiteStatus,
    UserRole,
)
from app.feeds.status import feed_health
from app.models import (
    Advisory,
    AuditLog,
    Case,
    Event,
    FeedRun,
    FeedState,
    Incident,
    IncidentAdvisory,
    Report,
    Site,
    User,
)
from app.services import cases as case_actions
from app.services.advisories import (
    RANGE_HELP,
    ReviewError,
    confirm_advisory,
    fixture_names,
    load_fixture,
    ranges_to_text,
    reject_advisory,
    set_exploited,
    upsert_advisory,
)
from app.services.alerting import acknowledge, is_acknowledged, summarize
from app.services.enrollment import create_site, issue_code
from app.services.findings import latest_findings
from app.services.incidents import apply_advisory, fix_not_visible, possible_sites, rematch_site
from app.services.observations import (
    disagreement,
    latest_observation,
    observe_site,
    public_php_version,
    public_view_outdated,
    tls_warning,
)
from app.settings import is_local_host

templates = Jinja2Templates(directory=Path(__file__).resolve().parent / "templates")


def _ago(when: datetime | None) -> str:
    """'12 min ago', '5 h ago', '3 days ago' (UTC times from the database)."""
    if when is None:
        return "never"
    seconds = max(0, int((utcnow() - when).total_seconds()))
    if seconds < 90:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    if seconds < 48 * 3600:
        return f"{seconds // 3600} h ago"
    return f"{seconds // 86400} days ago"


templates.env.filters["ago"] = _ago
# Changes whenever style.css changes, so browsers fetch the new file after a deploy.
templates.env.globals["css_version"] = hashlib.sha256(
    (Path(__file__).resolve().parent / "static" / "style.css").read_bytes()
).hexdigest()[:10]
router = APIRouter()

SessionDep = Annotated[Session, Depends(get_session)]
CSRF = [Depends(check_csrf)]
STALE_AFTER = timedelta(hours=3)
REFUSED_SHOWN_FOR = timedelta(hours=24)
REFUSED_TEXT = {  # why a correctly signed report was refused (Site.refused_reason)
    RefusedReason.SITE_URL_MISMATCH: (
        "it was signed with this site's key but came from a different address. A copy of the "
        "site (such as a staging site) is probably reporting. Its data was not used. Remove the "
        "plugin from the copy; if the live site's address changed, add the site again with its "
        "new address."
    ),
    RefusedReason.FORMAT: (
        "it didn't pass the format checks, so it was not used. The server log says which field. "
        "Until it's fixed the site will show as not reporting."
    ),
    RefusedReason.CLI: (
        "it was sent from command-line PHP, whose versions can differ from the website's."
    ),
}
RISK_TAGS = ("ecommerce", "personal_data")
MESSAGES = {  # fixed texts only: nothing user-supplied is reflected from the URL
    "acknowledged": "Acknowledged. Escalation is stopped.",
    "saved": "Saved.",
    "replayed": "Advisory replayed and matched against every active site.",
    "replayed_none": "Advisory replayed: no active site is affected.",
    "user_added": "Team member added.",
    "signed_up": (
        "You're set up. Next time, sign in with your email, password and the code from your app."
    ),
    "user_disabled": "Team member disabled.",
    "closed": "Incident closed.",
    "observed": "Public homepage viewed.",
    "ai_done": "AI summary ready. Check it before relying on it.",
    "reviewed": "Advisory confirmed and matched against every active site.",
    "reviewed_none": "Advisory confirmed: no active site is affected.",
    "rejected": "Advisory rejected. It won't open anything.",
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


def _dev_allowed(request: Request) -> bool:
    """The password-free demo sign-in: never in prod, and only when the browser talks to this
    machine directly. A request through a public address (a server left in dev mode) gets
    nothing."""
    settings = request.app.state.settings
    if settings.is_prod:
        return False
    host = request.url.hostname or ""
    return is_local_host(host) or (settings.env == "test" and host == "testserver")


def _dev_only(request: Request) -> None:
    if not _dev_allowed(request):
        raise HTTPException(status_code=404)


def _same_origin(request: Request) -> None:
    """Sign-in forms have no session yet, so no CSRF token: refuse posts from other sites."""
    origin = request.headers.get("origin")
    if origin is not None and origin.split("://", 1)[-1] != request.url.netloc:
        raise HTTPException(status_code=403)


def _attempt_allowed(request: Request) -> None:
    """At most a few sign-in and setup attempts per address, on top of the per-account pause."""
    ip = request.client.host if request.client else "unknown"
    if not request.app.state.login_limiter.allow(ip):
        raise HTTPException(status_code=429)


# --- Sign in / out ------------------------------------------------------------------------

SIGN_IN_FAILED = (
    "That didn't work. Check your email, password and the current code from your app. "
    "After 5 wrong tries the account pauses for 15 minutes."
)


def _login_page(
    request: Request, session: Session, next: str, error: str | None = None, email: str = ""
) -> HTMLResponse:
    dev = _dev_allowed(request)
    users = (
        session.scalars(
            select(User).where(User.disabled_at.is_(None)).order_by(User.display_name)
        ).all()
        if dev
        else []
    )
    ctx = {"dev": dev, "users": users, "next": safe_next(next), "error": error, "email": email}
    return page(request, "login.html", ctx, status=400 if error else 200)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, session: SessionDep, next: str = "/") -> HTMLResponse:
    return _login_page(request, session, next)


@router.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    session: SessionDep,
    email: Annotated[str, Form(max_length=320)],
    password: Annotated[str, Form(max_length=PASSWORD_MAX)],
    code: Annotated[str, Form(max_length=12)],
    next: Annotated[str, Form(max_length=500)] = "/",
) -> Response:
    _same_origin(request)
    _attempt_allowed(request)
    settings = request.app.state.settings
    user = session.scalar(select(User).where(User.email == email.strip().lower()))
    # Always run the password check (even for an unknown email) so timing reveals nothing.
    password_ok = verify_password(user.password_hash if user else None, password)
    if user is None or user.disabled_at is not None or is_locked(user):
        return _login_page(request, session, next, SIGN_IN_FAILED, email)
    secret = decrypt_secret(secret_bytes(settings), user.totp_secret_enc)
    step = check_totp(secret, code, user.totp_last_step) if password_ok and secret else None
    if step is None or user.password_hash is None:
        record_failure(user)
        _audit(session, user, "login_failed")
        session.commit()
        return _login_page(request, session, next, SIGN_IN_FAILED, email)
    user.failed_logins = 0
    user.locked_until = None
    user.totp_last_step = step
    _audit(session, user, "login", method="password")
    session.commit()
    response = RedirectResponse(safe_next(next), status_code=303)
    set_session_cookie(response, settings, user)
    return response


@router.post("/login/dev", dependencies=[Depends(_dev_only)])
def login_dev(
    request: Request,
    session: SessionDep,
    user_id: Annotated[int, Form()],
    next: Annotated[str, Form()] = "/",
) -> Response:
    _same_origin(request)
    user = session.get(User, user_id)
    if user is None or user.disabled_at is not None:
        raise HTTPException(status_code=403)
    _audit(session, user, "login", method="dev")
    session.commit()
    response = RedirectResponse(safe_next(next), status_code=303)
    set_session_cookie(response, request.app.state.settings, user)
    return response


# --- First-time setup (password + authenticator) -------------------------------------------


def _setup_user(session: Session, token: str) -> User | None:
    if not token or len(token) > 100:
        return None
    user = session.scalar(select(User).where(User.setup_token_hash == token_hash(token)))
    if user is None or user.disabled_at is not None or not setup_token_matches(user, token):
        return None
    return user


def _setup_page(
    request: Request, user: User | None, secret: str | None = None, error: str | None = None
) -> HTMLResponse:
    if user is None or secret is None:
        response = page(request, "setup.html", {"invalid": True}, status=404)
    else:
        ctx = {
            "invalid": False,
            "user": user,
            "qr": qr_data_uri(otpauth_uri(secret, user.email)),
            "secret": " ".join(secret[i : i + 4] for i in range(0, len(secret), 4)),
            "error": error,
        }
        response = page(request, "setup.html", ctx, status=400 if error else 200)
    response.headers["Cache-Control"] = "no-store"  # the page shows the authenticator secret
    return response


@router.get("/setup/{token}", response_class=HTMLResponse)
def setup_page(request: Request, token: str, session: SessionDep) -> HTMLResponse:
    user = _setup_user(session, token)
    if user is None:
        return _setup_page(request, None)
    key = secret_bytes(request.app.state.settings)
    secret = decrypt_secret(key, user.totp_secret_enc)
    if secret is None:  # first visit; later visits reuse it so a scanned code keeps working
        secret = new_totp_secret()
        user.totp_secret_enc = encrypt_secret(key, secret)
        session.commit()
    return _setup_page(request, user, secret)


@router.post("/setup/{token}", response_class=HTMLResponse)
def setup(
    request: Request,
    token: str,
    session: SessionDep,
    password: Annotated[str, Form(max_length=PASSWORD_MAX + 1)],
    confirm: Annotated[str, Form(max_length=PASSWORD_MAX + 1)],
    code: Annotated[str, Form(max_length=12)],
) -> Response:
    _same_origin(request)
    _attempt_allowed(request)
    settings = request.app.state.settings
    user = _setup_user(session, token)
    secret = decrypt_secret(secret_bytes(settings), user.totp_secret_enc) if user else None
    if user is None or secret is None:
        return _setup_page(request, None)
    problem = password_problem(password, confirm, user.email)
    if problem:
        return _setup_page(request, user, secret, problem)
    step = check_totp(secret, code, None)
    if step is None:
        return _setup_page(
            request,
            user,
            secret,
            "That code didn't match. Use the newest code in the app, and check the phone's "
            "time is set automatically.",
        )
    user.password_hash = hash_password(password)
    user.totp_last_step = step
    user.setup_token_hash = None
    user.setup_expires_at = None
    user.failed_logins = 0
    user.locked_until = None
    _audit(session, user, "sign_in_set_up")
    session.commit()
    response = RedirectResponse("/?msg=signed_up", status_code=303)
    set_session_cookie(response, settings, user)
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


@dataclass(frozen=True)
class SiteHealth:
    """One card on the overview's site grid: a colour (ok / warn / bad / idle) and why."""

    site: Site
    state: str
    label: str
    href: str


def _silent_for(site: Site) -> str:
    if site.last_report_at is None:
        return "No report yet"
    hours = int((utcnow() - site.last_report_at).total_seconds() // 3600)
    return f"Silent for {hours}h" if hours < 48 else f"Silent for {hours // 24} days"


def _site_health(
    session: Session, sites: list[Site], warning: set[int], disagree: set[int]
) -> list[SiteHealth]:
    """Worst thing first: an open fix, then warning signs, then silence or odd reports."""
    open_cases: dict[int, list[tuple[Exposure, Priority, bool]]] = {}
    for site_id, exposure, priority, drill in session.execute(
        select(Case.site_id, Case.exposure, Incident.priority, Incident.drill)
        .join(Incident)
        .where(
            Incident.status != IncidentStatus.CLOSED,
            Case.exposure.in_([Exposure.VULNERABLE, Exposure.NEEDS_CHECK, Exposure.FIX_CLAIMED]),
        )
    ):
        open_cases.setdefault(site_id, []).append((exposure, priority, drill))

    health = []
    for site in sites:
        href = f"/sites/{site.id}"
        cases = open_cases.get(site.id, [])
        real = [c for c in cases if not c[2]]
        if site.status == SiteStatus.PENDING:
            item = SiteHealth(site, "idle", "Not connected yet", href)
        elif any(e == Exposure.VULNERABLE and p in (Priority.P1, Priority.P2) for e, p, _ in real):
            item = SiteHealth(site, "bad", "Needs a fix now", href)
        elif site.id in warning:
            item = SiteHealth(site, "bad", "Warning signs in files", href + "#file-checks")
        elif site.id in disagree:
            item = SiteHealth(site, "bad", "Report and public view disagree", href + "#public-view")
        elif _stale(site):
            item = SiteHealth(site, "warn", _silent_for(site), href)
        elif site.suspicious:
            item = SiteHealth(site, "warn", "Sent an odd report", href)
        elif real:
            fixing = all(e == Exposure.FIX_CLAIMED for e, _, _ in real)
            item = SiteHealth(site, "warn", "Fix being checked" if fixing else "Needs a fix", href)
        elif cases:
            item = SiteHealth(site, "warn", "[DRILL] Practice fix open", href)
        else:
            item = SiteHealth(site, "ok", "All good", href)
        health.append(item)
    order = {"bad": 0, "warn": 1, "idle": 2, "ok": 3}
    return sorted(health, key=lambda h: (order[h.state], h.site.business_name.lower()))


@router.get("/", response_class=HTMLResponse)
def overview(request: Request, viewer: ViewerDep, session: SessionDep) -> HTMLResponse:
    incidents = session.scalars(
        select(Incident)
        .where(Incident.status != IncidentStatus.CLOSED)
        .order_by(Incident.priority, Incident.created_at.desc())
    ).all()
    rows = [(i, summarize(session, i), is_acknowledged(session, i)) for i in incidents]
    sites = session.scalars(
        select(Site).where(Site.status != SiteStatus.REMOVED).order_by(Site.business_name)
    ).all()
    active = [s for s in sites if s.status == SiteStatus.ACTIVE]
    stale = [s for s in active if _stale(s)]
    warning_sites = [s for s in active if any(f.is_warning for f in latest_findings(session, s))]
    disagree_sites = [s for s in active if disagreement(session, s, latest_observation(session, s))]
    urgent = [
        (i, s)
        for i, s, acked in rows
        if i.priority in (Priority.P1, Priority.P2) and not acked and s.affected
    ]
    reports = [s.last_report_at for s in active if s.last_report_at]
    queue = [
        (a, possible_sites(session, a))
        for a in session.scalars(
            select(Advisory).where(Advisory.review_status == ReviewStatus.NEEDS_REVIEW)
        )
    ]
    return page(
        request,
        "overview.html",
        {
            "rows": rows,
            "urgent": urgent,
            "unacked_urgent": len(urgent),
            "sites": sites,
            "active_sites": len(active),
            "reporting": len(active) - len(stale),
            "last_report": max(reports) if reports else None,
            "health": _site_health(
                session, sites, {s.id for s in warning_sites}, {s.id for s in disagree_sites}
            ),
            "stale": stale,
            "suspicious": [s for s in active if s.suspicious],
            "fixes_not_visible": sum(
                1
                for c in session.scalars(select(Case).where(Case.exposure == Exposure.FIX_CLAIMED))
                if fix_not_visible(session, c)
            ),
            "warning_sites": warning_sites,
            "disagree_sites": disagree_sites,
            "needs_review": len(queue),
            "review_matches": [(a, n) for a, n in queue if n],
            "feed_problems": [
                h for h in feed_health(session, request.app.state.settings) if h.needs_attention
            ],
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


def _refused_text(site: Site) -> str | None:
    """The refusal note, while it's recent or newer than the last accepted report."""
    if site.refused_at is None or site.refused_reason not in REFUSED_TEXT:
        return None
    newer = site.last_report_at is None or site.refused_at > site.last_report_at
    if not newer and utcnow() - site.refused_at > REFUSED_SHOWN_FOR:
        return None
    return REFUSED_TEXT[RefusedReason(site.refused_reason)]


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
            "refused": _refused_text(site),
            "host_types": list(HostType),
            "risk_tags": RISK_TAGS,
            "components": sorted(site.components, key=lambda c: c.component_key),
            "code_hours": request.app.state.settings.enrollment_code_ttl_hours,
            "findings": latest_findings(session, site),
            "observation": (obs := latest_observation(session, site)),
            "disagrees": disagreement(session, site, obs),
            "public_outdated": public_view_outdated(session, site, obs),
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
    if site.status is SiteStatus.REMOVED:  # no longer ours to look at
        raise HTTPException(status_code=400)
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
            "ai_summary": ai_service.latest_summary(session, incident),
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
            "draft": (draft := ai_service.draft_for(session, case)),
            "draft_warnings": ai_service.draft_warnings(draft, case.incident.drill)
            if draft
            else [],
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


# --- AI: incident summary and client drafts ---------------------------------------------------


def _provider(request: Request):  # type: ignore[no-untyped-def]
    return request.app.state.ai_provider_factory(request.app.state.settings)


@router.post("/incidents/{incident_id}/ai-summary", response_class=HTMLResponse, dependencies=CSRF)
async def incident_ai_summary(
    request: Request, incident_id: str, viewer: ResponderDep, session: SessionDep
):
    incident = _get(session, Incident, incident_id)
    form = await request.form()
    settings = request.app.state.settings
    try:
        ai_service.incident_summary(
            session,
            incident,
            _provider(request),
            settings.ai_summary_thinking,
            force=form.get("force") == "1",
        )
    except AIError as e:
        session.rollback()
        return incident_view(request, session, _get(session, Incident, incident_id), error=str(e))
    session.commit()
    return RedirectResponse(f"/incidents/{incident.id}?msg=ai_done#ai-summary", status_code=303)


@router.post("/cases/{case_id}/draft", response_class=HTMLResponse, dependencies=CSRF)
async def case_draft(request: Request, case_id: int, viewer: ResponderDep, session: SessionDep):
    case = _get(session, Case, case_id)
    form = await request.form()
    action = str(form.get("action", "create"))
    draft = ai_service.draft_for(session, case)
    try:
        if action == "create":
            ai_service.create_draft(
                session,
                case,
                viewer.user,
                _provider(request),
                request.app.state.settings.ai_draft_thinking,
            )
        elif draft is None:
            raise ai_service.DraftError("There's no draft yet.")
        elif action == "save":
            ai_service.save_draft(session, case, draft, viewer.user, str(form.get("content", "")))
        elif action == "approve":
            ai_service.approve_draft(session, case, draft, viewer.user)
        elif action == "sent":
            ai_service.mark_sent(session, case, draft, viewer.user)
        else:
            raise HTTPException(status_code=400)
    except (AIError, ai_service.DraftError, case_actions.CaseActionError) as e:
        session.rollback()
        return case_view(request, session, _get(session, Case, case_id), error=str(e))
    session.commit()
    return RedirectResponse(f"/cases/{case.id}?msg=saved#client-message", status_code=303)


# --- Advisories --------------------------------------------------------------------------------


@router.get("/advisories", response_class=HTMLResponse)
def advisories_page(request: Request, viewer: ViewerDep, session: SessionDep) -> HTMLResponse:
    advisories = session.scalars(select(Advisory).order_by(Advisory.created_at.desc())).all()
    queue = [
        (a, possible_sites(session, a))
        for a in advisories
        if a.review_status is ReviewStatus.NEEDS_REVIEW
    ]
    queue.sort(
        key=lambda item: (-item[1], -(item[0].published_at or item[0].created_at).timestamp())
    )
    return page(
        request,
        "advisories.html",
        {
            "queue": queue,
            "advisories": [
                a for a in advisories if a.review_status is not ReviewStatus.NEEDS_REVIEW
            ],
            "fixtures": fixture_names(),
        },
    )


def advisory_view(
    request: Request,
    session: Session,
    advisory: Advisory,
    error: str | None = None,
    ranges_text: str | None = None,
) -> HTMLResponse:
    incidents = session.scalars(
        select(Incident)
        .join(IncidentAdvisory, IncidentAdvisory.incident_id == Incident.id)
        .where(IncidentAdvisory.advisory_id == advisory.id)
        .order_by(Incident.created_at.desc())
    ).all()
    waiting = advisory.review_status is ReviewStatus.NEEDS_REVIEW
    return page(
        request,
        "advisory.html",
        {
            "advisory": advisory,
            "incidents": incidents,
            "waiting": waiting,
            "possible": possible_sites(session, advisory) if waiting else None,
            "ranges_text": ranges_to_text(advisory) if ranges_text is None else ranges_text,
            "range_help": RANGE_HELP,
            "reviewer": session.get(User, advisory.reviewed_by) if advisory.reviewed_by else None,
            "error": error,
        },
        status=400 if error else 200,
    )


@router.get("/advisories/{advisory_id}", response_class=HTMLResponse)
def advisory_page(request: Request, advisory_id: int, viewer: ViewerDep, session: SessionDep):
    return advisory_view(request, session, _get(session, Advisory, advisory_id))


@router.post("/advisories/{advisory_id}/review", response_class=HTMLResponse, dependencies=CSRF)
async def advisory_review(
    request: Request, advisory_id: int, viewer: ResponderDep, session: SessionDep
):
    advisory = _get(session, Advisory, advisory_id)
    form = await request.form()
    action, note = str(form.get("action", "")), str(form.get("note", ""))
    text = str(form.get("ranges", ""))[:20000]
    try:
        if action == "confirm":
            confirm_advisory(session, advisory, viewer.user, text, note)
        elif action == "reject":
            reject_advisory(session, advisory, viewer.user, note)
        else:
            raise HTTPException(status_code=400)
    except ReviewError as e:
        session.rollback()
        advisory = _get(session, Advisory, advisory_id)
        return advisory_view(request, session, advisory, error=str(e), ranges_text=text)
    _audit(session, viewer.user, f"advisory_{action}ed", str(advisory.id), note=note[:200])
    incident = apply_advisory(session, advisory) if action == "confirm" else None
    session.commit()
    if incident is not None:
        return RedirectResponse(f"/incidents/{incident.id}?msg=reviewed", status_code=303)
    msg = "reviewed_none" if action == "confirm" else "rejected"
    return RedirectResponse(f"/advisories/{advisory.id}?msg={msg}", status_code=303)


@router.post("/advisories/{advisory_id}/exploited", response_class=HTMLResponse, dependencies=CSRF)
async def advisory_exploited(
    request: Request, advisory_id: int, viewer: ResponderDep, session: SessionDep
):
    advisory = _get(session, Advisory, advisory_id)
    form = await request.form()
    on, note = form.get("exploited") == "1", str(form.get("note", ""))
    try:
        set_exploited(session, advisory, viewer.user, on, note)
    except ReviewError as e:
        session.rollback()
        return advisory_view(request, session, _get(session, Advisory, advisory_id), error=str(e))
    _audit(session, viewer.user, "advisory_exploited", str(advisory.id), on=on, note=note[:200])
    apply_advisory(session, advisory)  # rescore every open case (+30 or -30)
    session.commit()
    return RedirectResponse(f"/advisories/{advisory.id}?msg=saved", status_code=303)


@router.get("/feeds", response_class=HTMLResponse)
def feeds_page(request: Request, viewer: ViewerDep, session: SessionDep) -> HTMLResponse:
    runs = session.scalars(select(FeedRun).order_by(FeedRun.id.desc()).limit(30)).all()
    releases = session.get(FeedState, "php-releases")
    kev = session.get(FeedState, "kev")
    health = feed_health(session, request.app.state.settings)
    return page(
        request,
        "feeds.html",
        {
            "health": health,
            "runs": runs,
            "labels": {h.spec.name: h.spec.label for h in health},
            "php": releases.data if releases else {},
            "kev_count": len(kev.data.get("cves", [])) if kev else None,
            "kev_updated": kev.updated_at if kev else None,
        },
    )


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


def _users_page(
    request: Request, session: Session, link: str | None = None, link_for: User | None = None
) -> HTMLResponse:
    users = session.scalars(select(User).order_by(User.display_name)).all()
    ctx = {"users": users, "roles": list(UserRole), "link": link, "link_for": link_for}
    response = page(request, "users.html", ctx)
    if link:
        response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request, viewer: AdminDep, session: SessionDep) -> HTMLResponse:
    return _users_page(request, session)


@router.post("/users", response_class=HTMLResponse, dependencies=CSRF)
def add_user(
    request: Request,
    viewer: AdminDep,
    session: SessionDep,
    email: Annotated[str, Form(max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")],
    display_name: Annotated[str, Form(min_length=1, max_length=100)],
    role: Annotated[UserRole, Form()],
) -> Response:
    user = User(email=email.strip().lower(), display_name=display_name.strip(), role=role)
    token = start_setup(user)
    session.add(user)
    try:
        session.flush()
    except IntegrityError as e:
        session.rollback()
        raise HTTPException(status_code=400) from e
    _audit(session, viewer.user, "user_added", user.email, role=role.value)
    session.commit()
    link = setup_link(request.app.state.settings.base_url, token)
    return _users_page(request, session, link, user)


@router.post("/users/{user_id}/reset", response_class=HTMLResponse, dependencies=CSRF)
def reset_user(request: Request, user_id: int, viewer: AdminDep, session: SessionDep) -> Response:
    """New setup link: clears the password and authenticator and signs the person out."""
    user = _get(session, User, user_id)
    if user.id == viewer.user.id or user.disabled_at is not None:
        raise HTTPException(status_code=400)  # your own reset is on the server: app.cli reset-user
    token = start_setup(user)
    _audit(session, viewer.user, "sign_in_reset", user.email)
    session.commit()
    link = setup_link(request.app.state.settings.base_url, token)
    return _users_page(request, session, link, user)


@router.post("/users/{user_id}/disable", dependencies=CSRF)
def disable_user(user_id: int, viewer: AdminDep, session: SessionDep) -> Response:
    user = _get(session, User, user_id)
    if user.id == viewer.user.id:
        raise HTTPException(status_code=400)  # don't lock yourself out
    user.disabled_at = utcnow()
    user.setup_token_hash = None  # an unused setup link stops working too
    user.setup_expires_at = None
    _audit(session, viewer.user, "user_disabled", user.email)
    session.commit()
    return RedirectResponse("/users?msg=user_disabled", status_code=303)

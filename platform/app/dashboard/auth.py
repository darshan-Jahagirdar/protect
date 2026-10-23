"""Dashboard sign-in, sessions, roles and CSRF (DESIGN.md §4.13).

- Sessions are an HMAC-signed cookie holding the user id, expiry and a CSRF token. Nothing
  secret is stored in the browser; the cookie can't be forged without PROTECT_SECRET_KEY.
- The cookie is SameSite=Lax, HttpOnly, and Secure in prod. Lax (not Strict) so the link in an
  alert email opens the dashboard signed in; cross-site POSTs are still blocked by the CSRF
  token plus the same-site Origin check.
- Sign-in in dev is "pick a team member" (local demo only). Production sign-in is Cloudflare
  Access with Microsoft Entra SSO (PROGRESS.md P4); until then prod has no sign-in at all.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.db import get_session
from app.enums import UserRole
from app.models import User
from app.settings import Settings

COOKIE = "protect_session"
SESSION_SECONDS = 12 * 3600
_DEV_SECRET = secrets.token_bytes(32)  # dev/test only: sessions end when the process restarts

ROLE_RANK = {UserRole.VIEWER: 0, UserRole.RESPONDER: 1, UserRole.ADMIN: 2}


class NotSignedIn(Exception):
    """Raised by the auth dependency; main.py turns it into a redirect to /login."""

    def __init__(self, next_path: str):
        self.next_path = next_path


@dataclass(frozen=True)
class SessionData:
    user_id: int
    expires: int
    csrf: str


def _key(settings: Settings) -> bytes:
    if settings.secret_key is not None:
        return settings.secret_key.get_secret_value().encode()
    if settings.is_prod:
        raise RuntimeError("PROTECT_SECRET_KEY is required in prod")
    return _DEV_SECRET


def _sign(settings: Settings, payload: bytes) -> str:
    return hmac.new(_key(settings), payload, hashlib.sha256).hexdigest()


def encode_session(settings: Settings, user_id: int, now: float | None = None) -> str:
    data = SessionData(
        user_id, int((now or time.time()) + SESSION_SECONDS), secrets.token_urlsafe(24)
    )
    payload = base64.urlsafe_b64encode(json.dumps(data.__dict__).encode())
    return f"{payload.decode()}.{_sign(settings, payload)}"


def decode_session(
    settings: Settings, cookie: str | None, now: float | None = None
) -> SessionData | None:
    if not cookie or "." not in cookie:
        return None
    payload, sig = cookie.rsplit(".", 1)
    if not hmac.compare_digest(_sign(settings, payload.encode()), sig):
        return None
    try:
        data = SessionData(**json.loads(base64.urlsafe_b64decode(payload)))
    except (ValueError, TypeError):
        return None
    if data.expires < (now or time.time()):
        return None
    return data


def set_session_cookie(response, settings: Settings, user_id: int) -> None:  # type: ignore[no-untyped-def]
    response.set_cookie(
        COOKIE,
        encode_session(settings, user_id),
        max_age=SESSION_SECONDS,
        httponly=True,
        samesite="lax",
        secure=settings.is_prod,
        path="/",
    )


def clear_session_cookie(response) -> None:  # type: ignore[no-untyped-def]
    response.delete_cookie(COOKIE, path="/")


def safe_next(path: str | None) -> str:
    """Only same-site relative paths, so /login?next= can't redirect to another site."""
    if not path or not path.startswith("/") or path.startswith("//") or "\\" in path:
        return "/"
    return path


@dataclass(frozen=True)
class Viewer:
    user: User
    csrf: str

    def can(self, role: UserRole) -> bool:
        return ROLE_RANK[self.user.role] >= ROLE_RANK[role]


def current_viewer(request: Request, session: Annotated[Session, Depends(get_session)]) -> Viewer:
    settings: Settings = request.app.state.settings
    data = decode_session(settings, request.cookies.get(COOKIE))
    user = session.get(User, data.user_id) if data else None
    if data is None or user is None or user.disabled_at is not None:
        raise NotSignedIn(request.url.path)
    request.state.viewer = Viewer(user, data.csrf)
    return request.state.viewer


def require(role: UserRole):  # type: ignore[no-untyped-def]
    """Dependency factory: the signed-in user must have at least this role."""

    def dep(viewer: Annotated[Viewer, Depends(current_viewer)]) -> Viewer:
        if not viewer.can(role):
            raise HTTPException(status_code=403)
        return viewer

    return dep


async def check_csrf(request: Request, viewer: Annotated[Viewer, Depends(current_viewer)]) -> None:
    """Every form POST must carry the session's CSRF token and come from our own site."""
    origin = request.headers.get("origin") or request.headers.get("referer")
    if origin is not None:
        got = urlsplit(origin)
        if got.netloc != request.url.netloc:
            raise HTTPException(status_code=403)
    form = await request.form()
    token = form.get("csrf_token")
    if not isinstance(token, str) or not hmac.compare_digest(token, viewer.csrf):
        raise HTTPException(status_code=403)


ViewerDep = Annotated[Viewer, Depends(current_viewer)]
ResponderDep = Annotated[Viewer, Depends(require(UserRole.RESPONDER))]
AdminDep = Annotated[Viewer, Depends(require(UserRole.ADMIN))]

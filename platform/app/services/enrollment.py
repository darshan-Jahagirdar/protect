"""Adding sites and enrolling their plugin keys (DESIGN.md §4.2)."""

import hashlib
import re
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schemas import EnrollRequest
from app.api.signing import key_id_for
from app.db import utcnow
from app.enums import HostType, SiteStatus
from app.models import EnrollmentCode, Site

_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O or 1/I mix-ups


class EnrollError(Exception):
    """Enrollment refused. The message is for our logs only, never sent to the plugin."""


def normalize_url(url: str) -> str:
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"not an http(s) URL: {url!r}")
    host = parts.hostname.lower()
    netloc = f"{host}:{parts.port}" if parts.port else host
    return f"{parts.scheme}://{netloc}{parts.path.rstrip('/')}"


def _canonical_code(code: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", code.upper())


def _hash_code(code: str) -> str:
    return hashlib.sha256(_canonical_code(code).encode()).hexdigest()


def create_site(
    session: Session, business_name: str, url: str, host_type: HostType = HostType.UNKNOWN
) -> Site:
    site = Site(business_name=business_name.strip(), url=normalize_url(url), host_type=host_type)
    session.add(site)
    session.flush()
    return site


def issue_code(session: Session, site: Site, ttl_hours: int, now: datetime | None = None) -> str:
    """Create a one-time enrollment code. Returns the plain code; only its hash is stored."""
    now = now or utcnow()
    for old in session.scalars(
        select(EnrollmentCode).where(
            EnrollmentCode.site_id == site.id, EnrollmentCode.used_at.is_(None)
        )
    ):
        session.delete(old)  # only the newest code works
    raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(16))
    code = "-".join(raw[i : i + 4] for i in range(0, 16, 4))
    session.add(
        EnrollmentCode(
            code_hash=_hash_code(code), site_id=site.id, expires_at=now + timedelta(hours=ttl_hours)
        )
    )
    session.flush()
    return code


def enroll(session: Session, req: EnrollRequest, now: datetime | None = None) -> Site:
    now = now or utcnow()
    row = session.scalar(
        select(EnrollmentCode).where(EnrollmentCode.code_hash == _hash_code(req.code))
    )
    if row is None:
        raise EnrollError("unknown enrollment code")
    if row.used_at is not None:
        raise EnrollError("enrollment code already used")
    if row.expires_at <= now:
        raise EnrollError("enrollment code expired")

    site = session.get(Site, row.site_id)
    if site is None or site.status is SiteStatus.REMOVED:
        raise EnrollError("site is not available for enrollment")
    try:
        if normalize_url(req.site_url) != site.url:
            raise EnrollError(f"site_url {req.site_url!r} does not match registered {site.url!r}")
        key_id = key_id_for(req.public_key)
    except ValueError as e:
        raise EnrollError(str(e)) from e

    other = session.scalar(select(Site).where(Site.key_id == key_id, Site.id != site.id))
    if other is not None:
        raise EnrollError("public key already belongs to another site")

    site.public_key = req.public_key
    site.key_id = key_id
    site.enrolled_at = now
    site.status = SiteStatus.ACTIVE
    row.used_at = now
    session.flush()
    return site

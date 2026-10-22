"""Public report API: the only endpoints reachable without the dashboard login.

Every failure is a bare status code with an empty body. The plugin ignores reply bodies
(rule R2), and an attacker learns nothing about why a request failed. The reason goes to
our own log instead.

Order of checks for /report (cheap and unauthenticated checks first, then the signature,
then everything else):
  HTTPS (prod) -> per-IP rate limit -> body size -> header formats -> known key ->
  timestamp window -> signature -> per-key rate limit -> nonce (replay) -> JSON schema ->
  web SAPI only -> store.
"""

import json
import logging
import time
from dataclasses import dataclass
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from pydantic import ValidationError
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api import signing
from app.api.ratelimit import RateLimiter
from app.api.schemas import EnrollRequest, Report
from app.db import get_session, utcnow
from app.enums import SiteStatus
from app.models import Nonce, Site
from app.services.enrollment import EnrollError, enroll
from app.services.inventory import apply_report
from app.settings import Settings

log = logging.getLogger("protect.api")
router = APIRouter(prefix="/api/v1")

ENROLL_MAX_BYTES = 4096


@dataclass
class Limiters:
    per_ip: RateLimiter
    per_key: RateLimiter
    enroll_per_ip: RateLimiter

    @classmethod
    def from_settings(cls, s: Settings) -> "Limiters":
        return cls(
            RateLimiter(s.requests_per_ip_per_10min, 600),
            RateLimiter(s.reports_per_key_per_10min, 600),
            RateLimiter(s.enrollments_per_ip_per_10min, 600),
        )


class Reject(Exception):
    def __init__(self, status: int, reason: str):
        self.status = status
        self.reason = reason


def _settings(request: Request) -> Settings:
    return request.app.state.settings


def _limiters(request: Request) -> Limiters:
    return request.app.state.limiters


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _require_https(request: Request) -> None:
    if _settings(request).is_prod and request.url.scheme != "https":
        raise Reject(400, "plain HTTP in prod")


async def _read_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > limit):
        raise Reject(413, f"declared body too large: {declared}")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise Reject(413, "body too large")
    return bytes(body)


def _signed_headers(request: Request) -> tuple[str, str, str]:
    ts = request.headers.get("x-protect-timestamp", "")
    nonce = request.headers.get("x-protect-nonce", "")
    sig = request.headers.get("x-protect-signature", "")
    if not (
        signing.TIMESTAMP_RE.match(ts)
        and signing.NONCE_RE.match(nonce)
        and signing.SIGNATURE_RE.match(sig)
    ):
        raise Reject(401, "missing or malformed signature headers")
    return ts, nonce, sig


def _check_timestamp(ts: str, settings: Settings) -> None:
    if abs(time.time() - int(ts)) > settings.timestamp_skew_seconds:
        raise Reject(401, f"timestamp outside window: {ts}")


def _parse(model: type[Report] | type[EnrollRequest], body: bytes):  # type: ignore[no-untyped-def]
    try:
        data = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise Reject(400, "body is not JSON") from e
    if not isinstance(data, dict):
        raise Reject(400, "body is not a JSON object")
    try:
        return model.model_validate(data)
    except ValidationError as e:
        fields = ",".join(".".join(map(str, err["loc"])) for err in e.errors()[:5])
        raise Reject(400, f"schema validation failed: {fields}") from e


def _record_nonce(session: Session, key_id: str, nonce: str, settings: Settings) -> None:
    now = utcnow()
    session.execute(
        delete(Nonce).where(Nonce.seen_at < now - timedelta(seconds=settings.nonce_ttl_seconds))
    )
    session.add(Nonce(key_id=key_id, nonce=nonce, seen_at=now))
    try:
        session.flush()
    except IntegrityError as e:
        session.rollback()
        raise Reject(401, "nonce already used (replay)") from e


@router.post("/report", include_in_schema=False)
async def report(request: Request, session: Annotated[Session, Depends(get_session)]) -> Response:
    settings, limiters, ip = _settings(request), _limiters(request), _ip(request)
    key_id = request.headers.get("x-protect-key", "")
    try:
        _require_https(request)
        if not limiters.per_ip.allow(ip):
            raise Reject(429, "per-IP rate limit")
        body = await _read_body(request, settings.report_max_bytes)
        ts, nonce, sig = _signed_headers(request)

        site = session.scalar(select(Site).where(Site.key_id == key_id)) if key_id else None
        if site is None or site.status is not SiteStatus.ACTIVE or not site.public_key:
            raise Reject(401, "unknown or inactive key")
        _check_timestamp(ts, settings)
        if not signing.verify(site.public_key, ts, nonce, body, sig):
            raise Reject(401, "bad signature")
        if not limiters.per_key.allow(key_id):
            raise Reject(429, "per-key rate limit")
        _record_nonce(session, key_id, nonce, settings)

        payload: Report = _parse(Report, body)
        if payload.php.sapi == "cli":
            raise Reject(400, "report sent from the CLI SAPI")

        result = apply_report(session, site, payload)
        session.commit()
    except Reject as r:
        session.rollback()
        log.warning("report rejected (%s): %s key=%s ip=%s", r.status, r.reason, key_id[:32], ip)
        return Response(status_code=r.status)

    log.info("report from site %s: %s", site.id, "stored" if result.stored else "unchanged")
    return Response(status_code=204)


@router.post("/enroll", include_in_schema=False)
async def enroll_site(
    request: Request, session: Annotated[Session, Depends(get_session)]
) -> Response:
    settings, limiters, ip = _settings(request), _limiters(request), _ip(request)
    try:
        _require_https(request)
        if not limiters.enroll_per_ip.allow(ip):
            raise Reject(429, "enroll rate limit")
        body = await _read_body(request, ENROLL_MAX_BYTES)
        ts, nonce, sig = _signed_headers(request)
        req: EnrollRequest = _parse(EnrollRequest, body)
        _check_timestamp(ts, settings)
        # Proof of possession: the request must be signed by the key being enrolled.
        if not signing.verify(req.public_key, ts, nonce, body, sig):
            raise Reject(401, "enroll request not signed by the enrolled key")
        try:
            site = enroll(session, req)
        except EnrollError as e:
            raise Reject(403, f"enroll refused: {e}") from e
        session.commit()
    except Reject as r:
        session.rollback()
        log.warning("enroll rejected (%s): %s ip=%s", r.status, r.reason, ip)
        return Response(status_code=r.status)

    log.info("site %s enrolled with key %s", site.id, site.key_id)
    return Response(status_code=204)

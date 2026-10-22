from datetime import timedelta

from app.db import utcnow
from app.enums import SiteStatus
from app.models import EnrollmentCode, Site
from app.services.enrollment import create_site, issue_code, normalize_url
from tests.api.conftest import Env
from tests.api.helpers import FakePlugin


def _enroll(env: Env, plugin: FakePlugin, code: str, **kw: object) -> int:
    body = plugin.enroll_body(code, **kw)  # type: ignore[arg-type]
    return env.client.post(
        "/api/v1/enroll", content=body, headers=plugin.headers(body, with_key=False)
    ).status_code


def test_enroll_activates_site_and_stores_public_key(env: Env, code: str, plugin: FakePlugin):
    assert _enroll(env, plugin, code) == 204
    site = env.site()
    assert site.status is SiteStatus.ACTIVE
    assert site.public_key == plugin.public_key
    assert site.key_id == plugin.key_id
    assert site.enrolled_at is not None


def test_code_works_once(env: Env, code: str, plugin: FakePlugin) -> None:
    assert _enroll(env, plugin, code) == 204
    assert _enroll(env, FakePlugin(), code) == 403


def test_code_is_case_and_dash_insensitive(env: Env, code: str, plugin: FakePlugin) -> None:
    assert _enroll(env, plugin, code.replace("-", "")) == 204


def test_unknown_code(env: Env, code: str, plugin: FakePlugin) -> None:
    assert _enroll(env, plugin, "AAAA-BBBB-CCCC-DDDD") == 403
    assert env.site().status is SiteStatus.PENDING


def test_expired_code(env: Env, code: str, plugin: FakePlugin) -> None:
    with env.db() as s:
        row = s.query(EnrollmentCode).one()
        row.expires_at = utcnow() - timedelta(minutes=1)
        s.commit()
    assert _enroll(env, plugin, code) == 403


def test_site_url_must_match(env: Env, code: str, plugin: FakePlugin) -> None:
    assert _enroll(env, plugin, code, site_url="https://evil.example") == 403
    assert env.site().status is SiteStatus.PENDING


def test_must_be_signed_by_the_key_being_enrolled(env: Env, code: str) -> None:
    owner, attacker = FakePlugin(), FakePlugin()
    body = owner.enroll_body(code)  # claims owner's key...
    r = env.client.post(  # ...but is signed by someone else
        "/api/v1/enroll", content=body, headers=attacker.headers(body, with_key=False)
    )
    assert r.status_code == 401
    assert env.site().status is SiteStatus.PENDING


def test_key_cannot_be_reused_by_a_second_site(env: Env, code: str, plugin: FakePlugin) -> None:
    assert _enroll(env, plugin, code) == 204
    with env.db() as s:
        other = create_site(s, "Other", "https://other.example")
        other_code = issue_code(s, other, 24)
        s.commit()
    assert _enroll(env, plugin, other_code, site_url="https://other.example") == 403


def test_new_code_replaces_old_unused_code(env: Env, code: str, plugin: FakePlugin) -> None:
    with env.db() as s:
        newer = issue_code(s, s.query(Site).one(), 24)
        s.commit()
    assert _enroll(env, plugin, code) == 403
    assert _enroll(env, plugin, newer) == 204


def test_reenroll_rotates_key(env: Env, enrolled: FakePlugin) -> None:
    with env.db() as s:
        fresh = issue_code(s, s.query(Site).one(), 24)
        s.commit()
    rotated = FakePlugin()
    assert _enroll(env, rotated, fresh) == 204
    assert env.site().key_id == rotated.key_id


def test_rejections_have_empty_bodies(env: Env, code: str, plugin: FakePlugin) -> None:
    body = plugin.enroll_body("AAAA-BBBB-CCCC-DDDD")
    r = env.client.post(
        "/api/v1/enroll", content=body, headers=plugin.headers(body, with_key=False)
    )
    assert r.status_code == 403
    assert r.content == b""


def test_malformed_enroll_body(env: Env, code: str, plugin: FakePlugin) -> None:
    for body in [b"not json", b"[]", b'{"code": "X"}']:
        r = env.client.post(
            "/api/v1/enroll", content=body, headers=plugin.headers(body, with_key=False)
        )
        assert r.status_code == 400


def test_normalize_url() -> None:
    assert normalize_url("HTTP://Example.COM/") == "http://example.com"
    assert normalize_url("https://example.com:8443/shop/") == "https://example.com:8443/shop"
    for bad in ["ftp://x", "example.com", "http://"]:
        try:
            normalize_url(bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted {bad!r}")

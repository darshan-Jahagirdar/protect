"""Password + authenticator sign-in, setup links, lockout and resets (DESIGN.md §4.13).

The passwords and secrets here are made-up test values (S105/S106 are expected).
"""
# ruff: noqa: S105, S106

import re
import time
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app import cli
from app.dashboard.credentials import (
    check_totp,
    decrypt_secret,
    encrypt_secret,
    hash_password,
    password_problem,
    totp_code,
    verify_password,
)
from app.db import utcnow
from app.enums import UserRole
from app.models import AuditLog, User
from tests.dashboard_helpers import Dash, make_dash

PASSWORD = "correct horse battery staple"
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890", RFC 6238 appendix B


@pytest.fixture
def dash(db_url: str) -> Dash:
    return make_dash(db_url)


# --- Building blocks ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("at", "code"),
    [(59, "287082"), (1111111109, "081804"), (1234567890, "005924"), (2000000000, "279037")],
)
def test_totp_matches_the_rfc_test_vectors(at: int, code: str) -> None:
    assert totp_code(RFC_SECRET, now=at) == code


def test_totp_accepts_one_step_either_side_and_never_twice() -> None:
    now = 1_800_000_000.0
    step = int(now // 30)
    for offset in (-30, 0, 30):
        assert check_totp(RFC_SECRET, totp_code(RFC_SECRET, now + offset), None, now=now)
    assert check_totp(RFC_SECRET, totp_code(RFC_SECRET, now - 60), None, now=now) is None
    assert check_totp(RFC_SECRET, totp_code(RFC_SECRET, now), step, now=now) is None  # reused
    assert check_totp(RFC_SECRET, "12345", None, now=now) is None
    assert check_totp(RFC_SECRET, "abcdef", None, now=now) is None
    spaced = totp_code(RFC_SECRET, now)
    assert check_totp(RFC_SECRET, f"{spaced[:3]} {spaced[3:]}", None, now=now) == step


def test_passwords_are_hashed_and_checked() -> None:
    stored = hash_password(PASSWORD)
    assert PASSWORD not in stored and stored.startswith("scrypt$")
    assert verify_password(stored, PASSWORD)
    assert not verify_password(stored, PASSWORD + "!")
    assert not verify_password(None, PASSWORD)
    assert not verify_password("scrypt$broken", PASSWORD)
    assert hash_password(PASSWORD) != stored  # a fresh salt every time


@pytest.mark.parametrize(
    ("password", "confirm", "problem"),
    [
        ("short pass", "short pass", "at least 12"),
        (PASSWORD, PASSWORD + "x", "don't match"),
        ("x" * 201, "x" * 201, "at most 200"),
        ("alex@demo.test", "alex@demo.test", "email"),
        ("alexanderthe", "alexanderthe", None),
        (PASSWORD, PASSWORD, None),
    ],
)
def test_password_rules(password: str, confirm: str, problem: str | None) -> None:
    got = password_problem(password, confirm, "alex@demo.test")
    assert (got is None) if problem is None else (problem in (got or ""))


def test_authenticator_secret_is_encrypted() -> None:
    stored = encrypt_secret(b"k" * 32, RFC_SECRET)
    assert RFC_SECRET not in stored
    assert decrypt_secret(b"k" * 32, stored) == RFC_SECRET
    assert decrypt_secret(b"other key", stored) is None
    assert decrypt_secret(b"k" * 32, "not base64!") is None


# --- Setup and sign-in through the pages ----------------------------------------------------


def _invite(dash: Dash, email: str = "alex@demo.test", role: str = "responder") -> str:
    """An admin adds a team member on the Team page; returns the setup path."""
    dash.login(UserRole.ADMIN)
    r = dash.post("/users", {"email": email, "display_name": "Alex", "role": role}, page="/users")
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    m = re.search(r"https://[^/]+(/setup/[A-Za-z0-9_-]+)", r.text) or re.search(
        r"http://[^/]+(/setup/[A-Za-z0-9_-]+)", r.text
    )
    assert m, "no setup link on the page"
    dash.client.cookies.clear()  # the admin signs out; Alex opens the link
    return m.group(1)


def _secret_on(page: str) -> str:
    m = re.search(r'<code class="code-big">([A-Z2-7 ]+)</code>', page)
    assert m, "no setup key on the page"
    return m.group(1).replace(" ", "")


def _set_up(dash: Dash, path: str) -> str:
    """Alex completes setup; returns their authenticator secret."""
    secret = _secret_on(dash.client.get(path).text)
    r = dash.client.post(
        path,
        data={"password": PASSWORD, "confirm": PASSWORD, "code": totp_code(secret)},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    assert r.headers["location"] == "/?msg=signed_up"
    return secret


def _sign_in(dash: Dash, secret: str, offset: int = 30, **changes: str):  # type: ignore[no-untyped-def]
    data = {
        "email": "alex@demo.test",
        "password": PASSWORD,
        "code": totp_code(secret, time.time() + offset),
        "next": "/incidents",
        **changes,
    }
    return dash.client.post("/login", data=data, follow_redirects=False)


def test_setup_page_shows_a_qr_code_without_scripts(dash: Dash) -> None:
    page = dash.client.get(_invite(dash))
    assert page.status_code == 200
    assert page.headers["cache-control"] == "no-store"
    assert 'src="data:image/svg+xml' in page.text
    assert "<script" not in page.text
    assert "'unsafe-inline'" not in page.headers["content-security-policy"]


def test_setup_then_sign_in(dash: Dash) -> None:
    path = _invite(dash)
    secret = _set_up(dash, path)
    assert dash.client.get("/", follow_redirects=False).status_code == 200  # signed in by setup
    with dash.session() as s:
        alex = s.query(User).filter_by(email="alex@demo.test").one()
        assert alex.password_hash and alex.setup_token_hash is None
        assert secret not in (alex.totp_secret_enc or "")  # stored encrypted
    assert dash.client.get(path).status_code == 404  # a used link is dead

    dash.client.cookies.clear()
    r = _sign_in(dash, secret)
    assert r.status_code == 303 and r.headers["location"] == "/incidents"
    assert "httponly" in r.headers["set-cookie"].lower()
    with dash.session() as s:
        alex_id = s.query(User).filter_by(email="alex@demo.test").one().id
        logins = s.query(AuditLog).filter_by(action="login", actor_user_id=alex_id).all()
        assert [a.data for a in logins] == [{"method": "password"}]
        assert s.query(AuditLog).filter_by(action="sign_in_set_up").count() == 1


def test_setup_refuses_a_weak_password_or_wrong_code(dash: Dash) -> None:
    path = _invite(dash)
    secret = _secret_on(dash.client.get(path).text)
    weak = dash.client.post(
        path, data={"password": "short", "confirm": "short", "code": totp_code(secret)}
    )
    assert weak.status_code == 400 and "at least 12" in weak.text
    wrong = dash.client.post(
        path, data={"password": PASSWORD, "confirm": PASSWORD, "code": "000000"}
    )
    assert wrong.status_code == 400 and "didn&#39;t match" in wrong.text
    # Reloading the page keeps the same secret, so an already-scanned code still works.
    assert _secret_on(dash.client.get(path).text) == secret


def test_expired_or_unknown_setup_link(dash: Dash) -> None:
    path = _invite(dash)
    with dash.session() as s:
        s.query(User).filter_by(email="alex@demo.test").one().setup_expires_at = (
            utcnow() - timedelta(minutes=1)
        )
        s.commit()
    assert dash.client.get(path).status_code == 404
    assert dash.client.get("/setup/not-a-real-token").status_code == 404
    r = dash.client.post(path, data={"password": PASSWORD, "confirm": PASSWORD, "code": "123456"})
    assert r.status_code == 404


@pytest.mark.parametrize(
    "changes",
    [
        {"password": "wrong password!!"},
        {"code": "000000"},
        {"email": "nobody@demo.test"},
    ],
)
def test_wrong_details_get_one_vague_message(dash: Dash, changes: dict[str, str]) -> None:
    secret = _set_up(dash, _invite(dash))
    dash.client.cookies.clear()
    r = _sign_in(dash, secret, **changes)
    assert r.status_code == 400
    assert "That didn&#39;t work" in r.text
    assert "set-cookie" not in r.headers


def test_a_code_works_only_once(dash: Dash) -> None:
    secret = _set_up(dash, _invite(dash))
    dash.client.cookies.clear()
    assert _sign_in(dash, secret).status_code == 303
    dash.client.cookies.clear()
    assert _sign_in(dash, secret).status_code == 400  # same code, seen over a shoulder


def test_account_pauses_after_five_wrong_tries(dash: Dash) -> None:
    secret = _set_up(dash, _invite(dash))
    dash.client.cookies.clear()
    for _ in range(5):
        assert _sign_in(dash, secret, password="wrong password!!").status_code == 400
    assert _sign_in(dash, secret).status_code == 400  # right details, but paused
    with dash.session() as s:
        alex = s.query(User).filter_by(email="alex@demo.test").one()
        alex.locked_until = utcnow() - timedelta(seconds=1)
        s.commit()
    assert _sign_in(dash, secret).status_code == 303  # works again after the pause


def test_disabled_member_cannot_sign_in(dash: Dash) -> None:
    secret = _set_up(dash, _invite(dash))
    with dash.session() as s:
        s.query(User).filter_by(email="alex@demo.test").one().disabled_at = utcnow()
        s.commit()
    assert dash.client.get("/", follow_redirects=False).status_code == 303  # session ends
    assert _sign_in(dash, secret).status_code == 400


def test_new_setup_link_signs_the_person_out_everywhere(dash: Dash) -> None:
    secret = _set_up(dash, _invite(dash))
    alex_cookies = dict(dash.client.cookies)
    dash.client.cookies.clear()
    dash.login(UserRole.ADMIN, "Admin Two")
    with dash.session() as s:
        alex_id = s.query(User).filter_by(email="alex@demo.test").one().id
    r = dash.post(f"/users/{alex_id}/reset", page="/users")
    assert r.status_code == 200 and "/setup/" in r.text
    dash.client.cookies.clear()
    for name, value in alex_cookies.items():
        dash.client.cookies.set(name, value)
    assert dash.client.get("/", follow_redirects=False).status_code == 303  # old session dead
    dash.client.cookies.clear()
    assert _sign_in(dash, secret, offset=0).status_code == 400  # old password and app gone


def test_admin_cannot_reset_themselves_on_the_page(dash: Dash) -> None:
    me = dash.login(UserRole.ADMIN)
    assert dash.post(f"/users/{me.id}/reset", page="/users").status_code == 400


def test_sign_in_from_another_site_is_refused(dash: Dash) -> None:
    r = dash.client.post(
        "/login",
        data={"email": "a@b.test", "password": "x", "code": "123456"},
        headers={"origin": "https://evil.example"},
    )
    assert r.status_code == 403


def test_too_many_attempts_from_one_address(dash: Dash) -> None:
    data = {"email": "a@b.test", "password": "x", "code": "123456"}
    codes = [dash.client.post("/login", data=data).status_code for _ in range(21)]
    assert codes[:20] == [400] * 20 and codes[20] == 429


def test_prod_sign_in_works_over_https_with_a_secure_cookie(db_url: str) -> None:
    dash = make_dash(db_url, env="prod")
    dash.client = TestClient(dash.client.app, base_url="https://testserver")
    with dash.session() as s:
        from app.dashboard.credentials import start_setup

        admin = User(email="alex@demo.test", display_name="Alex", role=UserRole.ADMIN)
        token = start_setup(admin)
        s.add(admin)
        s.commit()
    secret = _set_up(dash, f"/setup/{token}")
    dash.client.cookies.clear()
    r = _sign_in(dash, secret)
    assert r.status_code == 303
    assert "secure" in r.headers["set-cookie"].lower()
    assert dash.client.get("/users").status_code == 200


def test_cli_add_and_reset_print_a_setup_link(
    db_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    dash = make_dash(db_url)
    monkeypatch.setattr(cli, "SessionLocal", dash.session)
    assert cli.main(["add-user", "--email", "Alex@Demo.test", "--name", "Alex"]) == 0
    first = capsys.readouterr().out
    assert "/setup/" in first and "24 hours" in first
    assert cli.main(["reset-user", "--email", "alex@demo.test"]) == 0
    second = capsys.readouterr().out
    assert "/setup/" in second and second != first
    assert cli.main(["reset-user", "--email", "nobody@demo.test"]) == 1


def test_prod_never_offers_the_demo_sign_in_even_on_a_local_address(db_url: str) -> None:
    # Someone on the server itself (or a misconfigured proxy) talks to 127.0.0.1.
    dash = make_dash(db_url, env="prod")
    local = TestClient(dash.client.app, base_url="https://127.0.0.1")
    assert "Local demo" not in local.get("/login").text
    assert local.post("/login/dev", data={"user_id": "1"}).status_code == 404

import re

import pytest

from app.dashboard.auth import COOKIE, decode_session, encode_session, safe_next
from app.enums import Compromise, Exposure, HostType, SiteStatus, UserRole
from app.models import AuditLog, Case, ChecklistItem, Event, Site, User
from app.settings import Settings
from tests.dashboard_helpers import Dash, make_dash
from tests.test_incidents import _replay, _site


@pytest.fixture
def dash(db_url: str) -> Dash:
    return make_dash(db_url)


def _case(dash: Dash, fixture: str = "php2shell", **site_kw) -> int:  # type: ignore[no-untyped-def]
    with dash.session() as s:
        site = _site(s, "http://127.0.0.1:8081")
        for k, v in site_kw.items():
            setattr(site, k, v)
        incident = _replay(s, fixture)
        assert incident is not None
        s.commit()
        return incident.cases[0].id


def _load_case(dash: Dash, case_id: int) -> Case:
    with dash.session() as s:
        case = s.get(Case, case_id)
        assert case is not None
        return case


# --- Sessions ------------------------------------------------------------------------------


def test_session_cookie_round_trip_and_tamper() -> None:
    s = Settings(env="test", secret_key="k" * 40)
    cookie = encode_session(s, 7)
    assert decode_session(s, cookie).user_id == 7  # type: ignore[union-attr]
    payload, sig = cookie.rsplit(".", 1)
    assert decode_session(s, payload + "." + "0" * len(sig)) is None
    assert decode_session(Settings(env="test", secret_key="z" * 40), cookie) is None
    assert decode_session(s, cookie, now=10**12) is None  # expired
    assert decode_session(s, "garbage") is None


@pytest.mark.parametrize(
    ("raw", "safe"),
    [
        ("/cases/3", "/cases/3"),
        ("//evil.example", "/"),
        ("https://evil.example", "/"),
        ("/\\evil", "/"),
        (None, "/"),
        ("", "/"),
    ],
)
def test_safe_next_blocks_open_redirects(raw: str | None, safe: str) -> None:
    assert safe_next(raw) == safe


def test_login_sets_a_lax_httponly_cookie(dash: Dash) -> None:
    user = dash.add_user(UserRole.ADMIN, "Darshan")
    r = dash.client.post(
        "/login", data={"user_id": user.id, "next": "//evil.example"}, follow_redirects=False
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/"
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    with dash.session() as s:
        assert s.query(AuditLog).filter_by(action="login").count() == 1


def test_login_page_lists_team_members(dash: Dash) -> None:
    dash.add_user(UserRole.ADMIN, "Darshan")
    assert "Darshan" in dash.client.get("/login").text


def test_disabled_user_is_signed_out(dash: Dash) -> None:
    user = dash.login(UserRole.ADMIN)
    with dash.session() as s:
        from app.db import utcnow

        s.get(User, user.id).disabled_at = utcnow()  # type: ignore[union-attr]
        s.commit()
    assert dash.client.get("/", follow_redirects=False).status_code == 303
    r = dash.client.post("/login", data={"user_id": user.id}, follow_redirects=False)
    assert r.status_code == 403


def test_forged_cookie_is_ignored(dash: Dash) -> None:
    dash.client.cookies.set(COOKIE, encode_session(Settings(env="test", secret_key="q" * 40), 1))
    assert dash.client.get("/", follow_redirects=False).status_code == 303


def test_logout(dash: Dash) -> None:
    dash.login()
    assert dash.post("/logout").status_code == 303
    dash.client.cookies.clear()
    assert dash.client.get("/", follow_redirects=False).status_code == 303


# --- Pages render, escape, and contain no scripts ------------------------------------------


def test_every_page_renders_without_scripts(dash: Dash) -> None:
    case_id = _case(dash)
    dash.login(UserRole.ADMIN)
    case = _load_case(dash, case_id)
    for path in [
        "/",
        "/incidents",
        f"/incidents/{case.incident_id}",
        f"/cases/{case_id}",
        "/sites",
        f"/sites/{case.site_id}",
        "/advisories",
        "/users",
    ]:
        r = dash.client.get(path)
        assert r.status_code == 200, path
        assert "<script" not in r.text, path


def test_hostile_names_are_escaped(dash: Dash) -> None:
    case_id = _case(dash, business_name="<script>alert('x')</script>")
    dash.login(UserRole.ADMIN)
    case = _load_case(dash, case_id)
    for path in [
        f"/cases/{case_id}",
        f"/sites/{case.site_id}",
        "/sites",
        f"/incidents/{case.incident_id}",
    ]:
        text = dash.client.get(path).text
        assert "<script>alert" not in text, path
        assert "&lt;script&gt;" in text, path


def test_overview_counts(dash: Dash) -> None:
    _case(dash)
    dash.login()
    text = dash.client.get("/").text
    assert "PHP2Shell" in text
    assert re.search(r'tile-value">1</div><div class="tile-label">P1/P2 not acknowledged', text)


# --- Roles -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "data"),
    [
        ("/sites", {"business_name": "X", "url": "https://x.test", "host_type": "unknown"}),
        ("/users", {"email": "a@b.test", "display_name": "A", "role": "viewer"}),
    ],
)
def test_admin_only_forms(dash: Dash, path: str, data: dict) -> None:
    dash.login(UserRole.RESPONDER)
    assert dash.post(path, data).status_code == 403
    assert dash.client.get("/users").status_code == 403


def test_viewer_cannot_act_on_cases(dash: Dash) -> None:
    case_id = _case(dash)
    dash.login(UserRole.VIEWER)
    page = dash.client.get(f"/cases/{case_id}").text
    assert "Mark fix claimed" not in page
    r = dash.post(f"/cases/{case_id}/action", {"action": "claim_fix"})
    assert r.status_code == 403


# --- Case actions --------------------------------------------------------------------------------


def test_claim_fix(dash: Dash) -> None:
    case_id = _case(dash)
    user = dash.login(UserRole.RESPONDER, "Priya")
    r = dash.post(f"/cases/{case_id}/action", {"action": "claim_fix", "note": "upgraded via WPE"})
    assert r.status_code == 303
    assert _load_case(dash, case_id).exposure is Exposure.FIX_CLAIMED
    with dash.session() as s:
        ev = s.query(Event).filter_by(type="fix_claimed").one()
        assert (ev.actor_user_id, ev.note) == (user.id, "upgraded via WPE")
    assert "Priya" in dash.client.get(f"/cases/{case_id}").text


def test_decision_needs_a_note(dash: Dash) -> None:
    case_id = _case(dash)
    dash.login()
    r = dash.post(f"/cases/{case_id}/action", {"action": "accepted_risk", "note": "  "})
    assert r.status_code == 400
    assert "Please add a note" in r.text
    assert _load_case(dash, case_id).exposure is Exposure.VULNERABLE
    r = dash.post(
        f"/cases/{case_id}/action", {"action": "accepted_risk", "note": "site retired on Friday"}
    )
    assert r.status_code == 303
    assert _load_case(dash, case_id).exposure is Exposure.ACCEPTED_RISK


def test_undo_hands_case_back_to_the_engine(dash: Dash) -> None:
    case_id = _case(dash)
    dash.login()
    dash.post(f"/cases/{case_id}/action", {"action": "false_positive", "note": "wrong site"})
    assert dash.post(f"/cases/{case_id}/action", {"action": "undo"}).status_code == 303
    assert _load_case(dash, case_id).exposure is Exposure.VULNERABLE  # still PHP 8.3.30


def test_shield_needs_a_note_and_lowers_score(dash: Dash) -> None:
    case_id = _case(dash)
    dash.login()
    assert dash.post(f"/cases/{case_id}/action", {"action": "shield_on"}).status_code == 400
    r = dash.post(
        f"/cases/{case_id}/action",
        {"action": "shield_on", "note": "Cloudflare managed rule 100xyz on"},
    )
    assert r.status_code == 303
    case = _load_case(dash, case_id)
    assert case.shielded and case.score == 75
    assert "edge firewall rule confirmed active (-5)" in case.score_reasons
    dash.post(f"/cases/{case_id}/action", {"action": "shield_off"})
    assert _load_case(dash, case_id).score == 80


def test_compromise_flag(dash: Dash) -> None:
    case_id = _case(dash)
    dash.login()
    r = dash.post(
        f"/cases/{case_id}/action",
        {"action": "compromise", "value": "suspected", "note": "test.php in uploads"},
    )
    assert r.status_code == 303
    assert _load_case(dash, case_id).compromise is Compromise.SUSPECTED


def test_unknown_action_rejected(dash: Dash) -> None:
    case_id = _case(dash)
    dash.login()
    assert dash.post(f"/cases/{case_id}/action", {"action": "delete_everything"}).status_code == 400


# --- Checklist ---------------------------------------------------------------------------------


def test_case_page_shows_managed_wp_checklist(dash: Dash) -> None:
    case_id = _case(dash, host_type=HostType.MANAGED_WP, host_name="WP Engine")
    dash.login()
    text = dash.client.get(f"/cases/{case_id}").text
    assert "PHP core flaw on a managed WordPress host" in text
    assert "Check WP Engine&#39;s status page" in text
    assert "switch to PHP 8.3.36 or newer" in text
    assert "Not &#39;Under Attack&#39; mode" in text


def test_tick_and_untick(dash: Dash) -> None:
    case_id = _case(dash, host_type=HostType.MANAGED_WP)
    user = dash.login(UserRole.RESPONDER, "Priya")
    r = dash.post(
        f"/cases/{case_id}/checklist",
        {"item_key": "host_status", "done": "1", "note": "WPE patched at 11:00"},
    )
    assert r.status_code == 303
    with dash.session() as s:
        row = s.query(ChecklistItem).one()
        assert (row.item_key, row.done_by, row.note) == (
            "host_status",
            user.id,
            "WPE patched at 11:00",
        )
        assert row.template_key == "php-core/managed-wp"
    assert "WPE patched at 11:00" in dash.client.get(f"/cases/{case_id}").text
    dash.post(f"/cases/{case_id}/checklist", {"item_key": "host_status", "done": "0"})
    with dash.session() as s:
        assert s.query(ChecklistItem).one().done_at is None


@pytest.mark.parametrize("item", ["report_shows_fix", "not_a_real_item"])
def test_auto_and_unknown_items_cannot_be_ticked(dash: Dash, item: str) -> None:
    case_id = _case(dash, host_type=HostType.MANAGED_WP)
    dash.login()
    r = dash.post(f"/cases/{case_id}/checklist", {"item_key": item, "done": "1"})
    assert r.status_code == 400


# --- Sites ----------------------------------------------------------------------------------------


def test_admin_adds_site_and_sees_code_once(dash: Dash) -> None:
    dash.login(UserRole.ADMIN)
    r = dash.post(
        "/sites",
        {"business_name": "Shop Co", "url": "HTTPS://Shop.Example/", "host_type": "managed-wp"},
        page="/sites",
    )
    assert r.status_code == 200
    code = re.search(r"code-big\">([A-Z0-9-]{19})<", r.text)
    assert code, "the new code is shown"
    with dash.session() as s:
        site = s.query(Site).filter_by(business_name="Shop Co").one()
        assert site.url == "https://shop.example"
        assert site.status is SiteStatus.PENDING
    assert code.group(1) not in dash.client.get(f"/sites/{site.id}").text  # only shown once


@pytest.mark.parametrize("url", ["not a url", "ftp://x.test"])
def test_add_site_rejects_bad_urls(dash: Dash, url: str) -> None:
    dash.login(UserRole.ADMIN)
    r = dash.post(
        "/sites", {"business_name": "X", "url": url, "host_type": "unknown"}, page="/sites"
    )
    assert r.status_code == 400


def test_duplicate_site_rejected(dash: Dash) -> None:
    dash.login(UserRole.ADMIN)
    data = {"business_name": "X", "url": "https://dup.example", "host_type": "unknown"}
    assert dash.post("/sites", data, page="/sites").status_code == 200
    r = dash.post("/sites", data, page="/sites")
    assert r.status_code == 400
    assert "already exists" in r.text


def test_risk_tags_rescore_open_cases(dash: Dash) -> None:
    case_id = _case(dash)
    dash.login(UserRole.ADMIN)
    site_id = _load_case(dash, case_id).site_id
    r = dash.post(
        f"/sites/{site_id}/settings",
        {"host_type": "managed-wp", "host_name": "WP Engine", "risk_ecommerce": "on"},
        page=f"/sites/{site_id}",
    )
    assert r.status_code == 303
    assert _load_case(dash, case_id).score == 90
    with dash.session() as s:
        assert s.get(Site, site_id).host_name == "WP Engine"  # type: ignore[union-attr]


def test_new_enrollment_code_from_site_page(dash: Dash) -> None:
    case_id = _case(dash)
    dash.login(UserRole.ADMIN)
    site_id = _load_case(dash, case_id).site_id
    r = dash.post(f"/sites/{site_id}/code", page=f"/sites/{site_id}")
    assert r.status_code == 200
    assert re.search(r"code-big\">[A-Z0-9-]{19}<", r.text)


# --- Advisories and team --------------------------------------------------------------------------


def test_replay_button(dash: Dash) -> None:
    with dash.session() as s:
        _site(s, "http://127.0.0.1:8081")
        s.commit()
    dash.login()
    r = dash.post("/advisories/replay", {"name": "php2shell"}, page="/advisories")
    assert r.status_code == 303
    assert r.headers["location"].startswith("/incidents/")
    assert (
        dash.post("/advisories/replay", {"name": "../etc/passwd"}, page="/advisories").status_code
        == 400
    )


def test_team_management(dash: Dash) -> None:
    me = dash.login(UserRole.ADMIN)
    r = dash.post(
        "/users",
        {"email": "New@Demo.test", "display_name": "New Person", "role": "viewer"},
        page="/users",
    )
    assert r.status_code == 303
    with dash.session() as s:
        new = s.query(User).filter_by(email="new@demo.test").one()
    assert dash.post(f"/users/{new.id}/disable", page="/users").status_code == 303
    assert dash.post(f"/users/{me.id}/disable", page="/users").status_code == 400  # not yourself
    bad = dash.post(
        "/users", {"email": "nope", "display_name": "X", "role": "viewer"}, page="/users"
    )
    assert bad.status_code == 422


def test_each_role_sees_the_right_controls(dash: Dash) -> None:
    case_id = _case(dash)
    site_id = _load_case(dash, case_id).site_id
    dash.login(UserRole.RESPONDER)
    case_page = dash.client.get(f"/cases/{case_id}").text
    assert "Mark fix claimed" in case_page and ">Done</button>" in case_page
    site_page = dash.client.get(f"/sites/{site_id}").text
    assert "Issue a new enrollment code" not in site_page and 'href="/users"' not in site_page

    dash.client.cookies.clear()
    dash.login(UserRole.ADMIN)
    site_page = dash.client.get(f"/sites/{site_id}").text
    assert "enrollment code" in site_page and 'name="host_type"' in site_page
    assert 'href="/users"' in site_page

"""Step 9: auto-verify, fix-not-visible, monitoring, reopening and closing."""

from datetime import timedelta

import pytest
from sqlalchemy.orm import Session

from app.db import utcnow
from app.enums import ClientNotice, Exposure, IncidentStatus, UserRole
from app.models import Event, Incident, User
from app.services import cases
from app.services.incidents import fix_not_visible, flag_unconfirmed_fixes
from tests.dashboard_helpers import Dash, make_dash
from tests.test_incidents import _replay, _site, send


@pytest.fixture
def user(session: Session) -> User:
    u = User(email="r@demo.test", display_name="Responder", role=UserRole.RESPONDER)
    session.add(u)
    session.flush()
    return u


def _setup(session: Session, php: str = "8.3.30", **kw):  # type: ignore[no-untyped-def]
    site = _site(session, "http://127.0.0.1:8081", php=php, **kw)
    incident = _replay(session, "php2shell")
    assert incident is not None
    return site, incident, incident.cases[0]


def _types(session: Session, incident: Incident) -> list[str]:
    return [
        e.type for e in session.query(Event).filter_by(incident_id=incident.id).order_by(Event.id)
    ]


@pytest.mark.parametrize(
    "start", [Exposure.FIX_CLAIMED, Exposure.ACCEPTED_RISK, Exposure.NEEDS_CHECK]
)
def test_these_states_verify_when_the_fix_shows(session: Session, start: Exposure) -> None:
    site, incident, case = _setup(session)
    case.exposure = start
    send(session, site, php="8.3.36")
    assert case.exposure is Exposure.VERIFIED


@pytest.mark.parametrize("start", [Exposure.FALSE_POSITIVE, Exposure.NOT_AFFECTED])
def test_these_states_are_left_alone(session: Session, start: Exposure) -> None:
    site, incident, case = _setup(session)
    case.exposure = start
    send(session, site, php="8.3.36")
    assert case.exposure is start


def test_regression_after_verify_reopens_case_and_incident(session: Session) -> None:
    site, incident, case = _setup(session)
    send(session, site, php="8.3.36")
    assert incident.status is IncidentStatus.MONITORING
    send(session, site, php="8.3.30")  # someone rolled PHP back
    assert case.exposure is Exposure.VULNERABLE
    assert incident.status is IncidentStatus.OPEN
    assert _types(session, incident)[-2:] == ["case_reopened", "incident_reopened"]


def test_claim_fix_when_report_already_shows_it_verifies_at_once(session: Session, user) -> None:
    site, incident, case = _setup(session)
    case.exposure = Exposure.FALSE_POSITIVE  # park it so the patched report doesn't verify it
    send(session, site, php="8.3.36")
    case.exposure = Exposure.VULNERABLE
    cases.claim_fix(session, case, user, "done")
    assert case.exposure is Exposure.VERIFIED


def test_manual_verify_needs_evidence(session: Session, user: User) -> None:
    site, incident, case = _setup(
        session, os={"id": "almalinux", "id_like": "rhel", "version_id": "9.4"}
    )
    assert case.exposure is Exposure.NEEDS_CHECK  # RHEL family: can't tell from the version
    with pytest.raises(cases.CaseActionError):
        cases.verify_manually(session, case, user, "")
    cases.verify_manually(session, case, user, "Host ticket #4411: backport applied 22 Oct")
    assert case.exposure is Exposure.VERIFIED
    assert incident.status is IncidentStatus.MONITORING


def test_manual_verify_not_allowed_on_decided_case(session: Session, user: User) -> None:
    site, incident, case = _setup(session)
    case.exposure = Exposure.FALSE_POSITIVE
    with pytest.raises(cases.CaseActionError):
        cases.verify_manually(session, case, user, "x")


# --- Fix claimed but not visible ------------------------------------------------------------


def test_fix_not_visible_after_two_hours(session: Session, user: User) -> None:
    site, incident, case = _setup(session)
    cases.claim_fix(session, case, user, "switched PHP in WPE panel")
    t = utcnow()
    assert flag_unconfirmed_fixes(session, now=t + timedelta(minutes=119)) == 0
    assert not fix_not_visible(session, case)
    assert flag_unconfirmed_fixes(session, now=t + timedelta(hours=2, minutes=1)) == 1
    assert fix_not_visible(session, case)
    assert flag_unconfirmed_fixes(session, now=t + timedelta(hours=5)) == 0  # only once
    note = session.query(Event).filter_by(type="fix_not_visible").one().note
    assert "no report from the site since the fix was claimed" in note


def test_fix_not_visible_mentions_the_version_still_reported(session: Session, user) -> None:
    site, incident, case = _setup(session)
    cases.claim_fix(session, case, user)
    send(session, site, php="8.3.31")  # still affected after the "fix"
    flag_unconfirmed_fixes(session, now=utcnow() + timedelta(hours=3))
    note = session.query(Event).filter_by(type="fix_not_visible").one().note
    assert "still show 8.3.31" in note


def test_new_claim_clears_the_flag(session: Session, user: User) -> None:
    site, incident, case = _setup(session)
    cases.claim_fix(session, case, user)
    flag_unconfirmed_fixes(session, now=utcnow() + timedelta(hours=3))
    cases.undo_decision(session, case, user)
    cases.claim_fix(session, case, user, "second try, restarted FPM")
    assert not fix_not_visible(session, case)


# --- Closing ---------------------------------------------------------------------------------


def test_cannot_close_while_sites_are_affected(session: Session, user: User) -> None:
    site, incident, case = _setup(session)
    with pytest.raises(cases.CaseActionError, match="once every affected site"):
        cases.close_incident(session, incident, user, "done")


def test_close_needs_a_reason_when_notices_are_missing(session: Session, user: User) -> None:
    site, incident, case = _setup(session)
    send(session, site, php="8.3.36")
    with pytest.raises(cases.CaseActionError, match="1 client notice"):
        cases.close_incident(session, incident, user, "")
    cases.close_incident(session, incident, user, "client is on holiday, told by phone")
    assert incident.status is IncidentStatus.CLOSED and incident.closed_at is not None


def test_ticking_client_notice_records_it(session: Session, user: User) -> None:
    site, incident, case = _setup(session)
    cases.tick(session, case, user, "client_notice", True, "emailed Ravi 10:40")
    assert case.client_notice is ClientNotice.SENT
    send(session, site, php="8.3.36")
    cases.close_incident(session, incident, user, None)  # no reason needed now
    assert incident.status is IncidentStatus.CLOSED


def test_regression_after_close_opens_a_new_incident(session: Session) -> None:
    site, incident, case = _setup(session)
    send(session, site, php="8.3.36")
    incident.status = IncidentStatus.CLOSED
    send(session, site, php="8.3.30")
    assert session.query(Incident).count() == 2


# --- Dashboard ----------------------------------------------------------------------------------


def _dash_case(dash: Dash) -> tuple[int, str]:
    with dash.session() as s:
        site = _site(s, "http://127.0.0.1:8081")
        incident = _replay(s, "php2shell")
        assert incident is not None
        s.commit()
        return incident.cases[0].id, incident.id, site.id  # type: ignore[return-value]


def test_dashboard_verify_close_flow(db_url: str) -> None:
    dash = make_dash(db_url)
    case_id, incident_id, site_id = _dash_case(dash)  # type: ignore[misc]
    dash.login()
    r = dash.post(f"/cases/{case_id}/action", {"action": "verify", "note": ""})
    assert r.status_code == 400
    r = dash.post(
        f"/cases/{case_id}/action", {"action": "verify", "note": "WPE confirmed 8.3.36 live"}
    )
    assert r.status_code == 303
    page = dash.client.get(f"/incidents/{incident_id}").text
    assert "Close incident" in page and "monitoring" in page.lower()
    r = dash.post(f"/incidents/{incident_id}/close", {"note": ""}, page=f"/incidents/{incident_id}")
    assert r.status_code == 400 and "client notice" in r.text
    r = dash.post(
        f"/incidents/{incident_id}/close",
        {"note": "told by phone"},
        page=f"/incidents/{incident_id}",
    )
    assert r.status_code == 303
    assert "Closed" in dash.client.get(f"/incidents/{incident_id}").text


def test_dashboard_shows_fix_not_visible(db_url: str) -> None:
    dash = make_dash(db_url)
    case_id, incident_id, site_id = _dash_case(dash)  # type: ignore[misc]
    dash.login()
    dash.post(f"/cases/{case_id}/action", {"action": "claim_fix", "note": "switched"})
    with dash.session() as s:
        flag_unconfirmed_fixes(s, now=utcnow() + timedelta(hours=3))
        s.commit()
    assert "isn't showing in this site's reports" in dash.client.get(f"/cases/{case_id}").text
    assert "Fixes not showing (2h+)" in dash.client.get("/").text

from datetime import timedelta

import pytest
from sqlalchemy.orm import Session

from app.alerts import mailer as mailer_mod
from app.alerts.mailer import MemoryMailer, Message, SmtpMailer
from app.db import utcnow
from app.enums import Exposure, IncidentStatus, Priority, UserRole
from app.models import Alert, Event, Incident
from app.services.alerting import (
    acknowledge,
    escalate_unacknowledged,
    send_digest,
    send_due_alerts,
)
from app.settings import Settings
from tests.dashboard_helpers import make_dash
from tests.test_incidents import _replay, _site

BASE = "https://protect.example"


def _settings(**kw: object) -> Settings:
    return Settings(env="test", base_url=BASE, alert_recipients="team@demo.test", **kw)  # type: ignore[arg-type]


@pytest.fixture
def mail() -> MemoryMailer:
    return MemoryMailer()


@pytest.fixture
def php2shell(session: Session) -> Incident:
    _site(session, "http://127.0.0.1:8081")
    incident = _replay(session, "php2shell")
    assert incident is not None and incident.priority is Priority.P1
    return incident


def _assert_counts_only(msg: Message, session: Session) -> None:
    """Rule R9: no site URL or business name in any outbound message."""
    from app.models import Site

    for site in session.query(Site).all():
        for text in (msg.subject, msg.body):
            assert site.url not in text
            assert site.business_name not in text
            assert site.url.split("://", 1)[1] not in text


# --- New and updated alerts -----------------------------------------------------------


def test_p1_incident_sends_one_counts_only_alert(session: Session, php2shell: Incident, mail):
    assert send_due_alerts(session, mail, _settings()) == 1
    [msg] = mail.sent
    assert msg.to == ("team@demo.test",)
    assert msg.subject.startswith("[Protect] P1: 1 site affected by PHP2Shell")
    assert "Sites affected: 1 (vulnerable: 1, needs check: 0)" in msg.body
    assert "CVE-2026-109618" in msg.body
    assert f"{BASE}/incidents/{php2shell.id}" in msg.body
    _assert_counts_only(msg, session)

    [alert] = session.query(Alert).all()
    assert (alert.kind, alert.sites_count, alert.priority) == ("new", 1, Priority.P1)
    assert "alert_sent" in [e.type for e in session.query(Event).all()]


def test_no_duplicate_alerts(session: Session, php2shell: Incident, mail: MemoryMailer) -> None:
    send_due_alerts(session, mail, _settings())
    send_due_alerts(session, mail, _settings())
    assert len(mail.sent) == 1


def test_more_sites_sends_an_update(session: Session, php2shell: Incident, mail) -> None:
    send_due_alerts(session, mail, _settings())
    _site(session, "https://second.example", php="8.2.20")  # report re-matches it into the incident
    assert send_due_alerts(session, mail, _settings()) == 1
    update = mail.sent[-1]
    assert "update: now 2 sites affected" in update.subject
    assert "went from 1 to 2" in update.body
    _assert_counts_only(update, session)


def test_low_priority_waits_for_digest(session: Session, mail: MemoryMailer) -> None:
    _site(session, "http://127.0.0.1:8081")
    drill = _replay(session, "drill-plugin")
    assert drill is not None and drill.priority is Priority.P4
    assert send_due_alerts(session, mail, _settings()) == 0
    assert send_digest(session, mail, _settings()) == 1
    [digest] = mail.sent
    assert "Daily digest: 1 open" in digest.subject
    assert "[DRILL] P4" in digest.body
    _assert_counts_only(digest, session)


def test_empty_digest_sends_nothing(session: Session, mail: MemoryMailer) -> None:
    assert send_digest(session, mail, _settings()) == 0
    assert mail.sent == []


def test_closed_incidents_are_ignored(session: Session, php2shell: Incident, mail) -> None:
    php2shell.status = IncidentStatus.CLOSED
    assert send_due_alerts(session, mail, _settings()) == 0


def test_verified_sites_are_not_counted(session: Session, php2shell: Incident, mail) -> None:
    php2shell.cases[0].exposure = Exposure.VERIFIED
    assert send_due_alerts(session, mail, _settings()) == 0


# --- Escalation and acknowledgement ----------------------------------------------------


def test_escalates_after_15_minutes_without_ack(session: Session, php2shell: Incident, mail):
    t0 = utcnow()
    send_due_alerts(session, mail, _settings(), now=t0)
    assert escalate_unacknowledged(session, mail, _settings(), now=t0 + timedelta(minutes=14)) == 0
    assert escalate_unacknowledged(session, mail, _settings(), now=t0 + timedelta(minutes=15)) == 1
    esc = mail.sent[-1]
    assert "[UNACKNOWLEDGED] P1" in esc.subject
    assert esc.to == ("team@demo.test",)  # no backup configured: back to the responders
    _assert_counts_only(esc, session)
    # Only once.
    assert escalate_unacknowledged(session, mail, _settings(), now=t0 + timedelta(hours=2)) == 0


def test_escalation_goes_to_backup_when_configured(session: Session, php2shell: Incident, mail):
    t0 = utcnow()
    s = _settings(backup_recipients="backup@demo.test")
    send_due_alerts(session, mail, s, now=t0)
    escalate_unacknowledged(session, mail, s, now=t0 + timedelta(minutes=16))
    assert mail.sent[-1].to == ("backup@demo.test",)


def test_ack_stops_escalation(session: Session, php2shell: Incident, mail: MemoryMailer) -> None:
    t0 = utcnow()
    send_due_alerts(session, mail, _settings(), now=t0)
    assert acknowledge(session, php2shell, user_id=None, now=t0 + timedelta(minutes=5))
    assert not acknowledge(session, php2shell, user_id=None)  # already acknowledged
    assert escalate_unacknowledged(session, mail, _settings(), now=t0 + timedelta(hours=1)) == 0
    assert "acknowledged" in [e.type for e in session.query(Event).all()]


def test_ack_before_any_email_still_counts(session: Session, php2shell: Incident, mail) -> None:
    t0 = utcnow()
    assert acknowledge(session, php2shell, user_id=None, now=t0)
    send_due_alerts(session, mail, _settings(), now=t0)  # the alert itself still goes out
    assert len(mail.sent) == 1
    assert escalate_unacknowledged(session, mail, _settings(), now=t0 + timedelta(hours=1)) == 0


def test_no_recipients_means_nothing_recorded(session: Session, php2shell: Incident, mail):
    empty = Settings(env="test", base_url=BASE, alert_recipients="")
    assert send_due_alerts(session, mail, empty) == 0
    assert session.query(Alert).count() == 0
    assert send_due_alerts(session, mail, _settings()) == 1  # sent once configured


def test_mail_failure_is_retried(session: Session, php2shell: Incident) -> None:
    class Broken:
        def send(self, message: Message) -> None:
            raise OSError("mail server down")

    assert send_due_alerts(session, Broken(), _settings()) == 0
    assert session.query(Alert).count() == 0
    retry = MemoryMailer()
    assert send_due_alerts(session, retry, _settings()) == 1


def test_recipient_lists() -> None:
    s = _settings(backup_recipients=" a@x.test , ,b@x.test")
    assert s.alert_recipient_list == ["team@demo.test"]
    assert s.backup_recipient_list == ["a@x.test", "b@x.test"]


# --- SMTP transport --------------------------------------------------------------------


def test_smtp_mailer_builds_a_plain_email(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = []

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: int):
            assert (host, port) == ("mailpit", 1025)

        def __enter__(self) -> "FakeSMTP":
            return self

        def __exit__(self, *a: object) -> None:
            pass

        def send_message(self, email) -> None:  # type: ignore[no-untyped-def]
            sent.append(email)

    monkeypatch.setattr(mailer_mod.smtplib, "SMTP", FakeSMTP)
    s = Settings(env="test", smtp_host="mailpit", smtp_port=1025, alert_from="p@demo.test")
    SmtpMailer(s).send(Message(("team@demo.test",), "Subject", "Body"))
    [email] = sent
    assert email["From"] == "p@demo.test"
    assert email["To"] == "team@demo.test"
    assert email.get_content().strip() == "Body"


# --- Incident page and the "I'm on it" button -------------------------------------------


def _incident_in(dash) -> str:  # type: ignore[no-untyped-def]
    with dash.session() as s:
        _site(s, "http://127.0.0.1:8081")
        incident = _replay(s, "php2shell")
        assert incident is not None
        s.commit()
        return incident.id


def test_incident_page_and_ack(db_url: str) -> None:
    dash = make_dash(db_url)
    incident_id = _incident_in(dash)
    user = dash.login(UserRole.RESPONDER, name="Priya Responder")
    page = dash.client.get(f"/incidents/{incident_id}")
    assert page.status_code == 200
    assert "PHP 8.3.30 is affected; fixed in 8.3.36" in page.text
    assert "I&#39;m on it" in page.text or "I'm on it" in page.text

    r = dash.post(f"/incidents/{incident_id}/ack", page=f"/incidents/{incident_id}")
    assert r.status_code == 303
    after = dash.client.get(f"/incidents/{incident_id}").text
    assert "Acknowledged" in after
    assert "Priya Responder" in after  # the timeline names who acknowledged
    with dash.session() as s:
        ev = s.query(Event).filter_by(type="acknowledged").one()
        assert ev.actor_user_id == user.id
    assert dash.client.get("/incidents/does-not-exist").status_code == 404


def test_viewer_cannot_acknowledge(db_url: str) -> None:
    dash = make_dash(db_url)
    incident_id = _incident_in(dash)
    dash.login(UserRole.VIEWER)
    assert "I&#39;m on it" not in dash.client.get(f"/incidents/{incident_id}").text
    r = dash.post(f"/incidents/{incident_id}/ack", page=f"/incidents/{incident_id}")
    assert r.status_code == 403


@pytest.mark.parametrize("origin", ["https://evil.example", "null"])
def test_cross_site_ack_is_refused(db_url: str, origin: str) -> None:
    dash = make_dash(db_url)
    incident_id = _incident_in(dash)
    dash.login()
    r = dash.post(f"/incidents/{incident_id}/ack", headers={"origin": origin})
    assert r.status_code == 403


def test_ack_without_csrf_token_is_refused(db_url: str) -> None:
    dash = make_dash(db_url)
    incident_id = _incident_in(dash)
    dash.login()
    r = dash.client.post(f"/incidents/{incident_id}/ack", follow_redirects=False)
    assert r.status_code == 403
    r = dash.client.post(
        f"/incidents/{incident_id}/ack", data={"csrf_token": "wrong"}, follow_redirects=False
    )
    assert r.status_code == 403


def test_referrer_policy_keeps_our_own_origin(db_url: str) -> None:
    assert make_dash(db_url).client.get("/healthz").headers["referrer-policy"] == "same-origin"


def test_dashboard_needs_sign_in(db_url: str) -> None:
    r = make_dash(db_url).client.get("/incidents/abc", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login?next=/incidents/abc"


def test_prod_has_no_dev_sign_in(db_url: str) -> None:
    c = make_dash(db_url, env="prod").client
    assert c.get("/login").status_code == 404
    assert c.post("/login", data={"user_id": 1}).status_code == 404
    assert c.get("/incidents/anything").status_code == 401

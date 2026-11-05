"""The review queue, the advisory and feeds pages, grouping, and review alerts."""

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.alerts.mailer import MemoryMailer
from app.alerts.messages import new_incident, one_line
from app.enums import Exposure, Priority, ReviewStatus, UserRole
from app.models import Advisory, AuditLog, Incident
from app.services.advisories import (
    AdvisoryDataError,
    ingest_feed_advisory,
    ranges_to_text,
    text_to_affects,
)
from app.services.alerting import send_review_alerts, summarize
from app.services.incidents import apply_advisory
from app.settings import Settings
from tests.dashboard_helpers import Dash, make_dash
from tests.test_incidents import _site

UNSURE = {
    "title": "PHP: <script>alert(1)</script> in bccomp()",
    "aliases": ["GHSA-x692-q9x7-8c3f", "CVE-2026-17544"],
    "source_url": "https://github.com/php/php-src/security/advisories/GHSA-x692-q9x7-8c3f",
    "summary_text": "Out-of-bounds write. <img src=x onerror=alert(2)>",
    "review_reason": "it doesn't say whether some supported PHP branches are affected",
    "affects": [
        {
            "component_key": "php",
            "ranges": [
                {"introduced": "8.4.0", "fixed": "8.4.24"},
                {"introduced": "8.5.0", "fixed": "8.5.9"},
                {"introduced": "0", "limit": "8.2.0", "unsupported": True},
                {"introduced": "8.2.0", "limit": "8.4.0", "unsure": True},
            ],
            "fixed_versions": ["8.4.24", "8.5.9"],
        }
    ],
}


def _queue_item(session: Session) -> Advisory:
    result = ingest_feed_advisory(
        session, "ghsa", "GHSA-x692-q9x7-8c3f", UNSURE, ReviewStatus.CONFIRMED
    )
    assert result.advisory is not None
    return result.advisory


@pytest.fixture
def dash(db_url: str) -> Dash:
    return make_dash(db_url)


# --- range text ----------------------------------------------------------------------------------


def test_range_text_round_trip(session: Session) -> None:
    adv = _queue_item(session)
    assert adv.review_status is ReviewStatus.NEEDS_REVIEW  # unsure ranges force review
    text = ranges_to_text(adv)
    assert text.splitlines() == [
        "php: from 8.4.0 fixed 8.4.24",
        "php: from 8.5.0 fixed 8.5.9",
        "php: from 0 until 8.2.0 unsupported",
        "php: from 8.2.0 until 8.4.0 unsure",
    ]
    assert text_to_affects(text)[0]["ranges"] == UNSURE["affects"][0]["ranges"]
    plugin = text_to_affects("wp-plugin:hello-dolly: from 0 last 1.7.2\nwordpress: from 4.7")
    assert plugin[0] == {
        "component_key": "wp-plugin:hello-dolly",
        "ranges": [{"introduced": "0", "last_affected": "1.7.2"}],
        "fixed_versions": [],
    }
    assert plugin[1]["ranges"] == [{"introduced": "4.7"}]


@pytest.mark.parametrize(
    "line",
    [
        "php from 8.4.0 fixed 8.4.24",
        "php: 8.4.0 to 8.4.24",
        "php: from banana fixed 8.4.24",
        "wp-plugin:<script>: from 0 fixed 1.0",
        "php: from 8.4.0 fixed 8.4.24 extra",
        "php: from 8.4.0 until 8.5.0 maybe",
    ],
)
def test_range_text_refuses_bad_lines(line: str) -> None:
    with pytest.raises(AdvisoryDataError, match="Line 1"):
        text_to_affects(line)


# --- grouping and worst-of ---------------------------------------------------------------------


def _feed(session: Session, ghsa: str, fixed: str, cvss: float | None) -> Advisory:
    data = {
        "title": f"PHP: flaw {ghsa}",
        "aliases": [ghsa],
        "cvss_score": cvss,
        "affects": [
            {
                "component_key": "php",
                "ranges": [{"introduced": "8.3.0", "fixed": fixed}],
                "fixed_versions": [fixed],
            }
        ],
    }
    adv = ingest_feed_advisory(session, "ghsa", ghsa, data, ReviewStatus.CONFIRMED).advisory
    assert adv is not None
    apply_advisory(session, adv)
    return adv


def test_same_fix_same_incident_worst_score_wins(session: Session) -> None:
    _site(session, "http://127.0.0.1:8081")  # PHP 8.3.30
    _feed(session, "GHSA-aaaa-aaaa-aaaa", "8.3.35", 9.8)
    _feed(session, "GHSA-bbbb-bbbb-bbbb", "8.3.35", 3.1)  # lower score, applied last
    [incident] = session.scalars(select(Incident)).all()
    assert incident.title == "PHP: 2 security flaws, fixed in 8.3.35"
    [case] = incident.cases
    assert case.score_reasons[0] == "CVSS 9.8, critical (+40)"
    _feed(session, "GHSA-cccc-cccc-cccc", "8.3.33", 5.0)  # different fix: its own incident
    assert session.query(Incident).count() == 2


def test_one_advisory_saying_safe_never_verifies_another_ones_case(session: Session) -> None:
    from app.models import IncidentAdvisory

    site = _site(session, "http://127.0.0.1:8081")
    first = _feed(session, "GHSA-aaaa-aaaa-aaaa", "8.3.35", 9.8)
    [incident] = session.scalars(select(Incident)).all()
    # An advisory merged into the same incident by people, which the site is safe from.
    other = _feed(session, "GHSA-dddd-dddd-dddd", "8.3.20", 9.8)
    session.add(IncidentAdvisory(incident_id=incident.id, advisory_id=other.id))
    apply_advisory(session, other, [site])
    assert incident.cases[0].exposure is Exposure.VULNERABLE
    assert first.id != other.id


# --- review alerts -------------------------------------------------------------------------------


def test_review_alert_once_when_a_site_may_match(session: Session) -> None:
    settings = Settings(
        env="test", base_url="https://protect.example", alert_recipients="t@demo.test"
    )
    mail = MemoryMailer()
    adv = _queue_item(session)
    assert send_review_alerts(session, mail, settings) == 0  # no site yet: stays quiet
    _site(session, "http://127.0.0.1:8081")  # PHP 8.3.30: inside the "unsure" 8.2-8.4 range
    assert send_review_alerts(session, mail, settings) == 1
    assert send_review_alerts(session, mail, settings) == 0
    [msg] = mail.sent
    assert msg.subject.startswith("[Protect] Review needed: possible match on 1 site: PHP:")
    assert f"https://protect.example/advisories/{adv.id}" in msg.body
    assert "127.0.0.1" not in msg.body and "Site http" not in msg.body  # counts only
    assert session.query(Incident).count() == 0


def test_titles_with_line_breaks_cannot_break_alert_subjects(session: Session) -> None:
    _site(session, "http://127.0.0.1:8081")
    adv = _feed(session, "GHSA-aaaa-aaaa-aaaa", "8.3.35", 9.8)
    incident = session.scalars(select(Incident)).one()
    incident.title = "Evil\r\nBcc: x@evil.test"  # as if it slipped past ingest
    subject, body = new_incident(summarize(session, incident), "https://protect.example")
    assert "\n" not in subject and "\r" not in subject
    assert "Evil Bcc: x@evil.test" in body
    assert one_line("a b\x00c") == "a b c"
    assert adv.title == "PHP: flaw GHSA-aaaa-aaaa-aaaa"


# --- dashboard -----------------------------------------------------------------------------------


def test_review_queue_and_page_escape_feed_text(dash: Dash) -> None:
    with dash.session() as s:
        _site(s, "http://127.0.0.1:8081")
        adv = _queue_item(s)
        s.commit()
        adv_id = adv.id
    dash.login(UserRole.VIEWER)
    queue = dash.client.get("/advisories").text
    assert "Waiting for review" in queue and "1 site" in queue
    assert "<script>alert(1)</script>" not in queue
    assert "&lt;script&gt;" in queue
    page = dash.client.get(f"/advisories/{adv_id}").text
    assert "<img src=x" not in page and "&lt;img src=x" in page
    assert "php: from 8.2.0 until 8.4.0 unsure" in page
    assert 'name="ranges"' not in page  # viewers can't review
    assert dash.client.get("/").text.count("Possible match on 1 site") == 1


def test_confirm_needs_unsure_lines_settled_then_opens_an_incident(dash: Dash) -> None:
    with dash.session() as s:
        _site(s, "http://127.0.0.1:8081")
        adv_id = _queue_item(s).id
        s.commit()
    dash.login(UserRole.RESPONDER)
    page = f"/advisories/{adv_id}"
    with dash.session() as s:
        text = ranges_to_text(s.get_one(Advisory, adv_id))
    r = dash.post(f"{page}/review", {"action": "confirm", "ranges": text}, page=page)
    assert r.status_code == 400 and "Settle every" in r.text
    # The person decides 8.2 and 8.3 aren't affected... except they say 8.3 is, fixed in 8.3.33.
    settled = text.replace("php: from 8.2.0 until 8.4.0 unsure", "php: from 8.3.0 fixed 8.3.33")
    r = dash.post(
        f"{page}/review", {"action": "confirm", "ranges": settled, "note": "checked"}, page=page
    )
    assert r.status_code == 303 and r.headers["location"].startswith("/incidents/")
    with dash.session() as s:
        adv = s.get_one(Advisory, adv_id)
        assert adv.review_status is ReviewStatus.CONFIRMED and adv.reviewed_by is not None
        assert adv.group_key is not None
        [incident] = s.scalars(select(Incident)).all()
        assert incident.cases[0].exposure is Exposure.VULNERABLE
        assert incident.cases[0].fixed_version == "8.3.33"
        assert s.scalar(select(AuditLog).where(AuditLog.action == "advisory_confirmed"))


def test_reject_needs_a_note(dash: Dash) -> None:
    with dash.session() as s:
        adv_id = _queue_item(s).id
        s.commit()
    dash.login(UserRole.RESPONDER)
    page = f"/advisories/{adv_id}"
    assert dash.post(f"{page}/review", {"action": "reject"}, page=page).status_code == 400
    r = dash.post(f"{page}/review", {"action": "reject", "note": "covered by GHSA-…"}, page=page)
    assert r.status_code == 303
    with dash.session() as s:
        assert s.get_one(Advisory, adv_id).review_status is ReviewStatus.REJECTED
        assert s.query(Incident).count() == 0


def test_viewer_cannot_review_or_mark_exploited(dash: Dash) -> None:
    with dash.session() as s:
        adv_id = _queue_item(s).id
        s.commit()
    dash.login(UserRole.VIEWER)
    page = f"/advisories/{adv_id}"
    assert (
        dash.post(f"{page}/review", {"action": "reject", "note": "x"}, page=page).status_code == 403
    )
    assert (
        dash.post(f"{page}/exploited", {"exploited": "1", "note": "x"}, page=page).status_code
        == 403
    )


def test_mark_exploited_raises_priority(dash: Dash) -> None:
    with dash.session() as s:
        _site(s, "http://127.0.0.1:8081")
        adv = _feed(s, "GHSA-aaaa-aaaa-aaaa", "8.3.35", 9.2)
        s.commit()
        adv_id = adv.id
        assert s.scalars(select(Incident)).one().priority is Priority.P3  # 9.2: +40
    dash.login(UserRole.RESPONDER)
    page = f"/advisories/{adv_id}"
    assert dash.post(f"{page}/exploited", {"exploited": "1"}, page=page).status_code == 400
    r = dash.post(f"{page}/exploited", {"exploited": "1", "note": "watchTowr report"}, page=page)
    assert r.status_code == 303
    with dash.session() as s:
        incident = s.scalars(select(Incident)).one()
        assert incident.priority is Priority.P1  # +30 = 70
        assert "credible reports of exploitation (+30)" in incident.cases[0].score_reasons


def test_feeds_page_renders(dash: Dash) -> None:
    dash.login(UserRole.VIEWER)
    page = dash.client.get("/feeds").text
    assert "GitHub php-src security advisories" in page
    assert "off: needs an API key" in page
    assert "No runs yet" in page

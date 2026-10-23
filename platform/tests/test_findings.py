"""Step 10: file-check findings, warning signs on open cases, dashboard views."""

import copy
from typing import Any

import pytest
from sqlalchemy.orm import Session

from app.api.schemas import Report as ReportPayload
from app.enums import UserRole
from app.models import Event, Report, Site
from app.services.findings import HIGH, INFO, LOW, MEDIUM, findings_for, latest_findings
from app.services.inventory import apply_report
from tests.api.helpers import report as sample_report
from tests.dashboard_helpers import make_dash
from tests.test_incidents import _replay, _site


def _report(checks: dict[str, Any] | None = None, **top: Any) -> Report:
    data = sample_report(**top)
    if checks:
        data["checks"] = {**data["checks"], **checks}
    return Report(payload=ReportPayload.model_validate(data).model_dump(mode="json", by_alias=True))


def _keys(findings) -> dict[str, str]:  # type: ignore[no-untyped-def]
    return {f.key: f.level for f in findings}


SITE = Site(business_name="Demo", url="http://127.0.0.1:8081", mu_plugin_allowlist=[])


def test_clean_scan_has_no_warning_signs() -> None:
    assert not [f for f in findings_for(SITE, _report()) if f.is_warning]


@pytest.mark.parametrize(
    ("checks", "key", "level"),
    [
        ({"uploads_php": ["wp-content/uploads/2026/10/x.php"]}, "uploads_php", HIGH),
        (
            {
                "core": {
                    "status": "mismatch",
                    "modified": ["wp-includes/version.php"],
                    "unexpected": [],
                }
            },
            "core_modified",
            HIGH,
        ),
        (
            {
                "core": {
                    "status": "mismatch",
                    "modified": [],
                    "unexpected": ["wp-admin/css/shell.php"],
                }
            },
            "core_unexpected",
            HIGH,
        ),
        (
            {
                "plugins": [
                    {
                        "slug": "contact-form-7",
                        "status": "mismatch",
                        "modified": ["wp-content/plugins/contact-form-7/x.php"],
                    }
                ]
            },
            "plugin:contact-form-7",
            HIGH,
        ),
        (
            {"plugins": [{"slug": "acme-pro", "status": "unverifiable", "modified": []}]},
            "plugins_unverifiable",
            INFO,
        ),
        (
            {"auto_prepend": {"set": True, "location": "wp-content/cache/x.php"}},
            "auto_prepend",
            MEDIUM,
        ),
        ({"user_ini": [".user.ini"]}, "user_ini", MEDIUM),
        ({"mu_plugins_present": ["wp-content/mu-plugins/loader.php"]}, "mu_unknown", MEDIUM),
        ({"recent_php_changes": ["wp-content/themes/astra/functions.php"]}, "recent_php", LOW),
        (
            {"core": {"status": "unavailable", "modified": [], "unexpected": []}},
            "core_unavailable",
            INFO,
        ),
    ],
)
def test_each_check_becomes_a_finding(checks: dict, key: str, level: str) -> None:
    findings = _keys(findings_for(SITE, _report(checks)))
    assert findings.get(key) == level


def test_wordfence_prepend_gets_a_hint() -> None:
    [f] = [
        f
        for f in findings_for(
            SITE, _report({"auto_prepend": {"set": True, "location": "wordfence-waf.php"}})
        )
        if f.key == "auto_prepend"
    ]
    assert "Wordfence" in f.advice


def test_allowlisted_mu_plugin_is_not_a_finding() -> None:
    site = Site(
        business_name="D",
        url="http://x.test",
        mu_plugin_allowlist=["wp-content/mu-plugins/wpengine-common.php"],
    )
    r = _report({"mu_plugins_present": ["wp-content/mu-plugins/wpengine-common.php"]})
    assert "mu_unknown" not in _keys(findings_for(site, r))


def test_recent_changes_from_an_update_are_ignored() -> None:
    before = _report()
    after_data = sample_report()
    after_data["themes"] = [{"slug": "twentytwentyfive", "version": "1.6", "active": True}]
    after_data["checks"] = {
        **after_data["checks"],
        "recent_php_changes": [
            "wp-content/themes/twentytwentyfive/functions.php",
            "wp-content/themes/other/evil.php",
        ],
    }
    after = Report(
        payload=ReportPayload.model_validate(after_data).model_dump(mode="json", by_alias=True)
    )
    [recent] = [f for f in findings_for(SITE, after, before) if f.key == "recent_php"]
    assert recent.paths == ("wp-content/themes/other/evil.php",)


def test_unfinished_scan_says_so_and_nothing_else() -> None:
    r = _report(
        {
            "scan": {"complete": False, "finished_at": None},
            "uploads_php": ["wp-content/uploads/x.php"],
        }
    )
    assert _keys(findings_for(SITE, r)) == {"scan_pending": INFO}


# --- Warning signs land on open cases --------------------------------------------------------


def _send_checks(session: Session, site: Site, **checks: Any) -> None:
    data = sample_report(site_url=site.url)
    data["checks"] = {**copy.deepcopy(data["checks"]), **checks}
    apply_report(session, site, ReportPayload.model_validate(data))
    session.flush()


def test_new_warning_signs_are_noted_on_open_cases(session: Session) -> None:
    site = _site(session, "http://127.0.0.1:8081")
    incident = _replay(session, "php2shell")
    assert incident is not None
    _send_checks(session, site, uploads_php=["wp-content/uploads/test.php"])
    ev = session.query(Event).filter_by(type="warning_signs").one()
    assert ev.case_id == incident.cases[0].id
    assert "PHP files in the uploads folder (1)" in ev.note
    # the same finding again is not news
    _send_checks(
        session,
        site,
        uploads_php=["wp-content/uploads/test.php"],
        recent_php_changes=["wp-content/themes/a/b.php"],
    )
    assert session.query(Event).filter_by(type="warning_signs").count() == 1
    # a second file is
    _send_checks(
        session, site, uploads_php=["wp-content/uploads/test.php", "wp-content/uploads/2026/x.php"]
    )
    assert session.query(Event).filter_by(type="warning_signs").count() == 2


def test_no_open_case_means_no_events(session: Session) -> None:
    site = _site(session, "https://quiet.example", php="8.3.36")
    _send_checks(session, site, uploads_php=["wp-content/uploads/test.php"])
    assert session.query(Event).filter_by(type="warning_signs").count() == 0
    assert any(f.key == "uploads_php" for f in latest_findings(session, site))


# --- Dashboard -----------------------------------------------------------------------------------


def _dash_site(db_url: str, **checks: Any):  # type: ignore[no-untyped-def]
    dash = make_dash(db_url)
    with dash.session() as s:
        site = _site(s, "http://127.0.0.1:8081")
        incident = _replay(s, "php2shell")
        if checks:
            _send_checks(s, site, **checks)
        s.commit()
        return dash, site.id, incident.cases[0].id  # type: ignore[union-attr]


def test_site_page_without_warnings_never_says_clean(db_url: str) -> None:
    dash, site_id, _ = _dash_site(db_url)
    dash.login()
    text = dash.client.get(f"/sites/{site_id}").text
    assert "No warning signs found" in text
    assert (
        "doesn&#39;t prove the site is clean" in text or "doesn't prove the site is clean" in text
    )


def test_findings_on_site_case_and_overview(db_url: str) -> None:
    dash, site_id, case_id = _dash_site(db_url, uploads_php=["wp-content/uploads/test.php"])
    dash.login()
    assert "wp-content/uploads/test.php" in dash.client.get(f"/sites/{site_id}").text
    case_page = dash.client.get(f"/cases/{case_id}").text
    assert "file checks show warning signs" in case_page
    assert "PHP files in the uploads folder (1)" in case_page
    assert "Sites with warning signs" in dash.client.get("/").text


def test_hostile_paths_are_escaped(db_url: str) -> None:
    dash, site_id, _ = _dash_site(db_url, uploads_php=["wp-content/uploads/<script>x</script>.php"])
    dash.login()
    text = dash.client.get(f"/sites/{site_id}").text
    assert "<script>x</script>" not in text
    assert "&lt;script&gt;x&lt;/script&gt;" in text


def test_admin_can_mark_mu_plugin_expected(db_url: str) -> None:
    mu = "wp-content/mu-plugins/wpengine-common.php"
    dash, site_id, _ = _dash_site(db_url, mu_plugins_present=[mu])
    dash.login(UserRole.RESPONDER)
    assert (
        dash.post(f"/sites/{site_id}/allow-mu", {"path": mu}, page=f"/sites/{site_id}").status_code
        == 403
    )
    dash.client.cookies.clear()
    dash.login(UserRole.ADMIN)
    assert "Mark as expected" in dash.client.get(f"/sites/{site_id}").text
    r = dash.post(f"/sites/{site_id}/allow-mu", {"path": mu}, page=f"/sites/{site_id}")
    assert r.status_code == 303
    assert "Must-use plugins not on this site" not in dash.client.get(f"/sites/{site_id}").text

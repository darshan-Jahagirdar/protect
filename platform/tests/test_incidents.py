import copy
from typing import Any

import pytest
from sqlalchemy.orm import Session

from app.api.schemas import Report as ReportPayload
from app.enums import Exposure, IncidentStatus, Priority, ReviewStatus, SiteStatus
from app.models import Case, Event, Incident, Site
from app.services.advisories import AdvisoryDataError, load_fixture, upsert_advisory
from app.services.enrollment import create_site
from app.services.incidents import apply_advisory, rematch_site
from app.services.inventory import apply_report
from tests.api.helpers import report


def _site(session: Session, url: str, **report_changes: Any) -> Site:
    site = create_site(session, f"Site {url}", url)
    site.status = SiteStatus.ACTIVE
    send(session, site, url=url, **report_changes)
    return site


def send(
    session: Session,
    site: Site,
    url: str | None = None,
    php: str | None = None,
    os: dict | None = None,
    plugins: list | None = None,
) -> None:
    data = report(site_url=url or site.url)
    if php is not None:
        major, minor, rest = php.split(".", 2)
        release = "".join(ch for ch in rest.split("-")[0] if ch.isdigit())
        data["php"] = {
            **data["php"],
            "version": php,
            "major": int(major),
            "minor": int(minor),
            "release": int(release),
            "extra": php[len(f"{major}.{minor}.{release}") :],
        }
    if os is not None:
        data["os"] = os
    if plugins is not None:
        data["plugins"] = plugins
    apply_report(session, site, ReportPayload.model_validate(data))
    session.flush()


def _replay(session: Session, name: str) -> Incident | None:
    return apply_advisory(session, upsert_advisory(session, load_fixture(name)))


def _events(session: Session, incident: Incident) -> list[str]:
    return [
        e.type for e in session.query(Event).filter_by(incident_id=incident.id).order_by(Event.id)
    ]


# --- PHP2Shell replay --------------------------------------------------------------


def test_php2shell_opens_p1_incident_for_vulnerable_site(session: Session) -> None:
    site = _site(session, "http://127.0.0.1:8081")  # sample report: PHP 8.3.30 upstream
    incident = _replay(session, "php2shell")
    assert incident is not None
    assert incident.priority is Priority.P1
    assert incident.kind == "php-core"
    assert incident.status is IncidentStatus.OPEN
    assert not incident.drill

    [case] = incident.cases
    assert case.site_id == site.id
    assert case.component_key == "php"
    assert case.exposure is Exposure.VULNERABLE
    assert case.score == 80
    assert case.version_seen == "8.3.30"
    assert case.fixed_version == "8.3.36"
    assert case.match_reasons == ["PHP 8.3.30 is affected; fixed in 8.3.36"]
    assert case.score_reasons == [
        "CVSS 9.2, critical (+40)",
        "credible reports of exploitation (+30)",
        "attackable remotely without a login (+10)",
    ]
    assert _events(session, incident) == ["incident_opened", "case_opened"]


def test_patched_site_gets_no_case_and_nothing_opens(session: Session) -> None:
    _site(session, "https://patched.example", php="8.3.36")
    assert _replay(session, "php2shell") is None
    assert session.query(Incident).count() == 0


def test_mixed_sites(session: Session) -> None:
    _site(session, "https://vuln.example", php="8.2.20")
    _site(session, "https://patched.example", php="8.4.27")
    _site(session, "https://eol.example", php="7.4.33")
    _site(
        session,
        "https://alma.example",
        php="8.3.30",
        os={"id": "almalinux", "id_like": "rhel centos fedora", "version_id": "9.4"},
    )
    _site(
        session,
        "https://ubuntu.example",
        php="8.1.2-1ubuntu2.20",
        os={"id": "ubuntu", "id_like": "debian", "version_id": "22.04"},
    )
    incident = _replay(session, "php2shell")
    assert incident is not None
    by_url = {c.site.url: c for c in incident.cases}
    assert set(by_url) == {
        "https://vuln.example",
        "https://eol.example",
        "https://alma.example",
        "https://ubuntu.example",
    }
    assert by_url["https://vuln.example"].exposure is Exposure.VULNERABLE
    assert by_url["https://eol.example"].unsupported_branch
    assert by_url["https://eol.example"].fixed_version is None
    assert by_url["https://alma.example"].exposure is Exposure.NEEDS_CHECK
    assert by_url["https://ubuntu.example"].exposure is Exposure.NEEDS_CHECK  # no Ubuntu data
    # needs_check scores the same as vulnerable (DESIGN.md §4.6)
    assert {c.score for c in incident.cases} == {80}


def test_replaying_twice_does_not_duplicate(session: Session) -> None:
    _site(session, "http://127.0.0.1:8081")
    first = _replay(session, "php2shell")
    second = _replay(session, "php2shell")
    assert first is not None and second is not None
    assert first.id == second.id
    assert session.query(Incident).count() == 1
    assert session.query(Case).count() == 1
    assert _events(session, first) == ["incident_opened", "case_opened"]


def test_inactive_and_removed_sites_are_ignored(session: Session) -> None:
    site = _site(session, "https://gone.example")
    site.status = SiteStatus.REMOVED
    pending = create_site(session, "Pending", "https://pending.example")
    assert pending.status is SiteStatus.PENDING
    assert _replay(session, "php2shell") is None


def test_needs_review_advisory_opens_nothing(session: Session) -> None:
    _site(session, "http://127.0.0.1:8081")
    adv = upsert_advisory(session, load_fixture("php2shell"), ReviewStatus.NEEDS_REVIEW)
    assert apply_advisory(session, adv) is None


def test_risk_tags_raise_the_score(session: Session) -> None:
    site = _site(session, "https://shop.example")
    site.risk_tags = ["ecommerce"]
    incident = _replay(session, "php2shell")
    assert incident is not None
    assert incident.cases[0].score == 90


# --- Drill advisory --------------------------------------------------------------------


def test_drill_plugin_advisory(session: Session) -> None:
    _site(session, "http://127.0.0.1:8081")  # sample has hello-dolly installed but inactive
    incident = _replay(session, "drill-plugin")
    assert incident is not None
    assert incident.drill
    assert incident.kind == "wp-plugin"
    [case] = incident.cases
    assert case.component_key == "wp-plugin:hello-dolly"
    assert case.exposure is Exposure.VULNERABLE
    assert case.score == 25
    assert case.priority is Priority.P4
    assert "component is inactive (-10)" in case.score_reasons
    assert any("inactive" in r for r in case.match_reasons)


# --- Re-matching after new reports ---------------------------------------------------


def test_new_report_with_vulnerable_plugin_joins_open_incident(session: Session) -> None:
    site = _site(session, "http://127.0.0.1:8081", plugins=[])
    other = _site(session, "https://other.example")
    incident = _replay(session, "drill-plugin")
    assert incident is not None
    assert [c.site_id for c in incident.cases] == [other.id]

    send(session, site, plugins=[{"slug": "hello-dolly", "version": "1.7.2", "active": True}])
    session.refresh(incident)
    assert {c.site_id for c in incident.cases} == {site.id, other.id}
    new_case = next(c for c in incident.cases if c.site_id == site.id)
    assert new_case.score == 35  # active this time, so no -10


def test_patch_verifies_the_case_automatically(session: Session) -> None:
    site = _site(session, "http://127.0.0.1:8081")
    incident = _replay(session, "php2shell")
    assert incident is not None
    send(session, site, php="8.3.36")
    [case] = incident.cases
    assert case.exposure is Exposure.VERIFIED
    assert case.version_seen == "8.3.36"
    assert case.fixed_version == "8.3.36"  # kept, so the page still says what the fix was
    assert case.match_reasons == ["PHP 8.3.36 is outside the affected ranges"]
    assert incident.status is IncidentStatus.MONITORING
    assert _events(session, incident)[-2:] == ["verified", "all_sites_resolved"]
    send(session, site, php="8.3.37")  # another safe report: nothing new
    assert _events(session, incident).count("verified") == 1


def test_human_decisions_are_never_overwritten(session: Session) -> None:
    site = _site(session, "http://127.0.0.1:8081")
    incident = _replay(session, "php2shell")
    assert incident is not None
    case = incident.cases[0]
    case.exposure = Exposure.ACCEPTED_RISK
    rematch_site(session, site)
    assert case.exposure is Exposure.ACCEPTED_RISK


def test_downgrade_after_verify_reopens_case(session: Session) -> None:
    site = _site(session, "http://127.0.0.1:8081")
    incident = _replay(session, "php2shell")
    assert incident is not None
    case = incident.cases[0]
    case.exposure = Exposure.VERIFIED
    send(session, site, php="8.3.29")
    assert case.exposure is Exposure.VULNERABLE
    assert "case_reopened" in _events(session, incident)


def test_uninstalling_the_component_verifies_the_case(session: Session) -> None:
    site = _site(session, "http://127.0.0.1:8081")
    incident = _replay(session, "drill-plugin")
    assert incident is not None
    send(session, site, plugins=[])
    [case] = incident.cases
    assert case.exposure is Exposure.VERIFIED
    assert case.match_reasons == ["wp-plugin:hello-dolly is no longer installed"]
    assert incident.status is IncidentStatus.MONITORING


# --- Advisory data -------------------------------------------------------------------


def test_upsert_merges_on_shared_alias(session: Session) -> None:
    data = load_fixture("php2shell")
    a = upsert_advisory(session, data)
    partial = copy.deepcopy(data)
    partial["aliases"] = ["CVE-2026-109619", "EXTRA-1"]
    b = upsert_advisory(session, partial)
    assert a.id == b.id
    assert "EXTRA-1" in b.aliases and "GHSA-w8hw-w9fx-j79w" in b.aliases


@pytest.mark.parametrize("name", ["../secrets", "php2shell.json", "nope"])
def test_unknown_fixture_names_rejected(name: str) -> None:
    with pytest.raises(AdvisoryDataError):
        load_fixture(name)


def test_invalid_component_key_in_advisory_rejected(session: Session) -> None:
    data = load_fixture("drill-plugin")
    data["affects"][0]["component_key"] = "wp-plugin:<script>"
    with pytest.raises(AdvisoryDataError):
        upsert_advisory(session, data)

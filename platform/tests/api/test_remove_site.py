"""Removing a site (client left, or added by mistake): it stops counting, its history stays,
and it can't be used to hide an open problem."""

from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from app import cli
from app.db import Base, make_engine
from app.enums import Exposure, SiteStatus, UserRole
from app.feeds.runner import FeedContext
from app.feeds.wordfence import installed_keys
from app.models import Case, EnrollmentCode, Report, Site
from app.services.advisories import load_fixture, upsert_advisory
from app.services.enrollment import issue_code
from app.services.incidents import apply_advisory, rematch_site
from app.services.sites import SiteRemovalError, remove_site
from app.settings import Settings
from tests.api.conftest import Env
from tests.api.helpers import FakePlugin, body_of, report
from tests.dashboard_helpers import make_dash
from tests.test_incidents import _site, send

URL = "http://127.0.0.1:8081"


def _send(env: Env, plugin: FakePlugin) -> int:
    body = body_of(report())
    return env.client.post("/api/v1/report", content=body, headers=plugin.headers(body)).status_code


def _enroll(env: Env, plugin: FakePlugin, code: str) -> int:
    body = plugin.enroll_body(code)
    return env.client.post(
        "/api/v1/enroll", content=body, headers=plugin.headers(body, with_key=False)
    ).status_code


# --- What removal does -----------------------------------------------------------------


def test_removed_site_reports_are_refused_and_it_cant_reenroll(
    env: Env, enrolled: FakePlugin
) -> None:
    assert _send(env, enrolled) == 204
    with env.db() as s:
        site = s.query(Site).one()
        stale_code = issue_code(s, site, 24)
        remove_site(s, site)
        s.commit()
        assert s.query(EnrollmentCode).filter_by(used_at=None).count() == 0

    assert _send(env, enrolled) == 401
    assert _enroll(env, FakePlugin(), stale_code) == 403
    site = env.site()
    assert site.status is SiteStatus.REMOVED and site.public_key is None
    with env.db() as s:  # history kept
        assert s.query(Report).count() == 1


def test_removed_site_is_left_out_of_matching_and_wordfence(session: Session) -> None:
    site = _site(session, URL, php="8.3.30")
    remove_site(session, site)
    assert apply_advisory(session, upsert_advisory(session, load_fixture("php2shell"))) is None
    assert session.query(Case).count() == 0

    ctx = FeedContext(session, None, Settings(env="test"), None)  # type: ignore[arg-type]
    assert installed_keys(ctx) == {"wordpress"}


def test_wordfence_still_sees_active_sites(session: Session) -> None:
    _site(session, URL)
    ctx = FeedContext(session, None, Settings(env="test"), None)  # type: ignore[arg-type]
    assert "wp-plugin:hello-dolly" in installed_keys(ctx)


# --- What removal refuses -------------------------------------------------------------


def test_refused_while_a_case_is_unresolved(session: Session) -> None:
    site = _site(session, URL, php="8.3.30")
    incident = apply_advisory(session, upsert_advisory(session, load_fixture("php2shell")))
    assert incident is not None
    [case] = incident.cases
    assert case.exposure is Exposure.VULNERABLE

    with pytest.raises(SiteRemovalError, match="1 unresolved case"):
        remove_site(session, site)
    assert site.status is SiteStatus.ACTIVE

    send(session, site, php="8.3.36")  # patched: the case verifies on its own
    rematch_site(session, site)
    session.refresh(case)
    assert case.exposure is Exposure.VERIFIED
    remove_site(session, site)
    assert site.status is SiteStatus.REMOVED


def test_refused_twice(session: Session) -> None:
    site = _site(session, URL)
    remove_site(session, site)
    with pytest.raises(SiteRemovalError, match="already removed"):
        remove_site(session, site)


# --- The CLI ------------------------------------------------------------------------------


@pytest.fixture
def cli_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> sessionmaker[Session]:
    engine = make_engine(f"sqlite:///{tmp_path / 'cli.sqlite'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(cli, "SessionLocal", factory)
    with factory() as s:
        _site(s, URL)
        s.commit()
    return factory


def test_cli_needs_the_matching_url(
    cli_db: sessionmaker[Session], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["remove-site", "--site-id", "1", "--url", "https://other.example"]) == 1
    assert "nothing removed" in capsys.readouterr().err
    assert cli.main(["remove-site", "--site-id", "99", "--url", URL]) == 1
    with cli_db() as s:
        assert s.get(Site, 1).status is SiteStatus.ACTIVE


def test_cli_removes_then_refuses_a_new_code(
    cli_db: sessionmaker[Session], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["remove-site", "--site-id", "1", "--url", URL + "/"]) == 0
    assert "Removed site #1" in capsys.readouterr().out
    with cli_db() as s:
        assert s.get(Site, 1).status is SiteStatus.REMOVED

    assert cli.main(["remove-site", "--site-id", "1", "--url", URL]) == 1
    assert "already removed" in capsys.readouterr().err
    assert cli.main(["new-code", "--site-id", "1"]) == 1
    assert "can't be reconnected" in capsys.readouterr().err
    with cli_db() as s:
        assert s.query(EnrollmentCode).count() == 0


# --- The dashboard ------------------------------------------------------------------------


def test_dashboard_shows_a_removed_site_but_offers_no_actions(db_url: str) -> None:
    dash = make_dash(db_url)
    with dash.session() as s:
        site = _site(s, URL)
        remove_site(s, site)
        s.commit()
        site_id = site.id
    dash.client.app.state.observe = None  # type: ignore[attr-defined]  # must never be called
    dash.login(UserRole.ADMIN)

    page = dash.client.get(f"/sites/{site_id}").text
    assert "Removed: Protect no longer watches this site" in page
    assert f"/sites/{site_id}/observe" not in page and f"/sites/{site_id}/code" not in page
    assert "removed" in dash.client.get("/sites").text
    assert f"/sites/{site_id}" not in dash.client.get("/").text  # not on the overview

    page_url = f"/sites/{site_id}"
    assert dash.post(f"/sites/{site_id}/observe", page=page_url).status_code == 400
    assert dash.post(f"/sites/{site_id}/code", page=page_url).status_code == 400

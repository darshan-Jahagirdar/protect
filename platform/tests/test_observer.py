"""Step 11: the observer (public page view), its safety rules, and the cross-check."""

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy.orm import Session

from app.db import utcnow
from app.enums import UserRole
from app.models import Event, Observation
from app.observer.observe import USER_AGENT, BlockedTarget, ObservationResult, check_target, observe
from app.services.cases import checklist
from app.services.observations import (
    disagreement,
    edge_status,
    observe_due,
    observe_site,
    public_php_version,
    tls_warning,
)
from app.settings import Settings
from tests.dashboard_helpers import make_dash
from tests.test_incidents import _replay, _site

PUBLIC = lambda host: ["93.184.216.34"]  # noqa: E731  (a public address)


class BodyTripwire(httpx.SyncByteStream):
    """Fails the test if anyone reads the response body."""

    read = False

    def __iter__(self):  # type: ignore[no-untyped-def]
        BodyTripwire.read = True
        yield b"<html>secret page body</html>"


def _client(routes: dict[str, httpx.Response], seen: list[httpx.Request]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        resp = routes[str(request.url)]
        return httpx.Response(resp.status_code, headers=resp.headers, stream=BodyTripwire())

    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


# --- The request itself ----------------------------------------------------------------------


def test_one_get_of_the_homepage_headers_only() -> None:
    BodyTripwire.read = False
    seen: list[httpx.Request] = []
    client = _client(
        {
            "https://shop.example/": httpx.Response(
                200,
                headers={
                    "server": "cloudflare",
                    "cf-ray": "8a1b2c3d4e5f-BOM",
                    "x-powered-by": "PHP/8.3.30",
                },
            )
        },
        seen,
    )
    r = observe(
        "https://shop.example",
        client=client,
        resolve=PUBLIC,
        get_tls_expiry=lambda h, p: datetime(2027, 1, 1, tzinfo=UTC),
    )
    [req] = seen
    assert (req.method, req.url.path) == ("GET", "/")
    assert req.headers["user-agent"] == USER_AGENT
    assert not req.headers.get("cookie") and not req.headers.get("authorization")
    assert not BodyTripwire.read, "the observer must never read the page body"
    assert (r.http_status, r.server_header, r.powered_by) == (200, "cloudflare", "PHP/8.3.30")
    assert r.behind_cloudflare is True
    assert r.tls_expires_at == datetime(2027, 1, 1, tzinfo=UTC)


def test_follows_up_to_three_redirects() -> None:
    seen: list[httpx.Request] = []
    routes = {
        "http://shop.example/": httpx.Response(301, headers={"location": "https://shop.example/"}),
        "https://shop.example/": httpx.Response(302, headers={"location": "/en/"}),
        "https://shop.example/en/": httpx.Response(200, headers={"server": "nginx"}),
    }
    r = observe(
        "http://shop.example",
        client=_client(routes, seen),
        resolve=PUBLIC,
        get_tls_expiry=lambda h, p: None,
    )
    assert [str(q.url) for q in seen] == list(routes)
    assert r.final_url == "https://shop.example/en/" and r.http_status == 200
    assert r.behind_cloudflare is False


def test_gives_up_after_too_many_redirects() -> None:
    seen: list[httpx.Request] = []
    routes = {
        f"https://loop.example/{i}": httpx.Response(302, headers={"location": f"/{i + 1}"})
        for i in range(10)
    }
    routes["https://loop.example/"] = httpx.Response(302, headers={"location": "/0"})
    r = observe("https://loop.example", client=_client(routes, seen), resolve=PUBLIC)
    assert r.error == "too many redirects"
    assert len(seen) == 4  # the first request + 3 redirects


@pytest.mark.parametrize(
    "location",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/",
        "http://localhost:8000/",
        "file:///etc/passwd",
        "ftp://shop.example/",
    ],
)
def test_redirects_into_private_networks_are_blocked(location: str) -> None:
    seen: list[httpx.Request] = []
    routes = {"https://shop.example/": httpx.Response(302, headers={"location": location})}

    def resolve(host: str) -> list[str]:
        return {"shop.example": ["93.184.216.34"], "localhost": ["127.0.0.1"]}.get(host, [host])

    r = observe("https://shop.example", client=_client(routes, seen), resolve=resolve)
    assert r.error and r.error.startswith("blocked")
    assert len(seen) == 1  # never requested the redirect target


@pytest.mark.parametrize(
    "addr",
    ["127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "::1", "fd00::1", "100.64.0.1"],
)
def test_non_public_addresses_blocked_in_prod(addr: str) -> None:
    with pytest.raises(BlockedTarget):
        check_target("http://x.example/", allow_private=False, resolve=lambda h: [addr])
    check_target("http://x.example/", allow_private=True, resolve=lambda h: [addr])  # dev demo


def test_tls_and_network_errors_are_recorded() -> None:
    seen: list[httpx.Request] = []
    client = _client({"https://shop.example/": httpx.Response(200)}, seen)

    def broken(host: str, port: int) -> datetime:
        raise OSError("handshake failed")

    r = observe("https://shop.example", client=client, resolve=PUBLIC, get_tls_expiry=broken)
    assert r.http_status == 200 and r.error == "TLS check failed: OSError"

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    down = httpx.Client(transport=httpx.MockTransport(refuse))
    assert observe("https://down.example", client=down, resolve=PUBLIC).error == (
        "request failed: ConnectError"
    )


def test_demo_rewrite_keeps_the_public_host() -> None:
    seen: list[httpx.Request] = []
    routes = {"http://wp-vuln/": httpx.Response(200, headers={"x-powered-by": "PHP/8.3.36"})}

    def rewrite(url: str) -> tuple[str, str | None]:
        return url.replace("http://127.0.0.1:8081", "http://wp-vuln"), "127.0.0.1:8081"

    r = observe(
        "http://127.0.0.1:8081", client=_client(routes, seen), allow_private=True, rewrite=rewrite
    )
    assert seen[0].headers["host"] == "127.0.0.1:8081"
    assert r.final_url == "http://127.0.0.1:8081/" and r.powered_by == "PHP/8.3.36"


def test_observer_source_only_ever_sends_get() -> None:
    """Rule R10, checked in the source: no other method, no body reads."""
    src = (Path(__file__).resolve().parents[1] / "app" / "observer" / "observe.py").read_text()
    assert re.findall(r'client\.stream\("(\w+)"', src) == ["GET"]
    for forbidden in [
        ".post(",
        ".put(",
        ".patch(",
        ".delete(",
        ".request(",
        ".read()",
        ".text",
        ".json(",
        ".content",
        "iter_bytes",
        "iter_text",
        "iter_raw",
    ]:
        assert forbidden not in src, forbidden


# --- Storing and cross-checking ------------------------------------------------------------------


def _fake(
    powered_by: str | None = "PHP/8.3.30",
    cloudflare: bool | None = False,
    tls: datetime | None = None,
):  # type: ignore[no-untyped-def]
    calls: list[str] = []

    def fn(url: str, allow_private: bool = False, rewrite=None) -> ObservationResult:  # type: ignore[no-untyped-def]
        calls.append(rewrite(url)[0] if rewrite else url)
        return ObservationResult(url, 200, "Apache", powered_by, cloudflare, tls)

    fn.calls = calls  # type: ignore[attr-defined]
    return fn


def test_public_php_parsing() -> None:
    assert public_php_version(Observation(powered_by="PHP/8.3.36")) == "8.3.36"
    assert public_php_version(Observation(powered_by="PHP/8.1.2-1ubuntu2.20")) == "8.1.2"
    assert public_php_version(Observation(powered_by="ASP.NET")) is None
    assert public_php_version(None) is None


def test_agreement_means_no_event(session: Session) -> None:
    site = _site(session, "http://127.0.0.1:8081")  # plugin reports 8.3.30
    _replay(session, "php2shell")
    obs = observe_site(session, site, Settings(env="test"), observe_fn=_fake("PHP/8.3.30"))
    assert disagreement(session, site, obs) is None
    assert session.query(Event).filter_by(type="public_view_disagrees").count() == 0


def test_disagreement_is_noted_on_open_cases_once(session: Session) -> None:
    site = _site(session, "http://127.0.0.1:8081")  # the plugin says 8.3.30...
    incident = _replay(session, "php2shell")
    assert incident is not None
    fake = _fake("PHP/8.3.29")  # ...but the server announces something else
    obs = observe_site(session, site, Settings(env="test"), observe_fn=fake)
    msg = disagreement(session, site, obs)
    assert msg == "the web server announces PHP 8.3.29, but the plugin reports PHP 8.3.30"
    ev = session.query(Event).filter_by(type="public_view_disagrees").one()
    assert ev.case_id == incident.cases[0].id and ev.note == msg
    observe_site(session, site, Settings(env="test"), observe_fn=fake)  # same story again
    assert session.query(Event).filter_by(type="public_view_disagrees").count() == 1


def test_hidden_version_is_not_a_disagreement(session: Session) -> None:
    site = _site(session, "http://127.0.0.1:8081")
    obs = observe_site(session, site, Settings(env="test"), observe_fn=_fake(None))
    assert disagreement(session, site, obs) is None


def test_demo_rewrite_only_outside_prod(session: Session) -> None:
    site = _site(session, "http://127.0.0.1:8081")
    fake = _fake()
    dev = Settings(env="test", observer_rewrites="http://127.0.0.1:8081=http://wp-vuln")
    observe_site(session, site, dev, observe_fn=fake)
    prod = Settings(
        env="prod",
        base_url="https://p.example",
        secret_key="x" * 40,
        observer_rewrites="http://127.0.0.1:8081=http://wp-vuln",
    )
    observe_site(session, site, prod, observe_fn=fake)
    assert fake.calls == ["http://wp-vuln", "http://127.0.0.1:8081"]  # type: ignore[attr-defined]


def test_schedule_daily_and_every_30_minutes_when_urgent(session: Session) -> None:
    quiet = _site(session, "https://quiet.example", php="8.3.36")
    busy = _site(session, "http://127.0.0.1:8081")
    _replay(session, "php2shell")  # P1 for the busy site only
    fake, s, t0 = _fake(), Settings(env="test"), utcnow()
    assert observe_due(session, s, now=t0, observe_fn=fake) == 2
    assert observe_due(session, s, now=t0 + timedelta(minutes=29), observe_fn=fake) == 0
    assert observe_due(session, s, now=t0 + timedelta(minutes=31), observe_fn=fake) == 1
    assert observe_due(session, s, now=t0 + timedelta(hours=25), observe_fn=fake) == 2
    assert {quiet.id, busy.id}  # both observed at some point


def test_old_observations_are_pruned(session: Session) -> None:
    site = _site(session, "http://127.0.0.1:8081")
    session.add(Observation(site_id=site.id, at=utcnow() - timedelta(days=91)))
    session.flush()
    observe_due(session, Settings(env="test"), observe_fn=_fake())
    assert session.query(Observation).count() == 1


def test_tls_warning() -> None:
    now = datetime(2026, 10, 23, tzinfo=UTC)
    assert tls_warning(Observation(tls_expires_at=now + timedelta(days=60)), now) is None
    assert tls_warning(Observation(tls_expires_at=now + timedelta(days=5)), now) == (
        "the HTTPS certificate expires in 5 day(s)"
    )
    assert tls_warning(Observation(tls_expires_at=now - timedelta(days=1)), now) == (
        "the HTTPS certificate has expired"
    )


def test_checklist_mentions_what_the_observer_saw(session: Session) -> None:
    site = _site(session, "http://127.0.0.1:8081")
    incident = _replay(session, "php2shell")
    assert incident is not None
    _, before = checklist(session, incident.cases[0])
    assert any(
        "hasn't checked whether this site is behind Cloudflare" in r.item.text for r in before
    )
    observe_site(session, site, Settings(env="test"), observe_fn=_fake(cloudflare=True))
    _, after = checklist(session, incident.cases[0])
    assert any("sees this site behind Cloudflare" in r.item.text for r in after)
    assert edge_status(None).startswith("The observer hasn't")


# --- Dashboard ---------------------------------------------------------------------------


def test_site_page_observe_now_and_disagreement_banner(db_url: str) -> None:
    dash = make_dash(db_url)
    with dash.session() as s:
        site = _site(s, "http://127.0.0.1:8081")
        incident = _replay(s, "php2shell")
        s.commit()
        site_id, case_id = site.id, incident.cases[0].id  # type: ignore[union-attr]
    dash.client.app.state.observe = _fake("PHP/8.3.36", cloudflare=True)  # type: ignore[attr-defined]

    dash.login(UserRole.VIEWER)
    assert dash.post(f"/sites/{site_id}/observe", page=f"/sites/{site_id}").status_code == 403
    dash.client.cookies.clear()
    dash.login(UserRole.RESPONDER)
    assert "Not viewed yet" in dash.client.get(f"/sites/{site_id}").text
    r = dash.post(f"/sites/{site_id}/observe", page=f"/sites/{site_id}")
    assert r.status_code == 303
    page = dash.client.get(f"/sites/{site_id}").text
    assert "PHP/8.3.36" in page and "Report and public view disagree" in page
    assert "Report and public view disagree" in dash.client.get(f"/cases/{case_id}").text
    assert "Report vs public view disagree" in dash.client.get("/").text

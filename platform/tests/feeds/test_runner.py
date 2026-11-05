"""Running feeds: feed_runs, failure alerts, and the download rules."""

from datetime import timedelta

import httpx
import pytest
from sqlalchemy.orm import Session, sessionmaker

from app.alerts.mailer import MemoryMailer
from app.enums import FeedRunStatus
from app.feeds import http
from app.feeds.registry import BY_NAME
from app.feeds.runner import FeedContext, FeedOutcome, FeedSpec, run_feed
from app.feeds.status import feed_health
from app.models import FeedRun
from app.settings import Settings
from tests.feeds.conftest import FakeFetcher, php_net, sample


def _boom(ctx: FeedContext, out: FeedOutcome) -> None:
    raise http.FeedFetchError("HTTP 503 from www.php.net")


def _leaky(ctx: FeedContext, out: FeedOutcome) -> None:
    raise ValueError("<script>alert('from the feed')</script>")


BROKEN = FeedSpec("php-releases", "php.net supported PHP releases", 15, _boom)


def test_a_good_run_is_recorded(
    factory: sessionmaker[Session], fetch: FakeFetcher, settings: Settings
) -> None:
    php_net(fetch)
    run = run_feed(factory, MemoryMailer(), settings, BY_NAME["php-releases"], fetch)
    assert run is not None and run.status is FeedRunStatus.OK
    assert run.finished_at is not None and run.items_updated == 1 and run.error is None


def test_three_failures_in_a_row_send_one_email(
    factory: sessionmaker[Session], fetch: FakeFetcher, settings: Settings
) -> None:
    mail = MemoryMailer()
    for _ in range(2):
        run = run_feed(factory, mail, settings, BROKEN, fetch)
        assert run is not None and run.status is FeedRunStatus.FAILED
        assert run.error == "HTTP 503 from www.php.net"
    assert mail.sent == []
    run_feed(factory, mail, settings, BROKEN, fetch)
    assert len(mail.sent) == 1
    msg = mail.sent[0]
    assert msg.subject == (
        "[Protect] Feed problem: php.net supported PHP releases failed 3 times in a row"
    )
    assert "https://protect.example/feeds" in msg.body and msg.to == ("team@demo.test",)
    run_feed(factory, mail, settings, BROKEN, fetch)
    assert len(mail.sent) == 1  # once per outage

    with factory() as s:
        [health] = [h for h in feed_health(s, settings) if h.spec.name == "php-releases"]
        assert health.state == "broken" and health.needs_attention

    php_net(fetch)
    run_feed(factory, mail, settings, BY_NAME["php-releases"], fetch)  # recovers
    for _ in range(3):
        run_feed(factory, mail, settings, BROKEN, fetch)
    assert len(mail.sent) == 2  # a new outage alerts again


def test_unexpected_errors_never_store_feed_text(
    factory: sessionmaker[Session], fetch: FakeFetcher, settings: Settings
) -> None:
    run = run_feed(factory, MemoryMailer(), settings, FeedSpec("x", "X", 5, _leaky), fetch)
    assert run is not None and run.error == "unexpected ValueError (details in the server log)"


def test_a_failed_run_keeps_nothing_half_done(
    factory: sessionmaker[Session], fetch: FakeFetcher, settings: Settings
) -> None:
    from app.feeds import ghsa

    php_net(fetch)

    def half(ctx: FeedContext, out: FeedOutcome) -> None:
        fetch.add("https://api.github.com/", sample("ghsa_php_src.json"))
        ghsa.run(ctx, out)
        raise http.FeedFetchError("HTTP 500 from api.github.com")

    run_feed(factory, MemoryMailer(), settings, FeedSpec("ghsa", "GitHub", 15, half), fetch)
    with factory() as s:
        from app.models import Advisory

        assert s.query(Advisory).count() == 0


def test_disabled_feed_does_not_run(
    factory: sessionmaker[Session], fetch: FakeFetcher, settings: Settings
) -> None:
    assert run_feed(factory, MemoryMailer(), settings, BY_NAME["wordfence"], fetch) is None
    assert fetch.calls == []
    with factory() as s:
        assert s.query(FeedRun).count() == 0
        [wf] = [h for h in feed_health(s, settings) if h.spec.name == "wordfence"]
        assert wf.state == "off" and not wf.needs_attention


def test_a_feed_with_no_good_run_for_long_is_late(
    factory: sessionmaker[Session], fetch: FakeFetcher, settings: Settings
) -> None:
    php_net(fetch)
    run = run_feed(factory, MemoryMailer(), settings, BY_NAME["php-releases"], fetch)
    assert run is not None and run.finished_at is not None
    with factory() as s:
        later = run.finished_at + timedelta(hours=2)
        [h] = [h for h in feed_health(s, settings, now=later) if h.spec.name == "php-releases"]
        assert h.state == "late"


# --- downloads -----------------------------------------------------------------------------------


@pytest.fixture
def transport(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """Route the real downloader through a fake transport: no network."""
    handlers: dict[str, httpx.Response] = {}
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handlers.get(str(request.url), httpx.Response(404))

    real = httpx.Client
    monkeypatch.setattr(
        http.httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handle), **kw)
    )
    return handlers, seen


@pytest.mark.parametrize(
    "url",
    [
        "http://www.php.net/feed.atom",  # not https
        "https://evil.example/feed.json",
        "https://www.php.net.evil.example/x",
        "https://127.0.0.1/x",
        "file:///etc/passwd",
    ],
)
def test_only_feed_hosts_over_https(url: str) -> None:
    with pytest.raises(http.FeedFetchError):
        http.download(url, max_bytes=100)


def test_download_reads_the_body(transport) -> None:  # type: ignore[no-untyped-def]
    handlers, seen = transport
    handlers["https://www.php.net/feed.atom"] = httpx.Response(200, content=b"<feed/>")
    dl = http.download("https://www.php.net/feed.atom", max_bytes=100)
    assert dl.read() == b"<feed/>"
    assert seen[0].headers["user-agent"].startswith("TransFunnel-Protect-Feeds")


def test_download_size_cap(transport) -> None:  # type: ignore[no-untyped-def]
    handlers, _ = transport
    handlers["https://www.php.net/feed.atom"] = httpx.Response(200, content=b"x" * 5000)
    with pytest.raises(http.FeedFetchError, match="larger than"):
        http.download("https://www.php.net/feed.atom", max_bytes=1000)


def test_download_error_status(transport) -> None:  # type: ignore[no-untyped-def]
    handlers, _ = transport
    handlers["https://api.github.com/x"] = httpx.Response(403, content=b"<b>rate limit</b>")
    with pytest.raises(http.FeedFetchError) as e:
        http.download("https://api.github.com/x", max_bytes=1000)
    assert str(e.value) == "HTTP 403 from api.github.com"  # no response text


def test_redirects_stay_on_feed_hosts(transport) -> None:  # type: ignore[no-untyped-def]
    handlers, _ = transport
    handlers["https://www.php.net/a"] = httpx.Response(302, headers={"location": "/b"})
    handlers["https://www.php.net/b"] = httpx.Response(200, content=b"ok")
    assert http.download("https://www.php.net/a", max_bytes=10).read() == b"ok"
    handlers["https://www.php.net/c"] = httpx.Response(
        302, headers={"location": "https://evil.example/steal"}
    )
    with pytest.raises(http.FeedFetchError, match="not a feed host"):
        http.download("https://www.php.net/c", max_bytes=10)


def test_api_key_never_follows_a_redirect_to_another_host(transport) -> None:  # type: ignore[no-untyped-def]
    handlers, seen = transport
    handlers["https://www.wordfence.com/feed"] = httpx.Response(
        302, headers={"location": "https://www.cisa.gov/elsewhere"}
    )
    handlers["https://www.cisa.gov/elsewhere"] = httpx.Response(200, content=b"{}")
    http.download(
        "https://www.wordfence.com/feed", max_bytes=10, headers={"Authorization": "Bearer k"}
    )
    assert seen[0].headers["authorization"] == "Bearer k"
    assert "authorization" not in seen[1].headers

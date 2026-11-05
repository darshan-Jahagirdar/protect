"""php.net, CISA KEV, Wordfence and NVD, on recorded samples."""

import json
from io import BytesIO
from typing import Any

import pytest
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.enums import Exposure, Priority, ReviewStatus
from app.feeds import clean, kev, nvd, phpnet, wordfence
from app.feeds.runner import FeedContext, FeedOutcome, state
from app.models import Advisory, Event, Incident
from app.services.advisories import ingest_feed_advisory
from app.settings import Settings
from tests.feeds.conftest import NOW, FakeFetcher, php_net, sample
from tests.test_incidents import _site


def _adv(session: Session, alias: str) -> Advisory | None:
    return next((a for a in session.scalars(select(Advisory)) if alias in a.aliases), None)


# --- php.net -----------------------------------------------------------------------------------


def test_releases_store_supported_branches(fetch: FakeFetcher, ctx: FeedContext) -> None:
    php_net(fetch)
    out = FeedOutcome()
    phpnet.run_releases(ctx, out)
    data = state(ctx.session, "php-releases").data
    assert data["supported"] == ["8.2", "8.3", "8.4", "8.5"]
    assert data["latest"]["8.3"] == "8.3.36"
    assert out.updated == 1
    again = FeedOutcome()
    phpnet.run_releases(ctx, again)
    assert again.updated == 0


@pytest.mark.parametrize(
    "body", [b"<html>maintenance</html>", b'{"supported_versions": ["<b>", 8]}', b"[]"]
)
def test_bad_releases_data_fails_the_run(fetch: FakeFetcher, ctx: FeedContext, body: bytes) -> None:
    fetch.add("https://www.php.net/releases/", body)
    with pytest.raises((clean.FeedDataError, ValueError)):
        phpnet.run_releases(ctx, FeedOutcome())


def test_news_security_posts_become_one_review_item_per_day(
    session: Session, fetch: FakeFetcher, ctx: FeedContext
) -> None:
    php_net(fetch)
    phpnet.run_releases(ctx, FeedOutcome())
    fetch.add(phpnet.NEWS_URL, sample("php_news.atom"))
    out = FeedOutcome()
    phpnet.run_news(ctx, out)
    news = [a for a in session.scalars(select(Advisory)) if a.source == "phpnet-news"]
    # 21 Oct (advisory + 4 releases) and 20 Oct (pre-announcement). The 24 Sep release posts
    # are older than the 30-day window, and conferences don't mention security.
    assert sorted(a.aliases[0] for a in news) == [
        "php.net-news:2026-10-20",
        "php.net-news:2026-10-21",
    ]
    assert all(a.review_status is ReviewStatus.NEEDS_REVIEW for a in news)
    oct21 = _adv(session, "php.net-news:2026-10-21")
    assert oct21 is not None
    assert oct21.aliases == ["php.net-news:2026-10-21"]  # mentioned ids don't merge advisories
    assert "Mentions: CVE-2026-109618" in (oct21.summary_text or "")
    assert oct21.title.startswith("php.net: Security advisory")
    [affect] = oct21.affects
    assert {"introduced": "8.3.0", "fixed": "8.3.36"} in affect.ranges
    pre = _adv(session, "php.net-news:2026-10-20")
    assert pre is not None and pre.affects == []


def test_news_never_merges_into_github_advisories(
    session: Session, fetch: FakeFetcher, ctx: FeedContext
) -> None:
    from app.feeds import ghsa

    php_net(fetch)
    fetch.add("https://api.github.com/", sample("ghsa_php_src.json"))
    ghsa.run(ctx, FeedOutcome())
    before = {a.id: list(a.aliases) for a in session.scalars(select(Advisory))}
    fetch.add(phpnet.NEWS_URL, sample("php_news.atom"))
    phpnet.run_news(ctx, FeedOutcome())
    after = {a.id: list(a.aliases) for a in session.scalars(select(Advisory)) if a.id in before}
    assert before == after


@pytest.mark.parametrize(
    "body",
    [
        b"not xml at all <",
        # Billion laughs: Python's expat refuses entity amplification.
        b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa">'
        + b"".join(
            f'<!ENTITY {chr(98 + i)} "{("&" + chr(97 + i) + ";") * 10}">'.encode() for i in range(8)
        )
        + b']><feed xmlns="http://www.w3.org/2005/Atom"><title>&i;</title></feed>',
    ],
)
def test_bad_news_xml_fails_safely(fetch: FakeFetcher, ctx: FeedContext, body: bytes) -> None:
    fetch.add(phpnet.NEWS_URL, body)
    with pytest.raises(clean.FeedDataError):
        phpnet.run_news(ctx, FeedOutcome())


# --- CISA KEV ------------------------------------------------------------------------------------


def test_kev_raises_priority_of_a_known_advisory(
    session: Session, fetch: FakeFetcher, ctx: FeedContext
) -> None:
    _site(session, "http://127.0.0.1:8081", php="8.3.7")
    from app.feeds import ghsa

    php_net(fetch)
    fetch.add("https://api.github.com/", sample("ghsa_php_src.json"))
    ghsa.run(ctx, FeedOutcome())
    adv = _adv(session, "CVE-2024-4577")  # php-cgi argument injection, on CISA's list
    assert adv is not None and not adv.kev
    [incident] = [i for i in session.scalars(select(Incident)) if i.title == adv.title]
    before = incident.cases[0].score

    fetch.add(kev.URL, sample("cisa_kev.json"))
    out = FeedOutcome()
    kev.run(ctx, out)
    assert adv.kev and out.updated >= 1
    assert incident.cases[0].score == before + 30
    assert "listed in CISA's known-exploited catalogue (+30)" in incident.cases[0].score_reasons
    assert session.scalar(
        select(Event).where(Event.incident_id == incident.id, Event.type == "known_exploited")
    )
    # Unchanged catalogue: nothing to do the second time.
    again = FeedOutcome()
    kev.run(ctx, again)
    assert again.updated == 0


def test_kev_flags_advisories_that_arrive_later(
    session: Session, fetch: FakeFetcher, ctx: FeedContext
) -> None:
    fetch.add(kev.URL, sample("cisa_kev.json"))
    kev.run(ctx, FeedOutcome())
    result = ingest_feed_advisory(
        session,
        "nvd",
        "CVE-2026-119977",
        {"title": "WordPress RCE", "aliases": ["CVE-2026-119977"], "affects": []},
        ReviewStatus.NEEDS_REVIEW,
        frozenset(state(session, "kev").data["cves"]),
    )
    assert result.advisory is not None and result.advisory.kev


@pytest.mark.parametrize(
    "body", [b"{}", b"nope", b'{"vulnerabilities": [{"cveID": "x"}, {"cveID": "y"}]}']
)
def test_bad_kev_data_fails_without_clearing_the_list(
    session: Session, fetch: FakeFetcher, ctx: FeedContext, body: bytes
) -> None:
    fetch.add(kev.URL, sample("cisa_kev.json"))
    kev.run(ctx, FeedOutcome())
    count = len(state(session, "kev").data["cves"])
    fetch.add(kev.URL, body)
    with pytest.raises(clean.FeedDataError):
        kev.run(ctx, FeedOutcome())
    assert len(state(session, "kev").data["cves"]) == count


# --- Wordfence ----------------------------------------------------------------------------------


@pytest.fixture
def wf_ctx(session: Session, fetch: FakeFetcher) -> FeedContext:
    settings = Settings(env="test", wordfence_api_key=SecretStr("wf-test-key-not-real"))
    fetch.add(wordfence.URL, sample("wordfence_production.json"))
    return FeedContext(session, fetch, settings, NOW)


def test_wordfence_core_flaw_reaches_the_site(
    session: Session, fetch: FakeFetcher, wf_ctx: FeedContext
) -> None:
    _site(session, "http://127.0.0.1:8081")  # WordPress 7.1.3, Hello Dolly 1.7.2 (inactive)
    out = FeedOutcome()
    wordfence.run(wf_ctx, out)
    # Core, Hello Dolly, two theme records; the uninstalled plugin and the informational
    # record are skipped without counting as refused.
    assert (out.new, out.rejected) == (4, 0)
    url, headers = fetch.calls[-1]
    assert headers["Authorization"] == "Bearer wf-test-key-not-real"

    core = _adv(session, "CVE-2026-119977")
    assert core is not None and core.review_status is ReviewStatus.CONFIRMED
    assert core.affects[0].ranges == [{"introduced": "4.7.0", "fixed": "7.1.4"}]
    assert "Defiant" in (core.attribution or "") and "MITRE" in (core.attribution or "")
    incident = next(i for i in session.scalars(select(Incident)) if i.kind == "wp-core")
    [case] = incident.cases
    assert case.exposure is Exposure.VULNERABLE and case.fixed_version == "7.1.4"

    dolly = _adv(session, "wordfence:0b5f1c7a-1111-4a8e-9c1d-000000000002")
    assert dolly is not None
    assert dolly.title == "Hello Dolly <= 1.7.2 - Cross-Site Scripting Injected: header"
    assert dolly.source_url is None  # the only reference was javascript:
    assert dolly.affects[0].ranges == [{"introduced": "0", "fixed": "1.7.3"}]

    theme = _adv(session, "wordfence:0b5f1c7a-1111-4a8e-9c1d-000000000005")
    assert theme is not None and theme.affects[0].ranges == [{"introduced": "1.0", "fixed": "1.3"}]
    odd = _adv(session, "wordfence:0b5f1c7a-1111-4a8e-9c1d-000000000006")
    assert odd is not None and odd.review_status is ReviewStatus.NEEDS_REVIEW
    assert _adv(session, "wordfence:0b5f1c7a-1111-4a8e-9c1d-000000000003") is None


def test_wordfence_core_flaw_on_kev_is_p1(
    session: Session, fetch: FakeFetcher, wf_ctx: FeedContext
) -> None:
    _site(session, "http://127.0.0.1:8081")
    fetch.add(kev.URL, sample("cisa_kev.json"))
    kev.run(wf_ctx, FeedOutcome())
    wordfence.run(wf_ctx, FeedOutcome())
    incident = next(i for i in session.scalars(select(Incident)) if i.kind == "wp-core")
    # 8.1 (+25) + known exploited (+30) + remote, no login (+10) = 65... plus nothing else.
    assert incident.cases[0].score == 65 and incident.priority is Priority.P2


def _records(n: int) -> dict[str, Any]:
    rec = json.loads(sample("wordfence_production.json"))
    first = next(iter(rec.values()))
    out = {}
    for i in range(n):
        r = json.loads(json.dumps(first))
        r["title"] = f"Record {i} – ünïcode ✓ " + "x" * (i % 7)
        out[f"id-{i}"] = r
    return out


@pytest.mark.parametrize("chunk", [1, 7, 64, 4096])
def test_record_reader_handles_any_chunking(chunk: int) -> None:
    data = _records(25)
    body = BytesIO(json.dumps(data, ensure_ascii=False, indent=2).encode())
    got = dict(wordfence.iter_records(body, chunk_size=chunk))
    assert got == data


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"[]",
        b'{"a": 1',
        b'{"a" 1}',
        b'{"a": 1 "b": 2}',
        b"{1: 2}",
        b'{"a": \xff}',
        b'{"a": tru',
    ],
)
def test_record_reader_refuses_broken_json(body: bytes) -> None:
    with pytest.raises(clean.FeedDataError):
        list(wordfence.iter_records(BytesIO(body), chunk_size=3))


def test_record_reader_refuses_a_giant_record(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wordfence, "MAX_RECORD", 1000)
    body = BytesIO(b'{"a": "' + b"x" * 5000)
    with pytest.raises(clean.FeedDataError):
        list(wordfence.iter_records(body, chunk_size=100))


def test_wordfence_is_off_without_a_key() -> None:
    from app.feeds.registry import BY_NAME

    assert not BY_NAME["wordfence"].enabled(Settings(env="test"))
    assert BY_NAME["wordfence"].enabled(Settings(env="test", wordfence_api_key=SecretStr("k")))
    assert not BY_NAME["kev"].enabled(Settings(env="test", feeds_enabled=False))


# --- NVD -----------------------------------------------------------------------------------------


@pytest.fixture
def nvd_feed(fetch: FakeFetcher) -> FakeFetcher:
    fetch.add(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:wordpress",
        sample("nvd_wordpress.json"),
    )
    fetch.add(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:php",
        sample("nvd_php.json"),
    )
    return fetch


def test_nvd_new_cve_waits_for_review_and_old_ones_are_ignored(
    session: Session, nvd_feed: FakeFetcher, ctx: FeedContext
) -> None:
    _site(session, "http://127.0.0.1:8081")
    out = FeedOutcome()
    nvd.run(ctx, out)
    wp = _adv(session, "CVE-2026-119977")
    assert wp is not None and wp.review_status is ReviewStatus.NEEDS_REVIEW
    assert {"introduced": "7.1", "fixed": "7.1.4"} in wp.affects[0].ranges
    assert wp.cvss_score is not None
    assert _adv(session, "CVE-2011-4899") is None  # old, edited again by NVD, unknown to us
    assert _adv(session, "CVE-2000-0967") is None
    assert session.query(Incident).count() == 0  # nothing opens before a person confirms
    assert state(session, "nvd").data["last_modified"] == NOW.isoformat()
    first_url = nvd_feed.calls[0][0]
    assert "lastModStartDate=2026-10-28T12:00:00.000Z" in first_url


def test_nvd_only_fills_blanks_in_a_github_advisory(
    session: Session, nvd_feed: FakeFetcher, ctx: FeedContext
) -> None:
    from app.feeds import ghsa

    items = json.loads(sample("ghsa_php_src.json"))
    php2shell = next(i for i in items if i["ghsa_id"] == "GHSA-w8hw-w9fx-j79w")
    php2shell["cvss_severities"] = {}
    php_net(nvd_feed)
    nvd_feed.add("https://api.github.com/", json.dumps([php2shell]).encode())
    ghsa.run(ctx, FeedOutcome())
    adv = _adv(session, "CVE-2026-109618")
    assert adv is not None and adv.cvss_score is None
    ranges = [a.ranges for a in adv.affects]
    nvd.run(ctx, FeedOutcome())
    assert adv.source == "ghsa" and adv.review_status is ReviewStatus.CONFIRMED
    assert adv.cvss_score is not None  # filled from NVD
    assert [a.ranges for a in adv.affects] == ranges  # NVD's broader ranges not taken


def test_nvd_garbage_fails_the_run(fetch: FakeFetcher, ctx: FeedContext) -> None:
    fetch.add("https://services.nvd.nist.gov/", b"<html>busy</html>")
    with pytest.raises(clean.FeedDataError):
        nvd.run(ctx, FeedOutcome())

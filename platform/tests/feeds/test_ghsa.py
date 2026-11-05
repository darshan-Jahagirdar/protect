"""GitHub php-src advisories: parsing real samples, the review gate, and incidents."""

import copy
import json
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.enums import Exposure, Priority, ReviewStatus
from app.feeds import ghsa
from app.feeds.runner import FeedContext, FeedOutcome
from app.models import Advisory, Event, FeedItem, Incident
from app.services.advisories import load_fixture
from tests.feeds.conftest import FakeFetcher, php_net, sample
from tests.test_incidents import _replay, _site

SUPPORTED = ["8.2", "8.3", "8.4", "8.5"]
ITEMS: list[dict[str, Any]] = json.loads(sample("ghsa_php_src.json"))


def item(ghsa_id: str) -> dict[str, Any]:
    return copy.deepcopy(next(i for i in ITEMS if i["ghsa_id"] == ghsa_id))


def _adv(session: Session, alias: str) -> Advisory:
    adv = next((a for a in session.scalars(select(Advisory)) if alias in a.aliases), None)
    assert adv is not None, alias
    return adv


@pytest.fixture
def feed(fetch: FakeFetcher) -> FakeFetcher:
    php_net(fetch)
    fetch.add("https://api.github.com/repos/php/php-src/", sample("ghsa_php_src.json"))
    return fetch


# --- one range line ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rng, patched, fixed, introduced, last, problem, note",
    [
        ("< 8.3.36", "8.3.36", "8.3.36", None, None, False, False),
        ("<8.3.35", "8.3.35", "8.3.35", None, None, False, False),
        ("< 8.3.36", "", "8.3.36", None, None, False, False),
        ("< 8.3.18", "8.3.19", "8.3.19", None, None, False, True),  # take the later fix
        ("< 8.1.28", " 8.1.28", "8.1.28", None, None, False, False),  # stray space
        ("<=8.0.27", "8.0.28", "8.0.28", None, None, False, False),
        (">=8.1.0, <=8.1.15", "8.1.16", "8.1.16", "8.1.0", None, False, False),
        ("> 8.1.11, < 8.1.28", "8.1.28", "8.1.28", "8.1.12", None, False, False),
        ("<= 8.2.12", "", "8.2.12", None, "8.2.12", False, False),
        ("< 8.3.36", "8.3.35", None, None, None, True, False),  # fix before the range ends
        ("8.3.6", "8.1.29, 8.2.20, 8.3.8", None, None, None, True, False),
        ("8.2.12", "", None, None, None, True, False),
        ("7.3.27 - 7.3.33, 8.0.2 - 8.0.30", "8.1.29", None, None, None, True, False),
        (">= 8.1.0, < 8.2.20", "8.2.20", None, None, None, True, False),  # spans branches
        ("< 8.3.36", "8.4.27", None, None, None, True, False),  # fix on another branch
        ("< 8.3.36; DROP TABLE", "8.3.36", None, None, None, True, False),
        (None, "8.3.36", None, None, None, True, False),
    ],
)
def test_range_lines(
    rng: object,
    patched: str,
    fixed: str | None,
    introduced: str | None,
    last: str | None,
    problem: bool,
    note: bool,
) -> None:
    fix, prob, n = ghsa._parse_line(rng, patched)
    assert (fix.fixed if fix else None) == fixed
    assert (fix.introduced if fix else None) == introduced
    assert (fix.last_affected if fix else None) == last
    assert bool(prob) is problem
    assert bool(n) is note


# --- whole advisories -------------------------------------------------------------------------


def test_php2shell_from_github_matches_the_hand_made_fixture() -> None:
    item_id, data, status = ghsa.parse(item("GHSA-w8hw-w9fx-j79w"), SUPPORTED)
    assert item_id == "GHSA-w8hw-w9fx-j79w"
    assert status is ReviewStatus.CONFIRMED
    assert data["aliases"] == ["GHSA-w8hw-w9fx-j79w", "CVE-2026-109618"]
    assert data["title"] == "PHP: RCE via OOM corruption"
    assert data["cvss_score"] == 9.2 and data["cvss_vector"].startswith("CVSS:4.0/AV:N")
    assert data["source_url"].startswith("https://github.com/php/php-src/security/advisories/")
    [affect] = data["affects"]
    fixture = load_fixture("php2shell")["affects"][0]
    assert affect["fixed_versions"] == sorted(fixture["fixed_versions"], key=ghsa._version_key)
    fixed = [r for r in affect["ranges"] if "fixed" in r]
    assert fixed == [r for r in fixture["ranges"] if "fixed" in r][::-1]
    assert {"introduced": "0", "limit": "8.2.0", "unsupported": True} in affect["ranges"]


def test_missing_supported_branch_waits_for_review() -> None:
    _, data, status = ghsa.parse(item("GHSA-x692-q9x7-8c3f"), SUPPORTED)
    assert status is ReviewStatus.NEEDS_REVIEW
    assert "supported PHP branches" in data["review_reason"]


def test_fix_one_release_later_is_confirmed_with_a_note() -> None:
    _, data, status = ghsa.parse(item("GHSA-wg4p-4hqh-c3g9"), SUPPORTED)
    assert status is ReviewStatus.CONFIRMED
    assert {"introduced": "8.3.0", "fixed": "8.3.19"} in data["affects"][0]["ranges"]
    assert "Note from Protect" in data["summary_text"]


def test_free_text_range_waits_for_review_with_no_versions() -> None:
    _, data, status = ghsa.parse(item("GHSA-9fcc-425m-g385"), SUPPORTED)
    assert status is ReviewStatus.NEEDS_REVIEW
    assert data["affects"] == []
    assert "couldn't read the range" in data["review_reason"]


def test_extension_name_is_kept_in_the_text() -> None:
    _, data, _ = ghsa.parse(item("GHSA-7875-c8px-7q5f"), SUPPORTED)
    assert data["summary_text"].endswith("Part of PHP: ext-standard")
    assert data["affects"][0]["component_key"] == "php"


def test_without_the_supported_list_everything_waits() -> None:
    _, _, status = ghsa.parse(item("GHSA-w8hw-w9fx-j79w"), None)
    assert status is ReviewStatus.NEEDS_REVIEW


@pytest.mark.parametrize(
    "change",
    [
        {"ghsa_id": "GHSA-<script>"},
        {"ghsa_id": None},
        {"summary": None},
        {"summary": "\r\n"},
    ],
)
def test_malformed_items_are_refused(change: dict[str, Any]) -> None:
    raw = item("GHSA-w8hw-w9fx-j79w")
    raw.update(change)
    with pytest.raises(ghsa.clean.FeedDataError):
        ghsa.parse(raw, SUPPORTED)


def test_hostile_fields_are_cleaned() -> None:
    raw = item("GHSA-w8hw-w9fx-j79w")
    raw["summary"] = "RCE\r\nBcc: someone@evil.test"
    raw["html_url"] = "javascript:alert(document.cookie)"
    raw["cve_id"] = "CVE-2026-109618<script>"
    raw["cvss_severities"]["cvss_v4"]["score"] = 99
    raw["vulnerabilities"][0]["package"]["name"] = "<img src=x onerror=alert(1)>"
    _, data, _ = ghsa.parse(raw, SUPPORTED)
    assert data["title"] == "PHP: RCE Bcc: someone@evil.test"
    assert data["source_url"] is None
    assert data["aliases"] == ["GHSA-w8hw-w9fx-j79w"]
    assert data["cvss_score"] is None
    assert "onerror" not in (data["summary_text"] or "")


# --- the feed run, into incidents ------------------------------------------------------------


def test_run_opens_grouped_incidents_for_an_outdated_site(
    session: Session, feed: FakeFetcher, ctx: FeedContext, out: FeedOutcome
) -> None:
    site = _site(session, "http://127.0.0.1:8081")  # PHP 8.3.30
    ghsa.run(ctx, out)
    assert out.new == len(ITEMS) and out.rejected == 0
    # Learned the supported branches first (first run).
    assert any("php.net/releases" in url for url, _ in feed.calls)

    incidents = {i.title: i for i in session.scalars(select(Incident))}
    php2shell = next(
        i for i in incidents.values() if "RCE via" in i.title or "2 security" in i.title
    )
    # GitHub's data doesn't say it's exploited: 9.2 (+40) and remote, no login (+10) = P2.
    # The team adds +30 from credible reports (test_review.py), or CISA's list does.
    assert php2shell.priority is Priority.P2
    assert php2shell.title == "PHP: 2 security flaws, fixed in 8.2.35, 8.3.36, 8.4.27, 8.5.12"
    [case] = php2shell.cases
    assert case.site_id == site.id and case.exposure is Exposure.VULNERABLE
    assert case.fixed_version == "8.3.36"
    events = [
        e.type for e in session.scalars(select(Event).where(Event.incident_id == php2shell.id))
    ]
    assert "advisory_added" in events
    # The September release (two advisories with the same fixes) is one incident too.
    sept = [i for i in incidents.values() if "8.3.35" in i.title]
    assert len(sept) == 1
    # Waiting for review: nothing opened for it.
    x692 = _adv(session, "GHSA-x692-q9x7-8c3f")
    assert x692.review_status is ReviewStatus.NEEDS_REVIEW
    assert not any("bccomp" in t for t in incidents)


def test_second_run_skips_unchanged_items(
    session: Session, feed: FakeFetcher, ctx: FeedContext
) -> None:
    _site(session, "http://127.0.0.1:8081")
    ghsa.run(ctx, FeedOutcome())
    events = session.query(Event).count()
    again = FeedOutcome()
    ghsa.run(ctx, again)
    assert (again.new, again.updated) == (0, 0)
    assert session.query(Event).count() == events
    assert session.query(FeedItem).count() == len(ITEMS)


def test_feed_never_overwrites_a_replayed_advisory(
    session: Session, feed: FakeFetcher, ctx: FeedContext, out: FeedOutcome
) -> None:
    _site(session, "http://127.0.0.1:8081")
    incident = _replay(session, "php2shell")
    assert incident is not None
    fixture = _adv(session, "GHSA-w8hw-w9fx-j79w")
    ranges = [a.ranges for a in fixture.affects]
    ghsa.run(ctx, out)
    session.refresh(fixture)
    assert fixture.source == "replay"
    assert fixture.exploited is True  # set by people, never cleared by a feed
    assert [a.ranges for a in fixture.affects] == ranges
    assert fixture.title.startswith("PHP2Shell")
    # Both GitHub advisories landed on the fixture (shared aliases): no duplicate incident.
    assert session.query(Incident).filter(Incident.title.contains("RCE via")).count() == 0


def test_withdrawn_advisory_is_rejected(
    session: Session, feed: FakeFetcher, ctx: FeedContext
) -> None:
    ghsa.run(ctx, FeedOutcome())
    items = json.loads(sample("ghsa_php_src.json"))
    items[0]["withdrawn_at"] = "2026-11-04T10:00:00Z"
    feed.add("https://api.github.com/repos/php/php-src/", json.dumps(items).encode())
    ghsa.run(ctx, FeedOutcome())
    assert _adv(session, items[0]["ghsa_id"]).review_status is ReviewStatus.REJECTED


def test_follows_next_page_only_on_github(
    session: Session, fetch: FakeFetcher, ctx: FeedContext
) -> None:
    php_net(fetch)
    page2 = "https://api.github.com/repos/php/php-src/security-advisories?page=2"
    fetch.add(page2, json.dumps([item("GHSA-x692-q9x7-8c3f")]).encode())
    fetch.add(
        ghsa.URL,
        json.dumps([item("GHSA-w8hw-w9fx-j79w")]).encode(),
        {"link": f'<{page2}>; rel="next"'},
    )
    out = FeedOutcome()
    ghsa.run(ctx, out)
    assert out.new == 2

    fetch.add(ghsa.URL, b"[]", {"link": '<https://evil.example/x>; rel="next"'})
    fetch.calls.clear()
    ghsa.run(ctx, FeedOutcome())
    assert all("evil" not in url for url, _ in fetch.calls)


def test_not_a_list_fails_the_run(fetch: FakeFetcher, ctx: FeedContext) -> None:
    php_net(fetch)
    fetch.add("https://api.github.com/", b'{"message": "rate limited"}')
    with pytest.raises(ghsa.clean.FeedDataError):
        ghsa.run(ctx, FeedOutcome())

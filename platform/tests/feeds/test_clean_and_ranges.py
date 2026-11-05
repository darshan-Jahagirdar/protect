"""Cleaning hostile feed text, and turning per-branch PHP fixes into ranges."""

from datetime import UTC, datetime

import pytest

from app.engine.matcher import AffectRule, Bucket, ComponentFacts, OsFacts, match_component
from app.feeds import clean
from app.feeds.php_ranges import BranchFix, build_ranges

# --- clean --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("PHP: RCE\r\nBcc: x@evil.test", "PHP: RCE Bcc: x@evil.test"),  # header injection
        ("a b c", "a b c"),  # unicode line and paragraph separators
        ("safe‮txt.php", "safe txt.php"),  # bidi override
        ("zero​width", "zero width"),
        ("  lots   of\tspace  ", "lots of space"),
        ("<script>alert(1)</script>", "<script>alert(1)</script>"),  # kept; escaped on output
    ],
)
def test_title_is_one_clean_line(raw: str, expected: str) -> None:
    assert clean.title(raw) == expected


@pytest.mark.parametrize("raw", [None, "", "   ", "\r\n", 42])
def test_title_missing_is_refused(raw: object) -> None:
    with pytest.raises(clean.FeedDataError):
        clean.title(raw)


def test_title_is_capped() -> None:
    assert len(clean.title("x" * 1000)) == clean.TITLE_MAX


def test_text_keeps_paragraphs_but_drops_controls() -> None:
    assert clean.text("one\r\n\r\n\r\n\r\ntwo\x00three\x1b[31m") == "one\n\ntwo three [31m"
    assert clean.text("") is None
    assert clean.text(None) is None
    assert len(clean.text("y" * 10000) or "") == clean.TEXT_MAX


@pytest.mark.parametrize(
    "url, ok",
    [
        ("https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w", True),
        ("http://www.php.net/archive/2026.php#2026-10-21-5", True),
        ("javascript:alert(1)", False),
        ("JavaScript:alert(1)", False),
        ("data:text/html,<script>alert(1)</script>", False),
        ("//evil.example/x", False),
        ("/relative/path", False),
        ("https://", False),
        ("https://exa mple.com/", False),
        ("https://example.com/\nSet-Cookie: x", False),
        ("ftp://example.com/x", False),
        ("https://example.com/" + "a" * 600, False),
        (None, False),
    ],
)
def test_only_http_links_survive(url: object, ok: bool) -> None:
    assert clean.http_url(url) == (url if ok else None)


def test_ids_scores_vectors_and_times() -> None:
    assert clean.cve("CVE-2026-109618") == "CVE-2026-109618"
    assert clean.cve("CVE-2026-1") is None
    assert clean.cve("cve-2026-109618") is None
    assert clean.cvss_score(9.2) == 9.2
    assert clean.cvss_score(11) is None
    assert clean.cvss_score(True) is None
    assert clean.cvss_score("9.8") is None
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert clean.cvss_vector(vector) == vector
    assert clean.cvss_vector(vector + "/<script>") is None
    assert clean.timestamp("2026-10-21T13:34:25Z") == datetime(2026, 10, 21, 13, 34, 25, tzinfo=UTC)
    assert clean.timestamp("2026-10-21 13:34:25") == datetime(2026, 10, 21, 13, 34, 25, tzinfo=UTC)
    assert clean.timestamp("yesterday") is None
    assert clean.version("8.3.36") == "8.3.36"
    assert clean.version("not a version") is None


# --- build_ranges ---------------------------------------------------------------------------

SUPPORTED = ["8.2", "8.3", "8.4", "8.5"]


def _fixes(*pairs: str) -> list[BranchFix]:
    out = []
    for fixed in pairs:
        major, minor, _ = fixed.split(".")
        out.append(BranchFix((int(major), int(minor)), fixed))
    return out


def _bucket(ranges: list[dict[str, object]], version: str) -> tuple[Bucket, bool]:
    result = match_component(
        ComponentFacts("php", version),
        AffectRule("php", ranges),
        OsFacts(),  # type: ignore[arg-type]
    )
    return result.bucket, result.unsupported_branch


def test_every_supported_branch_listed_is_confirmed() -> None:
    ranges, unsure = build_ranges(_fixes("8.2.35", "8.3.36", "8.4.27", "8.5.12"), SUPPORTED)
    assert not unsure
    assert ranges == [
        {"introduced": "8.2.0", "fixed": "8.2.35"},
        {"introduced": "8.3.0", "fixed": "8.3.36"},
        {"introduced": "8.4.0", "fixed": "8.4.27"},
        {"introduced": "8.5.0", "fixed": "8.5.12"},
        {"introduced": "0", "limit": "8.2.0", "unsupported": True},
    ]


@pytest.mark.parametrize(
    "version, bucket, unsupported",
    [
        ("8.3.30", Bucket.VULNERABLE, False),
        ("8.3.36", Bucket.SAFE, False),
        ("8.3.37", Bucket.SAFE, False),
        ("8.5.11", Bucket.VULNERABLE, False),
        ("8.6.0", Bucket.SAFE, False),  # newer than every listed branch
        ("8.1.34", Bucket.VULNERABLE, True),  # end of life: no fix coming
        ("7.4.33", Bucket.VULNERABLE, True),
    ],
)
def test_php2shell_shaped_ranges_through_the_engine(
    version: str, bucket: Bucket, unsupported: bool
) -> None:
    ranges, _ = build_ranges(_fixes("8.2.35", "8.3.36", "8.4.27", "8.5.12"), SUPPORTED)
    assert _bucket(ranges, version) == (bucket, unsupported)


def test_missing_supported_branch_is_unsure_not_safe() -> None:
    ranges, unsure = build_ranges(_fixes("8.4.24", "8.5.9"), SUPPORTED)
    assert unsure
    assert {"introduced": "8.2.0", "limit": "8.4.0", "unsure": True} in ranges
    assert {"introduced": "0", "limit": "8.2.0", "unsupported": True} in ranges


def test_gap_between_listed_branches_is_unsure() -> None:
    ranges, unsure = build_ranges(_fixes("8.2.30", "8.4.16"), SUPPORTED)
    assert unsure
    assert {"introduced": "8.3.0", "limit": "8.4.0", "unsure": True} in ranges


def test_old_advisory_below_supported_branches_is_confirmed() -> None:
    # A 2023 advisory listing only 8.0: everything below 8.0 is end of life too.
    ranges, unsure = build_ranges(_fixes("8.0.30"), SUPPORTED)
    assert not unsure
    assert ranges[-1] == {"introduced": "0", "limit": "8.0.0", "unsupported": True}


def test_unknown_supported_list_makes_everything_below_unsure() -> None:
    ranges, unsure = build_ranges(_fixes("8.3.36"), None)
    assert unsure
    assert ranges[-1] == {"introduced": "0", "limit": "8.3.0", "unsure": True}


def test_explicit_lower_bound_leaves_nothing_below() -> None:
    fixes = [BranchFix((8, 1), "8.1.16", introduced="8.1.0"), BranchFix((8, 0), "8.0.28")]
    ranges, unsure = build_ranges(fixes, ["8.0", "8.1"])
    assert not unsure
    assert {"introduced": "8.1.0", "fixed": "8.1.16"} in ranges
    assert not any(r.get("limit") == "8.1.0" for r in ranges)

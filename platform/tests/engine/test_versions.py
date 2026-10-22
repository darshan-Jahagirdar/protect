import pytest

from app.engine.versions import (
    compare_dpkg,
    extract_version,
    parse_loose,
    parse_php,
)

# --- PHP_VERSION ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("8.3.30", (8, 3, 30, "")),
        ("8.1.2-1ubuntu2.20", (8, 1, 2, "-1ubuntu2.20")),
        ("8.2.29-1~deb12u1", (8, 2, 29, "-1~deb12u1")),
        ("8.3.36RC1", (8, 3, 36, "RC1")),
        ("  8.4.27 ", (8, 4, 27, "")),
        ("7.4.33", (7, 4, 33, "")),
    ],
)
def test_parse_php(raw: str, expected: tuple[int, int, int, str]) -> None:
    v = parse_php(raw)
    assert v is not None
    assert (v.major, v.minor, v.release, v.extra) == expected


@pytest.mark.parametrize("raw", [None, "", "8.3", "eight", "8.x.1", "v8.3.30"])
def test_parse_php_rejects(raw: str | None) -> None:
    assert parse_php(raw) is None


def test_php_upstream_ignores_suffix() -> None:
    """The bug we must never have: '-1ubuntu2.20' must not make 8.1.2 sort below 8.1.2."""
    v = parse_php("8.1.2-1ubuntu2.20")
    assert v is not None
    assert v.upstream == parse_loose("8.1.2")
    assert v.branch == "8.1"


# --- Loose versions ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("6.6.2", "6.6.10"),  # numeric, not string, comparison
        ("6.9", "6.10"),
        ("2.0.0-beta1", "2.0.0"),
        ("2.0.0-beta3", "2.0.0-rc1"),
        ("2.0.0-alpha", "2.0.0-beta"),
        ("2.0.0-dev", "2.0.0-alpha1"),
        ("1.0.0-rc.1", "1.0.0-rc.2"),
        ("1.1.1", "1.1.1a"),  # OpenSSL patch letters
        ("1.1.1v", "1.1.1w"),
        ("1.1.1w", "1.1.2"),
        ("4.9.99", "5.0"),
        ("2024.01.15", "2024.02.01"),
        ("0", "0.0.1"),
    ],
)
def test_loose_ordering(a: str, b: str) -> None:
    va, vb = parse_loose(a), parse_loose(b)
    assert va is not None and vb is not None
    assert va < vb
    assert vb > va
    assert va != vb


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("6.6", "6.6.0"),
        ("v1.2", "1.2"),
        ("1.2.3+build.5", "1.2.3"),
        ("5.9.8", "5.9.8"),
        ("2.0RC1", "2.0-rc1"),
    ],
)
def test_loose_equal(a: str, b: str) -> None:
    assert parse_loose(a) == parse_loose(b)
    assert hash(parse_loose(a)) == hash(parse_loose(b))


@pytest.mark.parametrize(
    "raw", [None, "", "trunk", "latest", "1.0 beta", "1..2", "abc1.0", "1.0-final-final", "-1"]
)
def test_loose_rejects(raw: str | None) -> None:
    assert parse_loose(raw) is None


# --- dpkg ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("a", "b", "sign"),
    [
        ("8.1.2-1ubuntu2.20", "8.1.2-1ubuntu2.21", -1),
        ("8.1.2-1ubuntu2.21", "8.1.2-1ubuntu2.21", 0),
        ("8.1.2-1ubuntu2.22", "8.1.2-1ubuntu2.21", 1),
        ("8.1.2-1ubuntu2.20", "8.1.2-1ubuntu2.3", 1),  # 20 > 3 numerically
        ("8.2.29-1~deb12u1", "8.2.29-1~deb12u2", -1),
        ("8.2.29-1~deb12u1", "8.2.29-1", -1),  # ~ sorts before everything
        ("8.2.29-1+deb12u1", "8.2.29-1", 1),
        ("1.0~rc1", "1.0", -1),
        ("1.0", "1.0-0", 0),  # missing revision == 0
        ("1:0.1", "2.0", 1),  # epoch wins
        ("1.0a", "1.0", 1),
        ("1.0", "1.0.1", -1),
        ("3.0.2-0ubuntu1.18", "3.0.2-0ubuntu1.10", 1),
    ],
)
def test_compare_dpkg(a: str, b: str, sign: int) -> None:
    result = compare_dpkg(a, b)
    assert (result > 0) - (result < 0) == sign
    reverse = compare_dpkg(b, a)
    assert (reverse > 0) - (reverse < 0) == -sign


@pytest.mark.parametrize("bad", ["", "abc", "-1", "1.0 beta"])
def test_compare_dpkg_rejects(bad: str) -> None:
    with pytest.raises(ValueError):
        compare_dpkg(bad, "1.0")


# --- Extracting versions from descriptive strings --------------------------------------


@pytest.mark.parametrize(
    ("key", "raw", "expected"),
    [
        ("lib:openssl", "OpenSSL 3.0.13 30 Jan 2024", "3.0.13"),
        ("lib:openssl", "OpenSSL 1.1.1w  11 Sep 2023", "1.1.1w"),
        ("server:apache", "Apache/2.4.58 (Ubuntu)", "2.4.58"),
        ("server:apache", "Apache", None),  # ServerTokens Prod hides the version
        ("server:nginx", "nginx/1.24.0", "1.24.0"),
        ("server:litespeed", "LiteSpeed", None),
        ("wp-plugin:contact-form-7", " 5.9.8 ", "5.9.8"),
        ("lib:curl", "8.5.0", "8.5.0"),
        ("lib:curl", None, None),
    ],
)
def test_extract_version(key: str, raw: str | None, expected: str | None) -> None:
    assert extract_version(key, raw) == expected

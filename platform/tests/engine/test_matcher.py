import json
from pathlib import Path
from typing import Any

import pytest

from app.engine.matcher import (
    AffectRule,
    Bucket,
    ComponentFacts,
    OsFacts,
    PhpBuild,
    classify_php_build,
    match_component,
)
from app.engine.versions import parse_php

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "advisories"
V, N, S = Bucket.VULNERABLE, Bucket.NEEDS_CHECK, Bucket.SAFE

UBUNTU_2204 = OsFacts("ubuntu", ("debian",), "22.04")
DEBIAN_12 = OsFacts("debian", (), "12")
ALMA_9 = OsFacts("almalinux", ("rhel", "centos", "fedora"), "9.4")
CLOUDLINUX_8 = OsFacts("cloudlinux", ("rhel", "fedora", "centos"), "8.10")
NO_OS = OsFacts()


def _php2shell_rule(distro_fixes: dict[str, Any] | None = None) -> AffectRule:
    data = json.loads((FIXTURES / "php2shell.json").read_text())
    affect = data["affects"][0]
    return AffectRule(affect["component_key"], affect["ranges"], distro_fixes or {})


def _php(version: str | None, os: OsFacts = NO_OS, **fixes: Any):
    return match_component(ComponentFacts("php", version), _php2shell_rule(fixes or None), os)


# --- PHP2Shell on upstream builds, every branch ------------------------------------


@pytest.mark.parametrize(
    ("version", "bucket", "fixed", "unsupported"),
    [
        ("8.5.11", V, "8.5.12", False),
        ("8.5.12", S, None, False),
        ("8.5.13", S, None, False),
        ("8.4.0", V, "8.4.27", False),
        ("8.4.26", V, "8.4.27", False),
        ("8.4.27", S, None, False),
        ("8.3.30", V, "8.3.36", False),  # our demo site
        ("8.3.35", V, "8.3.36", False),
        ("8.3.36", S, None, False),
        ("8.3.40", S, None, False),
        ("8.2.34", V, "8.2.35", False),
        ("8.2.35", S, None, False),
        ("8.1.33", V, None, True),  # end of life: no official fix
        ("8.0.30", V, None, True),
        ("7.4.33", V, None, True),
        ("5.6.40", V, None, True),
        ("5.4.0", V, None, True),
        ("5.3.29", S, None, False),  # older than the bug
        ("8.6.0", S, None, False),  # newer than every listed branch
    ],
)
def test_php2shell_upstream(version: str, bucket: Bucket, fixed: str | None, unsupported: bool):
    r = _php(version)
    assert r.bucket is bucket, r.reasons
    assert r.fixed_version == fixed
    assert r.unsupported_branch is unsupported
    assert r.build is PhpBuild.UPSTREAM
    assert r.reasons  # always explain


def test_sury_style_build_on_debian_trusts_the_number() -> None:
    """No suffix on Debian = upstream build (e.g. official Docker image, Sury repo)."""
    assert _php("8.3.30", DEBIAN_12).bucket is V
    assert _php("8.3.36", DEBIAN_12).bucket is S


# --- Distro builds ---------------------------------------------------------------------


UBUNTU_FIX = {"22.04": {"php8.1": "8.1.2-1ubuntu2.21"}}


@pytest.mark.parametrize(
    ("version", "fixes", "bucket"),
    [
        ("8.1.2-1ubuntu2.20", UBUNTU_FIX, V),  # one revision short of the fix
        ("8.1.2-1ubuntu2.21", UBUNTU_FIX, S),  # exactly the fix
        ("8.1.2-1ubuntu2.22", UBUNTU_FIX, S),
        ("8.1.2-1ubuntu2.20", {}, N),  # no Ubuntu data: never guess
        ("8.1.2-1ubuntu2.20", {"22.04": {"php8.1": "not-affected"}}, S),
        ("8.1.2-1ubuntu2.20", {"22.04": {"php8.1": "unfixed"}}, V),
        ("8.1.2-1ubuntu2.20", {"24.04": {"php8.1": "8.1.2-1ubuntu2.21"}}, N),  # other release
        ("8.1.2-1ubuntu2.20", {"22.04": {"php8.3": "8.3.6-0ubuntu0.24.04.5"}}, N),  # other pkg
    ],
)
def test_ubuntu_builds(version: str, fixes: dict[str, Any], bucket: Bucket) -> None:
    r = _php(version, UBUNTU_2204, ubuntu=fixes)
    assert r.bucket is bucket, r.reasons
    assert r.build is PhpBuild.UBUNTU
    assert not r.unsupported_branch  # Ubuntu still patches its own 8.1 package


def test_ubuntu_vulnerable_reports_package_fix() -> None:
    r = _php("8.1.2-1ubuntu2.20", UBUNTU_2204, ubuntu=UBUNTU_FIX)
    assert r.fixed_version == "8.1.2-1ubuntu2.21"
    assert "Ubuntu" in r.reasons[0]


def test_ubuntu_build_with_unknown_os_release_needs_check() -> None:
    r = _php("8.1.2-1ubuntu2.20", NO_OS, ubuntu=UBUNTU_FIX)
    assert r.bucket is N


DEBIAN_FIX = {"12": {"php8.2": "8.2.29-1~deb12u2"}}


@pytest.mark.parametrize(
    ("version", "bucket"),
    [
        ("8.2.29-1~deb12u1", V),
        ("8.2.29-1~deb12u2", S),
        ("8.2.29-1+deb12u3", S),
    ],
)
def test_debian_builds(version: str, bucket: Bucket) -> None:
    r = _php(version, DEBIAN_12, debian=DEBIAN_FIX)
    assert r.bucket is bucket, r.reasons
    assert r.build is PhpBuild.DEBIAN


def test_patched_upstream_number_is_safe_even_on_distro() -> None:
    # Outside the affected range: no need for distro data at all.
    assert _php("8.3.36-1ubuntu0.1", UBUNTU_2204).bucket is S


@pytest.mark.parametrize("os", [ALMA_9, CLOUDLINUX_8, OsFacts("rhel", (), "9")])
def test_rhel_family_needs_check(os: OsFacts) -> None:
    r = _php("8.3.30", os)
    assert r.bucket is N
    assert r.build is PhpBuild.RHEL_FAMILY
    assert "backported" in r.reasons[0]
    assert r.fixed_version == "8.3.36"  # still tell the team what "fixed" looks like


def test_rhel_family_patched_number_is_safe() -> None:
    assert _php("8.3.36", ALMA_9).bucket is S


# --- Things that must never come out SAFE ----------------------------------------------


@pytest.mark.parametrize(
    "version", [None, "", "eight", "8.3", "garbage-8.3.30", "8.3.30-custom", "8.3.30RC1"]
)
def test_unreadable_or_odd_php_needs_check(version: str | None) -> None:
    assert _php(version).bucket is N


@pytest.mark.parametrize(
    "ranges",
    [
        [],
        [{"introduced": "8.3.0", "fixed": "not-a-version"}],
        [{"introduced": "8.3.0", "fixed": "8.3.36", "last_affected": "8.3.35"}],
    ],
)
def test_broken_advisory_ranges_need_check(ranges: list[dict[str, Any]]) -> None:
    r = match_component(ComponentFacts("php", "8.3.30"), AffectRule("php", ranges), NO_OS)
    assert r.bucket is N
    assert "advisory needs review" in r.reasons[0]


# --- WordPress, plugins, themes -------------------------------------------------------


PLUGIN_RULE = AffectRule("wp-plugin:contact-form-7", [{"introduced": "0", "fixed": "5.9.9"}])


@pytest.mark.parametrize(
    ("version", "bucket"),
    [
        ("5.9.8", V),
        ("5.9.9", S),
        ("5.10", S),  # 5.10 > 5.9.9 numerically
        ("5.9.9-beta1", V),  # pre-release of the fix isn't the fix
        ("1.0", V),
        ("trunk", N),
        (None, N),
    ],
)
def test_plugin_versions(version: str | None, bucket: Bucket) -> None:
    r = match_component(ComponentFacts("wp-plugin:contact-form-7", version), PLUGIN_RULE, NO_OS)
    assert r.bucket is bucket, r.reasons


def test_last_affected_and_open_ranges() -> None:
    rule = AffectRule("wp-theme:astra", [{"introduced": "4.0", "last_affected": "4.8.1"}])
    assert match_component(ComponentFacts("wp-theme:astra", "4.8.1"), rule, NO_OS).bucket is V
    assert match_component(ComponentFacts("wp-theme:astra", "4.8.2"), rule, NO_OS).bucket is S
    open_rule = AffectRule("wordpress", [{"introduced": "7.0"}])
    r = match_component(ComponentFacts("wordpress", "7.1.3"), open_rule, NO_OS)
    assert r.bucket is V
    assert r.fixed_version is None
    assert "no fix is available yet" in r.reasons[0]


def test_inactive_component_keeps_its_bucket_but_says_so() -> None:
    r = match_component(
        ComponentFacts("wp-plugin:contact-form-7", "5.9.8", active=False), PLUGIN_RULE, NO_OS
    )
    assert r.bucket is V
    assert any("inactive" in reason for reason in r.reasons)


# --- OS-provided components -----------------------------------------------------------


def test_os_provided_library_in_range_needs_check() -> None:
    rule = AffectRule("lib:openssl", [{"introduced": "3.0.0", "fixed": "3.0.15"}])
    r = match_component(
        ComponentFacts("lib:openssl", "OpenSSL 3.0.13 30 Jan 2024"), rule, UBUNTU_2204
    )
    assert r.bucket is N
    assert r.version == "3.0.13"
    assert r.fixed_version == "3.0.15"
    assert "backported" in r.reasons[0]
    ok = match_component(ComponentFacts("lib:openssl", "OpenSSL 3.0.15 3 Sep 2024"), rule, NO_OS)
    assert ok.bucket is S


def test_server_without_version_needs_check() -> None:
    rule = AffectRule("server:apache", [{"introduced": "2.4.0", "fixed": "2.4.62"}])
    r = match_component(ComponentFacts("server:apache", "Apache"), rule, NO_OS)
    assert r.bucket is N


# --- Guard rails -----------------------------------------------------------------------


def test_mismatched_component_and_rule_is_a_programming_error() -> None:
    with pytest.raises(ValueError):
        match_component(ComponentFacts("wordpress", "7.1.3"), PLUGIN_RULE, NO_OS)


def test_invalid_component_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        match_component(
            ComponentFacts("plugin:<script>", "1.0"), AffectRule("plugin:<script>", []), NO_OS
        )


@pytest.mark.parametrize(
    ("version", "os", "build"),
    [
        ("8.3.30", NO_OS, PhpBuild.UPSTREAM),
        ("8.3.30", DEBIAN_12, PhpBuild.UPSTREAM),
        ("8.3.30", ALMA_9, PhpBuild.RHEL_FAMILY),
        ("8.1.2-1ubuntu2.20", UBUNTU_2204, PhpBuild.UBUNTU),
        ("8.1.2-1ubuntu2.20", NO_OS, PhpBuild.UBUNTU),
        ("8.2.29-1~deb12u1", NO_OS, PhpBuild.DEBIAN),
        ("8.2.29-1", DEBIAN_12, PhpBuild.DEBIAN),
        ("8.2.29-1", NO_OS, PhpBuild.UNKNOWN_SUFFIX),
        ("8.3.36RC1", NO_OS, PhpBuild.PRERELEASE),
        ("8.4.0-dev", NO_OS, PhpBuild.PRERELEASE),
        ("8.3.30-custom", NO_OS, PhpBuild.UNKNOWN_SUFFIX),
    ],
)
def test_classify_php_build(version: str, os: OsFacts, build: PhpBuild) -> None:
    php = parse_php(version)
    assert php is not None
    assert classify_php_build(php, os) is build


def test_os_facts_from_report() -> None:
    os = OsFacts.from_report(
        {"id": "AlmaLinux", "id_like": "rhel centos fedora", "version_id": "9.4"}
    )
    assert os.id == "almalinux"
    assert os.is_family("rhel")
    assert OsFacts.from_report(None) == NO_OS

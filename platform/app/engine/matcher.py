"""Decides whether one site component is affected by one advisory (DESIGN.md §4.5).

Deterministic and pure: no I/O, no AI. Every result lands in one of three buckets:

- VULNERABLE: inside an affected range and nothing says it's patched.
- NEEDS_CHECK: the version alone can't tell us. A person confirms with the host or by other means.
- SAFE: fixed, or outside the affected ranges.

Rule of thumb: when in doubt, NEEDS_CHECK. This module must never return SAFE because
something was missing or unparseable.

Advisory ranges are OSV-style dicts. Each has one lower bound and at most one upper bound:
    {"introduced": "8.3.0", "fixed": "8.3.36"}          fix exists (exclusive upper bound)
    {"introduced": "1.0", "last_affected": "1.4.2"}     no fix known (inclusive upper bound)
    {"introduced": "5.4.0", "limit": "8.2.0",
     "unsupported": true}                              end-of-life branches, no fix will come
    {"introduced": "2.0"}                              everything from 2.0 up, no fix yet
"introduced": "0" means "from the very first version".

Distro fix data (advisory_affects.distro_fixes), for PHP packages:
    {"ubuntu": {"22.04": {"php8.1": "8.1.2-1ubuntu2.21"}},
     "debian": {"12": {"php8.2": "8.2.29-1~deb12u2"}}}
A value is the first fixed package version, "not-affected", or "unfixed".
"""

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from app.engine.catalogue import SYSTEM_PROVIDED, ComponentKind, kind_of
from app.engine.versions import (
    LooseVersion,
    PhpVersion,
    compare_dpkg,
    extract_version,
    parse_loose,
    parse_php,
)


class Bucket(StrEnum):
    VULNERABLE = "vulnerable"
    NEEDS_CHECK = "needs_check"
    SAFE = "safe"


class PhpBuild(StrEnum):
    UPSTREAM = "upstream"
    UBUNTU = "ubuntu"
    DEBIAN = "debian"
    RHEL_FAMILY = "rhel_family"
    PRERELEASE = "prerelease"
    UNKNOWN_SUFFIX = "unknown_suffix"


@dataclass(frozen=True)
class OsFacts:
    id: str | None = None
    id_like: tuple[str, ...] = ()
    version_id: str | None = None

    @classmethod
    def from_report(cls, os: dict[str, Any] | None) -> "OsFacts":
        if not os:
            return cls()
        like = tuple((os.get("id_like") or "").lower().split())
        return cls((os.get("id") or "").lower() or None, like, os.get("version_id"))

    def is_family(self, *names: str) -> bool:
        return self.id in names or any(n in self.id_like for n in names)


@dataclass(frozen=True)
class ComponentFacts:
    key: str
    version_raw: str | None
    active: bool = True


@dataclass(frozen=True)
class AffectRule:
    component_key: str
    ranges: list[dict[str, Any]]
    distro_fixes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MatchResult:
    bucket: Bucket
    reasons: tuple[str, ...]
    version: str | None = None
    fixed_version: str | None = None  # the fix to move to, for this branch or distro
    unsupported_branch: bool = False
    build: PhpBuild | None = None  # PHP only


class AdvisoryRangeError(ValueError):
    pass


_RHEL_FAMILY = ("rhel", "centos", "almalinux", "rocky", "cloudlinux", "ol", "fedora", "amzn")
_UBUNTU_SUFFIX = re.compile(r"^-\d+ubuntu[0-9a-z.~+]*$")
_DEBIAN_TAG = re.compile(r"[+~]deb\d+u\d+")
_DEBIAN_REVISION = re.compile(r"^-\d+[0-9a-z.~+]*$")
_PRERELEASE = re.compile(r"^-?(dev|alpha\d*|beta\d*|rc\d*)$", re.IGNORECASE)


def classify_php_build(php: PhpVersion, os: OsFacts) -> PhpBuild:
    extra = php.extra
    if extra == "":
        return PhpBuild.RHEL_FAMILY if os.is_family(*_RHEL_FAMILY) else PhpBuild.UPSTREAM
    if _UBUNTU_SUFFIX.match(extra):
        return PhpBuild.UBUNTU
    if _DEBIAN_TAG.search(extra) or (_DEBIAN_REVISION.match(extra) and os.is_family("debian")):
        return PhpBuild.DEBIAN
    if _PRERELEASE.match(extra):
        return PhpBuild.PRERELEASE
    return PhpBuild.UNKNOWN_SUFFIX


@dataclass(frozen=True)
class _Hit:
    fixed: str | None
    unsupported: bool


def _v(raw: Any, what: str) -> LooseVersion:
    v = parse_loose(str(raw)) if raw is not None else None
    if v is None:
        raise AdvisoryRangeError(f"unparseable {what}: {raw!r}")
    return v


def _find_hit(version: LooseVersion, ranges: list[dict[str, Any]]) -> _Hit | None:
    if not ranges:
        raise AdvisoryRangeError("advisory lists no version ranges")
    for rng in ranges:
        uppers = [k for k in ("fixed", "last_affected", "limit") if rng.get(k) is not None]
        if len(uppers) > 1:
            raise AdvisoryRangeError(f"range has more than one upper bound: {rng!r}")
        if version < _v(rng.get("introduced", "0"), "introduced"):
            continue
        if "fixed" in uppers:
            if version < _v(rng["fixed"], "fixed"):
                return _Hit(fixed=str(rng["fixed"]), unsupported=False)
        elif "last_affected" in uppers:
            if version <= _v(rng["last_affected"], "last_affected"):
                return _Hit(fixed=None, unsupported=False)
        elif "limit" in uppers:
            if version < _v(rng["limit"], "limit"):
                return _Hit(fixed=None, unsupported=bool(rng.get("unsupported")))
        else:
            return _Hit(fixed=None, unsupported=False)
    return None


def _affected(label: str, version: str | None, hit: _Hit) -> MatchResult:
    """label is what the reason names, e.g. "PHP 8.3.30" or "version 5.9.8"."""
    if hit.unsupported:
        reason = f"{label} is on a branch that no longer gets fixes; upgrade to a supported branch"
    elif hit.fixed:
        reason = f"{label} is affected; fixed in {hit.fixed}"
    else:
        reason = f"{label} is affected and no fix is available yet"
    return MatchResult(
        Bucket.VULNERABLE, (reason,), version, hit.fixed, unsupported_branch=hit.unsupported
    )


def _with(result: MatchResult, **changes: Any) -> MatchResult:
    data = {f: getattr(result, f) for f in result.__dataclass_fields__}
    data.update(changes)
    return MatchResult(**data)


def _match_php(raw: str | None, rule: AffectRule, os: OsFacts) -> MatchResult:
    php = parse_php(raw)
    if php is None:
        return MatchResult(Bucket.NEEDS_CHECK, (f"PHP version could not be read: {raw!r}",), raw)
    build = classify_php_build(php, os)
    upstream = f"{php.major}.{php.minor}.{php.release}"
    try:
        hit = _find_hit(php.upstream, rule.ranges)
    except AdvisoryRangeError as e:
        return MatchResult(
            Bucket.NEEDS_CHECK, (f"advisory needs review: {e}",), php.raw, build=build
        )

    if hit is None:
        return MatchResult(
            Bucket.SAFE, (f"PHP {upstream} is outside the affected ranges",), php.raw, build=build
        )

    if build is PhpBuild.UPSTREAM:
        return _with(_affected(f"PHP {upstream}", php.raw, hit), build=build)

    if build in (PhpBuild.UBUNTU, PhpBuild.DEBIAN):
        return _match_distro_php(php, build, hit, rule, os)

    reason = {
        PhpBuild.RHEL_FAMILY: (
            f"PHP {upstream} on a RHEL-family system: fixes are often backported without "
            "changing the version number; confirm with the host"
        ),
        PhpBuild.PRERELEASE: f"PHP {php.raw} is a pre-release build; confirm what it contains",
        PhpBuild.UNKNOWN_SUFFIX: (
            f"PHP {php.raw} has an unrecognised build suffix {php.extra!r}; confirm with the host"
        ),
    }[build]
    return MatchResult(Bucket.NEEDS_CHECK, (reason,), php.raw, hit.fixed, build=build)


def _match_distro_php(
    php: PhpVersion, build: PhpBuild, hit: _Hit, rule: AffectRule, os: OsFacts
) -> MatchResult:
    distro = build.value  # "ubuntu" or "debian"
    name = distro.capitalize()
    package = f"php{php.branch}"
    if not os.version_id:
        return MatchResult(
            Bucket.NEEDS_CHECK,
            (f"{name} PHP build, but the OS release is unknown; confirm with the host",),
            php.raw,
            build=build,
        )
    fix = rule.distro_fixes.get(distro, {}).get(os.version_id, {}).get(package)
    where = f"{package} on {name} {os.version_id}"
    if fix is None:
        return MatchResult(
            Bucket.NEEDS_CHECK,
            (f"no {name} fix data for {where}; check {name}'s security notice",),
            php.raw,
            build=build,
        )
    if fix == "not-affected":
        return MatchResult(
            Bucket.SAFE, (f"{name} says {where} is not affected",), php.raw, build=build
        )
    if fix == "unfixed":
        return MatchResult(
            Bucket.VULNERABLE,
            (f"{name} has not released a fix for {where} yet",),
            php.raw,
            build=build,
        )
    try:
        patched = compare_dpkg(php.raw, fix) >= 0
    except ValueError:
        return MatchResult(
            Bucket.NEEDS_CHECK,
            (f"could not compare {name} package versions {php.raw!r} and {fix!r}",),
            php.raw,
            build=build,
        )
    if patched:
        return MatchResult(
            Bucket.SAFE,
            (f"{name} package {php.raw} includes the fix ({fix})",),
            php.raw,
            build=build,
        )
    return MatchResult(
        Bucket.VULNERABLE,
        (f"{name} package {php.raw} is affected; fixed in {fix}",),
        php.raw,
        fix,
        build=build,
    )


def _match_generic(component: ComponentFacts, kind: ComponentKind, rule: AffectRule) -> MatchResult:
    raw = extract_version(component.key, component.version_raw)
    version = parse_loose(raw)
    if version is None:
        return MatchResult(
            Bucket.NEEDS_CHECK,
            (f"{component.key} version could not be read: {component.version_raw!r}",),
            raw,
        )
    try:
        hit = _find_hit(version, rule.ranges)
    except AdvisoryRangeError as e:
        return MatchResult(Bucket.NEEDS_CHECK, (f"advisory needs review: {e}",), raw)
    if hit is None:
        return MatchResult(Bucket.SAFE, (f"{raw} is outside the affected ranges",), raw)

    result = _affected(f"version {raw}", raw, hit)
    if kind in SYSTEM_PROVIDED:
        return _with(
            result,
            bucket=Bucket.NEEDS_CHECK,
            reasons=(
                f"{component.key} {raw} is in the affected range, but it is provided by the OS "
                "or host, where fixes are often backported; confirm with the host",
            ),
        )
    return result


def match_component(component: ComponentFacts, rule: AffectRule, os: OsFacts) -> MatchResult:
    """Match one site component against one advisory's rule for that component."""
    if component.key != rule.component_key:
        raise ValueError(f"component {component.key!r} doesn't match rule {rule.component_key!r}")
    kind = kind_of(component.key)
    if kind is ComponentKind.PHP:
        result = _match_php(component.version_raw, rule, os)
    else:
        result = _match_generic(component, kind, rule)

    if not component.active and result.bucket is not Bucket.SAFE:
        result = _with(
            result,
            reasons=(
                *result.reasons,
                "component is inactive, but its files may still be reachable",
            ),
        )
    return result

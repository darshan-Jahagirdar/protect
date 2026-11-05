"""Turning per-branch PHP fixes into OSV-style ranges (see app/engine/matcher.py).

PHP advisories list one fix per release branch ("< 8.3.36, patched 8.3.36"). Read literally,
"< 8.2.35" also covers 8.1 and 7.4, and "< 8.4.24" covers 8.3 even when 8.3 isn't listed. We read
each line as "this branch, fixed in this release", and then look at the branches in between and
below, where the literal and per-branch readings disagree:

- Branches older than every supported one (php.net's list) get no fixes: `unsupported`, which
  the engine reports as vulnerable with "upgrade to a supported branch".
- A supported branch the advisory doesn't mention is `unsure`: maybe not affected, maybe
  forgotten. The advisory waits for a person to settle it (the review queue), never "safe".
- Branches above the newest one listed are treated as fixed, as GitHub's own tools do.
"""

from dataclasses import dataclass

from app.engine.versions import parse_loose


@dataclass(frozen=True)
class BranchFix:
    branch: tuple[int, int]
    fixed: str
    introduced: str | None = None  # an explicit lower bound from the advisory
    last_affected: str | None = None  # "<= X" with no patched release


def branch_of(version: str) -> tuple[int, int] | None:
    parts = version.split(".")
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
        return None
    return int(parts[0]), int(parts[1])


def _b(branch: tuple[int, int]) -> str:
    return f"{branch[0]}.{branch[1]}.0"


def _lt(a: str, b: str) -> bool:
    va, vb = parse_loose(a), parse_loose(b)
    if va is None or vb is None:  # only built from versions we produced; never expected
        raise ValueError(f"unreadable version {a!r} or {b!r}")
    return va < vb


def build_ranges(
    fixes: list[BranchFix], supported: list[str] | None
) -> tuple[list[dict[str, object]], bool]:
    """Returns (ranges, unsure). unsure=True means the advisory needs a person's review."""
    ranges: list[dict[str, object]] = []
    ordered = sorted(fixes, key=lambda f: f.branch)
    for f in ordered:
        rng: dict[str, object] = {"introduced": f.introduced or _b(f.branch)}
        if f.last_affected:
            rng["last_affected"] = f.last_affected
        else:
            rng["fixed"] = f.fixed
        ranges.append(rng)

    oldest_supported = None
    if supported:
        branches = [b for b in (branch_of(v) for v in supported) if b is not None]
        oldest_supported = _b(min(branches)) if branches else None

    previous: tuple[int, int] | None = None
    for f in ordered:
        if f.introduced is None:  # the literal "< X" also covers everything below this branch
            low = "0" if previous is None else _b((previous[0], previous[1] + 1))
            high = _b(f.branch)
            if oldest_supported is None:
                if _lt(low, high):
                    ranges.append({"introduced": low, "limit": high, "unsure": True})
            else:
                if _lt(low, oldest_supported):
                    top = high if _lt(high, oldest_supported) else oldest_supported
                    if _lt(low, top):
                        ranges.append({"introduced": low, "limit": top, "unsupported": True})
                bottom = oldest_supported if _lt(low, oldest_supported) else low
                if _lt(bottom, high):
                    ranges.append({"introduced": bottom, "limit": high, "unsure": True})
        previous = f.branch
    return ranges, any(r.get("unsure") for r in ranges)

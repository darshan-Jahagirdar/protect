"""Priority scoring (DESIGN.md §4.6). Simple, explainable, pure.

Every point added or taken away comes with a reason the dashboard shows, so the team can
see why something is P1 instead of trusting a black box.
"""

from dataclasses import dataclass

from app.enums import Priority


@dataclass(frozen=True)
class ScoreInput:
    cvss_score: float | None
    cvss_vector: str | None = None
    network_unauthenticated: bool | None = None
    kev: bool = False
    exploited: bool = False
    risk_tags: tuple[str, ...] = ()
    component_active: bool = True
    shielded: bool = False


@dataclass(frozen=True)
class Score:
    points: int
    priority: Priority
    reasons: tuple[str, ...]


def _severity(cvss: float | None) -> tuple[int, str]:
    if cvss is None:
        return 25, "CVSS unknown, assumed high (+25)"
    if cvss >= 9.0:
        return 40, f"CVSS {cvss:g}, critical (+40)"
    if cvss >= 7.0:
        return 25, f"CVSS {cvss:g}, high (+25)"
    if cvss >= 4.0:
        return 10, f"CVSS {cvss:g}, medium (+10)"
    return 3, f"CVSS {cvss:g}, low (+3)"


def _remote_unauthenticated(inp: ScoreInput) -> bool:
    if inp.network_unauthenticated is not None:
        return inp.network_unauthenticated
    parts = set((inp.cvss_vector or "").split("/"))
    return "AV:N" in parts and "PR:N" in parts


def priority_for(points: int) -> Priority:
    if points >= 70:
        return Priority.P1
    if points >= 50:
        return Priority.P2
    if points >= 30:
        return Priority.P3
    return Priority.P4


def score(inp: ScoreInput) -> Score:
    points, first = _severity(inp.cvss_score)
    reasons = [first]

    if inp.kev:
        points += 30
        reasons.append("listed in CISA's known-exploited catalogue (+30)")
    elif inp.exploited:
        points += 30
        reasons.append("credible reports of exploitation (+30)")

    if _remote_unauthenticated(inp):
        points += 10
        reasons.append("attackable remotely without a login (+10)")

    if "ecommerce" in inp.risk_tags:
        points += 10
        reasons.append("site takes payments (+10)")
    if "personal_data" in inp.risk_tags:
        points += 10
        reasons.append("site holds personal data (+10)")

    if not inp.component_active:
        points -= 10
        reasons.append("component is inactive (-10)")
    if inp.shielded:
        points -= 5
        reasons.append("edge firewall rule confirmed active (-5)")

    return Score(points, priority_for(points), tuple(reasons))

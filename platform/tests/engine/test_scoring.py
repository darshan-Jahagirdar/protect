import pytest

from app.engine.scoring import ScoreInput, priority_for, score
from app.enums import Priority


@pytest.mark.parametrize(
    ("inp", "points", "priority"),
    [
        # PHP2Shell on a plain site: 40 + 30 + 10 (DESIGN.md §4.6 worked example)
        (ScoreInput(9.2, exploited=True, network_unauthenticated=True), 80, Priority.P1),
        # ...on a shop that also holds customer data
        (
            ScoreInput(
                9.2,
                exploited=True,
                network_unauthenticated=True,
                risk_tags=("ecommerce", "personal_data"),
            ),
            100,
            Priority.P1,
        ),
        # ...behind a confirmed WAF rule: still P1
        (
            ScoreInput(9.2, exploited=True, network_unauthenticated=True, shielded=True),
            75,
            Priority.P1,
        ),
        # KEV counts once, even when also marked exploited
        (ScoreInput(9.8, kev=True, exploited=True), 70, Priority.P1),
        (ScoreInput(7.5, network_unauthenticated=True), 35, Priority.P3),
        (
            ScoreInput(7.5, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            35,
            Priority.P3,
        ),
        (
            ScoreInput(7.5, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
            25,
            Priority.P4,
        ),
        # The drill: high CVSS, remote, but the plugin is inactive
        (ScoreInput(7.2, network_unauthenticated=True, component_active=False), 25, Priority.P4),
        (ScoreInput(5.0), 10, Priority.P4),
        (ScoreInput(2.0), 3, Priority.P4),
        # Unknown severity is assumed high, never low
        (ScoreInput(None, exploited=True), 55, Priority.P2),
    ],
)
def test_score(inp: ScoreInput, points: int, priority: Priority) -> None:
    s = score(inp)
    assert s.points == points
    assert s.priority is priority
    assert s.reasons  # always explained


def test_explicit_flag_beats_vector() -> None:
    inp = ScoreInput(7.5, cvss_vector="AV:N/PR:N", network_unauthenticated=False)
    assert score(inp).points == 25


def test_reasons_are_readable() -> None:
    s = score(ScoreInput(9.2, exploited=True, network_unauthenticated=True, component_active=False))
    assert s.reasons == (
        "CVSS 9.2, critical (+40)",
        "credible reports of exploitation (+30)",
        "attackable remotely without a login (+10)",
        "component is inactive (-10)",
    )


@pytest.mark.parametrize(
    ("points", "priority"),
    [
        (70, Priority.P1),
        (69, Priority.P2),
        (50, Priority.P2),
        (49, Priority.P3),
        (30, Priority.P3),
        (29, Priority.P4),
        (-5, Priority.P4),
    ],
)
def test_priority_bands(points: int, priority: Priority) -> None:
    assert priority_for(points) is priority

"""Alert wording. Rule R9: counts only.

These functions never receive a Site, a URL or a business name, so they can't leak one.
Advisory titles and CVE/GHSA ids are public, so they're fine to include.
"""

from dataclasses import dataclass

from app.enums import Priority


@dataclass(frozen=True)
class IncidentSummary:
    """Everything an alert may say about an incident. Deliberately site-free."""

    incident_id: str
    title: str
    priority: Priority
    drill: bool
    aliases: tuple[str, ...]
    vulnerable: int
    needs_check: int

    @property
    def affected(self) -> int:
        return self.vulnerable + self.needs_check


def _prefix(s: IncidentSummary) -> str:
    return "[Protect] " + ("[DRILL] " if s.drill else "")


def _sites(n: int) -> str:
    return f"{n} site{'s' if n != 1 else ''}"


def _footer(s: IncidentSummary, base_url: str) -> str:
    return (
        f"\nOpen the dashboard to see which sites and what to do:\n"
        f"{base_url.rstrip('/')}/incidents/{s.incident_id}\n\n"
        "This alert lists counts only. Site details stay behind the dashboard login."
    )


def _facts(s: IncidentSummary) -> str:
    ids = ", ".join(s.aliases) if s.aliases else "none"
    return (
        f"{'[DRILL] practice incident, not a real vulnerability.\n' if s.drill else ''}"
        f"{s.priority.value} incident: {s.title}\n"
        f"Advisory ids: {ids}\n"
        f"Sites affected: {s.affected} (vulnerable: {s.vulnerable}, needs check: {s.needs_check})\n"
    )


def new_incident(s: IncidentSummary, base_url: str) -> tuple[str, str]:
    subject = f"{_prefix(s)}{s.priority.value}: {_sites(s.affected)} affected by {s.title}"
    return subject, _facts(s) + _footer(s, base_url)


def more_sites(s: IncidentSummary, previous: int, base_url: str) -> tuple[str, str]:
    subject = (
        f"{_prefix(s)}{s.priority.value} update: now {_sites(s.affected)} affected by {s.title}"
    )
    body = f"The number of affected sites went from {previous} to {s.affected}.\n\n"
    return subject, body + _facts(s) + _footer(s, base_url)


def unacknowledged(s: IncidentSummary, minutes: int, base_url: str) -> tuple[str, str]:
    subject = (
        f"{_prefix(s)}[UNACKNOWLEDGED] {s.priority.value}: "
        f"{_sites(s.affected)} affected by {s.title}"
    )
    body = (
        f"Nobody has acknowledged this alert for {minutes} minutes. "
        'Open the dashboard and press "I\'m on it".\n\n'
    )
    return subject, body + _facts(s) + _footer(s, base_url)


def digest(summaries: list[IncidentSummary], base_url: str) -> tuple[str, str]:
    lines = [
        f"- {'[DRILL] ' if s.drill else ''}{s.priority.value} {s.title}: {_sites(s.affected)}"
        f"  {base_url.rstrip('/')}/incidents/{s.incident_id}"
        for s in summaries
    ]
    subject = f"[Protect] Daily digest: {len(summaries)} open lower-priority incident(s)"
    body = (
        "Open P3/P4 incidents (counts only):\n\n" + "\n".join(lines) + "\n\n"
        "Site details stay behind the dashboard login."
    )
    return subject, body

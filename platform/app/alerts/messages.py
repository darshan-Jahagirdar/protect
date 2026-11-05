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


def one_line(text: str) -> str:
    """Titles come from feeds. A line break in an email subject broke every send (and could
    add headers), so subjects and title lines are always flattened to one line."""
    return " ".join("".join(" " if ord(ch) < 32 or ord(ch) == 127 else ch for ch in text).split())


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
        f"{s.priority.value} incident: {one_line(s.title)}\n"
        f"Advisory ids: {ids}\n"
        f"Sites affected: {s.affected} (vulnerable: {s.vulnerable}, needs check: {s.needs_check})\n"
    )


def new_incident(s: IncidentSummary, base_url: str) -> tuple[str, str]:
    subject = f"{_prefix(s)}{s.priority.value}: {_sites(s.affected)} affected by {s.title}"
    return one_line(subject), _facts(s) + _footer(s, base_url)


def more_sites(s: IncidentSummary, previous: int, base_url: str) -> tuple[str, str]:
    subject = (
        f"{_prefix(s)}{s.priority.value} update: now {_sites(s.affected)} affected by {s.title}"
    )
    body = f"The number of affected sites went from {previous} to {s.affected}.\n\n"
    return one_line(subject), body + _facts(s) + _footer(s, base_url)


def unacknowledged(s: IncidentSummary, minutes: int, base_url: str) -> tuple[str, str]:
    subject = (
        f"{_prefix(s)}[UNACKNOWLEDGED] {s.priority.value}: "
        f"{_sites(s.affected)} affected by {s.title}"
    )
    body = (
        f"Nobody has acknowledged this alert for {minutes} minutes. "
        'Open the dashboard and press "I\'m on it".\n\n'
    )
    return one_line(subject), body + _facts(s) + _footer(s, base_url)


def digest(summaries: list[IncidentSummary], base_url: str) -> tuple[str, str]:
    lines = [
        f"- {'[DRILL] ' if s.drill else ''}{s.priority.value} {one_line(s.title)}: "
        f"{_sites(s.affected)}"
        f"  {base_url.rstrip('/')}/incidents/{s.incident_id}"
        for s in summaries
    ]
    subject = f"[Protect] Daily digest: {len(summaries)} open lower-priority incident(s)"
    body = (
        "Open P3/P4 incidents (counts only):\n\n" + "\n".join(lines) + "\n\n"
        "Site details stay behind the dashboard login."
    )
    return subject, body


def review_needed(
    advisory_id: int, title: str, aliases: tuple[str, ...], sites: int, base_url: str
) -> tuple[str, str]:
    """A feed advisory whose versions a person must confirm may affect some sites."""
    subject = f"[Protect] Review needed: possible match on {_sites(sites)}: {title}"
    body = (
        "A new advisory came in without versions Protect can trust on its own. If its likely "
        f"versions are right, it affects {_sites(sites)}.\n"
        "Nothing is opened until a person confirms the affected versions.\n\n"
        f"Advisory: {one_line(title)}\n"
        f"Advisory ids: {', '.join(aliases) if aliases else 'none'}\n\n"
        "Review it here:\n"
        f"{base_url.rstrip('/')}/advisories/{advisory_id}\n\n"
        "This alert lists counts only. Site details stay behind the dashboard login."
    )
    return one_line(subject), body


def feed_failing(label: str, failures: int, base_url: str) -> tuple[str, str]:
    subject = f"[Protect] Feed problem: {label} failed {failures} times in a row"
    body = (
        f"Protect couldn't read {label} {failures} times in a row. New advisories from this "
        "source aren't arriving until it works again. Protect keeps retrying on its own.\n\n"
        "See the feed status and the last error here:\n"
        f"{base_url.rstrip('/')}/feeds\n\n"
        "You'll get this once per outage."
    )
    return one_line(subject), body

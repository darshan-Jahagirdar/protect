"""Turning a report's file checks into findings people can act on (DESIGN.md §4.12).

Wording rule: never "clean". The best a report can say is "no warning signs found", because a
compromised site can lie in its own reports.
"""

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.enums import IncidentStatus
from app.models import Case, Event, Incident, Report, Site
from app.services.incidents import RESOLVED

HIGH, MEDIUM, LOW, INFO = "high", "medium", "low", "info"
WARNING_LEVELS = (HIGH, MEDIUM)


@dataclass(frozen=True)
class Finding:
    key: str  # stable id, e.g. "uploads_php" or "plugin:hello-dolly"
    level: str
    title: str
    advice: str
    paths: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_warning(self) -> bool:
        return self.level in WARNING_LEVELS


def _versions(payload: dict[str, Any] | None, section: str) -> dict[str, str | None]:
    return {p["slug"]: p.get("version") for p in (payload or {}).get(section, [])}


def _updated_folders(payload: dict[str, Any], previous: dict[str, Any] | None) -> set[str]:
    """Plugin/theme folders whose version changed since the previous report."""
    if previous is None:
        return set()
    out = set()
    for section, folder in (("plugins", "wp-content/plugins/"), ("themes", "wp-content/themes/")):
        before, now = _versions(previous, section), _versions(payload, section)
        out |= {folder + slug + "/" for slug, v in now.items() if before.get(slug) != v}
    return out


def findings_for(
    site: Site, report: Report | None, previous: Report | None = None
) -> list[Finding]:
    if report is None:
        return [Finding("no_report", INFO, "No report received yet", "Connect the plugin.")]
    payload = report.payload
    checks = payload.get("checks") or {}
    out: list[Finding] = []

    scan = checks.get("scan") or {}
    if not scan.get("complete"):
        out.append(
            Finding(
                "scan_pending",
                INFO,
                "File scan hasn't finished yet",
                "It runs in small batches; results arrive with a later report.",
            )
        )
        return out

    core = checks.get("core") or {}
    if core.get("modified"):
        out.append(
            Finding(
                "core_modified",
                HIGH,
                "WordPress core files differ from the official release",
                "Compare with a fresh copy of the same WordPress version; reinstall core if they "
                "weren't changed on purpose.",
                tuple(core["modified"]),
            )
        )
    if core.get("unexpected"):
        out.append(
            Finding(
                "core_unexpected",
                HIGH,
                "Unexpected PHP files in wp-admin or wp-includes",
                "WordPress doesn't ship these. A classic place for a backdoor.",
                tuple(core["unexpected"]),
            )
        )
    if core.get("status") == "unavailable":
        out.append(
            Finding(
                "core_unavailable",
                INFO,
                "Couldn't check WordPress core files",
                "The site couldn't reach api.wordpress.org for the official list.",
            )
        )

    for plugin in checks.get("plugins") or []:
        if plugin.get("status") == "mismatch":
            out.append(
                Finding(
                    f"plugin:{plugin['slug']}",
                    HIGH,
                    f"Plugin {plugin['slug']} differs from its official release",
                    "Reinstall the plugin from wordpress.org and check the listed files.",
                    tuple(plugin.get("modified") or ()),
                )
            )
    unverifiable = [
        p["slug"] for p in checks.get("plugins") or [] if p.get("status") == "unverifiable"
    ]
    if unverifiable:
        out.append(
            Finding(
                "plugins_unverifiable",
                INFO,
                "Plugins that can't be verified (not on wordpress.org)",
                "Premium or custom plugins: keep them updated from their vendor.",
                tuple(unverifiable),
            )
        )

    if checks.get("uploads_php"):
        out.append(
            Finding(
                "uploads_php",
                HIGH,
                "PHP files in the uploads folder",
                "Uploads should only hold media. Look at each file before deleting it, and keep a "
                "copy if the client may need an investigation.",
                tuple(checks["uploads_php"]),
            )
        )

    prepend = checks.get("auto_prepend") or {}
    if prepend.get("set"):
        where = prepend.get("location") or "unknown"
        note = " Wordfence's firewall uses this on purpose." if "wordfence" in where.lower() else ""
        out.append(
            Finding(
                "auto_prepend",
                MEDIUM,
                "PHP runs an extra file before every page (auto_prepend_file)",
                "Confirm who set it and why." + note,
                (where,),
            )
        )
    if checks.get("user_ini"):
        out.append(
            Finding(
                "user_ini",
                MEDIUM,
                ".user.ini files found",
                "They can change PHP settings, including auto_prepend_file. Hosts sometimes add "
                "them; confirm each one.",
                tuple(checks["user_ini"]),
            )
        )

    allow = set(site.mu_plugin_allowlist or [])
    unknown_mu = [p for p in checks.get("mu_plugins_present") or [] if p not in allow]
    if unknown_mu:
        out.append(
            Finding(
                "mu_unknown",
                MEDIUM,
                "Must-use plugins not on this site's allowlist",
                "mu-plugins load automatically and nobody looks there. Mark each as expected "
                "once you know what it is.",
                tuple(unknown_mu),
            )
        )

    updated = _updated_folders(payload, previous.payload if previous else None)
    recent = [
        p
        for p in checks.get("recent_php_changes") or []
        if not any(p.startswith(folder) for folder in updated)
    ]
    if recent:
        out.append(
            Finding(
                "recent_php",
                LOW,
                "PHP files changed since the previous scan",
                "Often just an update. A hint, not proof: file dates can be faked.",
                tuple(recent),
            )
        )
    return out


def latest_findings(session: Session, site: Site) -> list[Finding]:
    report = session.get(Report, site.last_report_id) if site.last_report_id else None
    previous = None
    if report is not None:
        previous = session.scalar(
            select(Report)
            .where(Report.site_id == site.id, Report.id < report.id)
            .order_by(Report.id.desc())
        )
    return findings_for(site, report, previous)


def warning_keys(findings: list[Finding]) -> set[str]:
    return {f"{f.key}|{p}" for f in findings if f.is_warning for p in (f.paths or ("",))}


def note_new_warning_signs(
    session: Session, site: Site, report: Report, previous: Report | None
) -> list[Finding]:
    """New high/medium findings go onto the timeline of the site's open cases."""
    now = findings_for(site, report, previous)
    before = findings_for(site, previous) if previous else []
    new_keys = warning_keys(now) - warning_keys(before)
    if not new_keys:
        return []
    new = [f for f in now if f.is_warning and any(k.startswith(f.key + "|") for k in new_keys)]
    summary = "; ".join(f"{f.title} ({len(f.paths) or 1})" for f in new)
    open_cases = session.scalars(
        select(Case)
        .join(Incident)
        .where(
            Case.site_id == site.id,
            Incident.status != IncidentStatus.CLOSED,
            Case.exposure.not_in(RESOLVED),
        )
    ).all()
    for case in open_cases:
        session.add(
            Event(
                incident_id=case.incident_id,
                case_id=case.id,
                type="warning_signs",
                note=f"file checks found: {summary}",
                data={"keys": sorted(new_keys)[:50]},
            )
        )
    return new

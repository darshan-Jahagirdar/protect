"""What people do to a case from the dashboard. Every action records who did it and when.

The engine owns vulnerable <-> needs_check. People own fix_claimed, false_positive,
accepted_risk and not_affected, plus shielded, compromise and checklist ticks.
"""

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checklists.loader import ChecklistTemplate, RenderedItem, render, template_for
from app.db import utcnow
from app.enums import ChecklistItemKind, Compromise, Exposure, HostType
from app.models import (
    Advisory,
    Case,
    ChecklistItem,
    Event,
    IncidentAdvisory,
    Site,
    User,
)
from app.services.incidents import DONE, apply_advisory

DECISIONS = {Exposure.FALSE_POSITIVE, Exposure.ACCEPTED_RISK, Exposure.NOT_AFFECTED}
OPEN = {Exposure.VULNERABLE, Exposure.NEEDS_CHECK}

_HOST_LABEL = {
    HostType.MANAGED_WP: "the managed host",
    HostType.CPANEL: "the host",
    HostType.VPS: "our server provider",
    HostType.UNKNOWN: "the host",
}


class CaseActionError(ValueError):
    """Shown to the user as-is; never contains anything they didn't type or can't see."""


def _event(
    session: Session, case: Case, user: User, type_: str, note: str | None = None, **data: object
) -> None:
    session.add(
        Event(
            incident_id=case.incident_id,
            case_id=case.id,
            actor_user_id=user.id,
            type=type_,
            note=note,
            data=data,
        )
    )


def _advisories(session: Session, case: Case) -> list[Advisory]:
    return list(
        session.scalars(
            select(Advisory)
            .join(IncidentAdvisory, IncidentAdvisory.advisory_id == Advisory.id)
            .where(IncidentAdvisory.incident_id == case.incident_id)
        )
    )


def _rematch(session: Session, case: Case) -> None:
    site = session.get(Site, case.site_id)
    for advisory in _advisories(session, case):
        apply_advisory(session, advisory, [site])


def _required(note: str | None, what: str) -> str:
    note = (note or "").strip()
    if not note:
        raise CaseActionError(f"Please add a note saying why ({what}).")
    if len(note) > 1000:
        raise CaseActionError("Notes are limited to 1000 characters.")
    return note


# --- Exposure decisions ----------------------------------------------------------------


def claim_fix(session: Session, case: Case, user: User, note: str | None = None) -> None:
    if case.exposure not in OPEN:
        raise CaseActionError("Only an open case can be marked as fixed.")
    case.exposure = Exposure.FIX_CLAIMED
    _event(session, case, user, "fix_claimed", (note or "").strip()[:1000] or None)


def decide(session: Session, case: Case, user: User, decision: Exposure, note: str | None) -> None:
    if decision not in DECISIONS:
        raise CaseActionError("Unknown decision.")
    if case.exposure in DONE and case.exposure is not Exposure.NOT_AFFECTED:
        raise CaseActionError("This case is already verified.")
    text = _required(note, decision.value.replace("_", " "))
    before = case.exposure
    case.exposure = decision
    _event(session, case, user, "decision", text, decision=decision.value, before=before.value)


def undo_decision(session: Session, case: Case, user: User) -> None:
    """Hand the case back to the engine, which re-checks it against the latest report."""
    if case.exposure not in DECISIONS | {Exposure.FIX_CLAIMED}:
        raise CaseActionError("There's no decision to undo.")
    before = case.exposure
    case.exposure = Exposure.VULNERABLE
    _event(session, case, user, "decision_undone", before=before.value)
    session.flush()
    _rematch(session, case)


# --- Shield and compromise ----------------------------------------------------------------


def set_shield(session: Session, case: Case, user: User, on: bool, note: str | None) -> None:
    if on:
        text = _required(note, "which firewall rule, and how you confirmed it")
        case.shielded, case.shield_note = True, text
        _event(session, case, user, "shielded", text)
    else:
        case.shielded, case.shield_note = False, None
        _event(session, case, user, "shield_removed")
    session.flush()
    _rematch(session, case)  # the score changes by 5 points


def set_compromise(
    session: Session, case: Case, user: User, value: Compromise, note: str | None
) -> None:
    text = _required(note, "what was found") if value is not Compromise.NONE else note
    case.compromise = value
    _event(session, case, user, "compromise", text, value=value.value)


# --- Checklist ------------------------------------------------------------------------------


@dataclass(frozen=True)
class ChecklistRow:
    item: RenderedItem
    done: bool
    done_by: str | None
    done_at: str | None
    note: str | None


def _fix_text(case: Case) -> str:
    label = "PHP " if case.component_key == "php" else ""
    if case.unsupported_branch:
        return "a supported PHP branch" if case.component_key == "php" else "a supported version"
    if case.fixed_version:
        return f"{label}{case.fixed_version} or newer"
    return "a fixed version (none published yet)"


def checklist_template(session: Session, case: Case) -> ChecklistTemplate:
    site = session.get(Site, case.site_id)
    return template_for(case.incident.kind, site.host_type.value if site else "default")


def checklist(session: Session, case: Case) -> tuple[ChecklistTemplate, list[ChecklistRow]]:
    site = session.get(Site, case.site_id)
    template = checklist_template(session, case)
    ids = sorted({a for adv in _advisories(session, case) for a in adv.aliases})
    values = {
        "component": case.component_key.split(":", 1)[-1],
        "current_version": case.version_seen or "?",
        "fix_text": _fix_text(case),
        "advisory_ids": ", ".join(ids) or "this advisory",
        "host": (
            site.host_name
            if site and site.host_name
            else _HOST_LABEL[site.host_type]
            if site
            else "the host"
        ),
    }
    ticks = {
        t.item_key: t
        for t in session.scalars(select(ChecklistItem).where(ChecklistItem.case_id == case.id))
    }
    rows = []
    for item in render(template, values):
        if item.kind == "auto":
            rows.append(ChecklistRow(item, case.exposure in DONE, "system", None, None))
            continue
        tick = ticks.get(item.key)
        done = tick is not None and tick.done_at is not None
        user = session.get(User, tick.done_by) if done and tick.done_by else None
        rows.append(
            ChecklistRow(
                item,
                done,
                user.display_name if user else None,
                tick.done_at.strftime("%Y-%m-%d %H:%M UTC") if done else None,
                tick.note if tick else None,
            )
        )
    return template, rows


def tick(
    session: Session, case: Case, user: User, item_key: str, done: bool, note: str | None = None
) -> None:
    template = checklist_template(session, case)
    item = next((i for i in template.items if i.key == item_key), None)
    if item is None:
        raise CaseActionError("That checklist item doesn't exist.")
    if item.kind != "manual":
        raise CaseActionError("That step is ticked automatically.")
    row = session.scalar(
        select(ChecklistItem).where(
            ChecklistItem.case_id == case.id, ChecklistItem.item_key == item_key
        )
    )
    if row is None:
        row = ChecklistItem(
            case_id=case.id,
            template_key=template.key,
            item_key=item_key,
            kind=ChecklistItemKind.MANUAL,
        )
        session.add(row)
    text = (note or "").strip()[:1000] or None
    if done:
        row.done_by, row.done_at, row.note = user.id, utcnow(), text
    else:
        row.done_by, row.done_at = None, None
    _event(
        session,
        case,
        user,
        "checklist_done" if done else "checklist_undone",
        f"{item_key}: {text}" if text else item_key,
    )

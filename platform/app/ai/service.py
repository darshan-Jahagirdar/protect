"""AI-written incident summaries and client-message drafts (DESIGN.md §4.10).

- Inputs come only from app/ai/inputs.py (site-free). The site name is put into a draft by
  Protect afterwards, on the team's screen; the AI never sees it.
- One summary and one draft text per incident and input, cached in ai_results.
- Drafts are only ever sent by a person: save → approve → mark sent. Nothing is emailed.
"""

import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai import prompts
from app.ai.inputs import facts_for
from app.ai.providers import Provider
from app.db import utcnow
from app.enums import ClientNotice
from app.models import AIResult, Case, Draft, Event, Incident, Site, User
from app.services import cases as case_actions

MAX_LEN = 6000
TASK_SUMMARY, TASK_DRAFT = "incident_summary", "client_draft"
_BANNED_CLAIMS = re.compile(
    r"unhackable|fully protected|guaranteed(ly)? secure|guaranteed security|"
    r"complete protection|totally (safe|secure)|no data was (accessed|stolen)",
    re.IGNORECASE,
)
_PLACEHOLDER = re.compile(r"\{\{[A-Z_]+\}\}")


class DraftError(ValueError):
    """Shown to the user as-is."""


def _cached(session: Session, incident: Incident, task: str, digest: str) -> AIResult | None:
    return session.scalar(
        select(AIResult)
        .where(
            AIResult.incident_id == incident.id,
            AIResult.task == task,
            AIResult.input_hash == digest,
            AIResult.prompt_version == prompts.PROMPT_VERSION,
        )
        .order_by(AIResult.id.desc())
    )


def _generate(
    session: Session,
    incident: Incident,
    task: str,
    provider: Provider,
    thinking: str,
    force: bool = False,
) -> AIResult:
    facts = facts_for(session, incident)
    digest = facts.digest()
    if not force and (hit := _cached(session, incident, task, digest)):
        return hit
    prompt = (
        prompts.incident_summary(facts) if task == TASK_SUMMARY else prompts.client_draft(facts)
    )
    out = provider.generate(prompts.SYSTEM, prompt, thinking)
    result = AIResult(
        incident_id=incident.id,
        task=task,
        provider=out.provider,
        model=out.model,
        prompt_version=prompts.PROMPT_VERSION,
        input_hash=digest,
        content=out.text[:MAX_LEN],
    )
    session.add(result)
    session.flush()
    return result


def incident_summary(
    session: Session, incident: Incident, provider: Provider, thinking: str, force: bool = False
) -> AIResult:
    return _generate(session, incident, TASK_SUMMARY, provider, thinking, force)


def latest_summary(session: Session, incident: Incident) -> AIResult | None:
    return session.scalar(
        select(AIResult)
        .where(AIResult.incident_id == incident.id, AIResult.task == TASK_SUMMARY)
        .order_by(AIResult.id.desc())
    )


# --- Client drafts, one per case -----------------------------------------------------------


def draft_for(session: Session, case: Case) -> Draft | None:
    return session.scalar(select(Draft).where(Draft.case_id == case.id).order_by(Draft.id.desc()))


def _event(session: Session, case: Case, user: User, type_: str, note: str | None = None) -> None:
    session.add(
        Event(
            incident_id=case.incident_id,
            case_id=case.id,
            actor_user_id=user.id,
            type=type_,
            note=note,
        )
    )


def create_draft(
    session: Session, case: Case, user: User, provider: Provider, thinking: str
) -> Draft:
    if draft_for(session, case) is not None:
        raise DraftError("This case already has a draft.")
    result = _generate(session, case.incident, TASK_DRAFT, provider, thinking)
    site = session.get(Site, case.site_id)
    # Filled in by Protect for the team, after the AI step. {{CLIENT_NAME}} and {{FIX_TIME}}
    # are left for a person: client contacts are never stored (rule R6).
    content = result.content.replace(
        "{{SITE_NAME}}", site.business_name if site else "{{SITE_NAME}}"
    )
    content = content.replace("{{SENDER_NAME}}", user.display_name)
    draft = Draft(
        incident_id=case.incident_id, case_id=case.id, content=content, ai_result_id=result.id
    )
    session.add(draft)
    case.client_notice = ClientNotice.DRAFTED
    _event(session, case, user, "draft_created", f"{result.provider}/{result.model}")
    session.flush()
    return draft


def save_draft(session: Session, case: Case, draft: Draft, user: User, content: str) -> None:
    if draft.sent_at is not None:
        raise DraftError("This message was already sent.")
    text = content.replace("\r\n", "\n").strip()
    if not text:
        raise DraftError("The message can't be empty.")
    if len(text) > MAX_LEN:
        raise DraftError(f"Messages are limited to {MAX_LEN} characters.")
    draft.content = text
    draft.approved_by, draft.approved_at = None, None  # an edit needs a fresh approval
    case.client_notice = ClientNotice.DRAFTED
    _event(session, case, user, "draft_edited")


def draft_warnings(draft: Draft, drill: bool) -> list[str]:
    warnings = []
    left = sorted(set(_PLACEHOLDER.findall(draft.content)))
    if left:
        warnings.append("Fill in before approving: " + ", ".join(left))
    if m := _BANNED_CLAIMS.search(draft.content):
        warnings.append(f'Remove the claim "{m.group(0)}": we never promise security.')
    if drill and "[DRILL]" not in draft.content:
        warnings.append("This is a drill: keep the [DRILL] line so it's never sent to a client.")
    return warnings


def approve_draft(session: Session, case: Case, draft: Draft, user: User) -> None:
    problems = draft_warnings(draft, case.incident.drill)
    if problems:
        raise DraftError(" ".join(problems))
    draft.approved_by, draft.approved_at = user.id, utcnow()
    case.client_notice = ClientNotice.APPROVED
    _event(session, case, user, "draft_approved")


def mark_sent(session: Session, case: Case, draft: Draft, user: User) -> None:
    """The person sent it themselves (e.g. from Outlook). Protect only records that."""
    if draft.approved_at is None:
        raise DraftError("Approve the message before marking it sent.")
    if draft.sent_at is not None:
        raise DraftError("Already marked as sent.")
    draft.sent_marked_by, draft.sent_at = user.id, utcnow()
    case_actions.tick(session, case, user, "client_notice", True, "client message sent")

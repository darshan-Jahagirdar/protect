"""What the AI is allowed to see (rule R7). This module is the allowlist.

Only advisory text, component names with versions, and fixed versions. Never a site, URL,
business name, contact, file path, report or anything else from a client. The builder takes
an incident and returns this site-free structure; prompts are made from it and nothing else.
"""

import json
from dataclasses import asdict, dataclass
from hashlib import sha256

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Advisory, Incident, IncidentAdvisory


@dataclass(frozen=True)
class ComponentFact:
    component: str  # e.g. "php", "wp-plugin:hello-dolly"
    version: str | None
    fixed_version: str | None
    unsupported_branch: bool


@dataclass(frozen=True)
class AdvisoryFacts:
    title: str
    ids: tuple[str, ...]
    summary: str  # public advisory text: untrusted input, treated as data in prompts
    cvss: float | None
    # Wording matters: "reported" is not "confirmed". The model once wrote "confirmed
    # exploitation" from a bare `exploited: true`.
    exploitation_attempts_reported: bool
    in_cisa_known_exploited_list: bool
    affected_ranges: tuple[str, ...]  # e.g. "php: 8.3.0 up to (not including) 8.3.36"
    fixed_versions: tuple[str, ...]
    components: tuple[ComponentFact, ...]
    drill: bool

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, indent=2)

    def digest(self) -> str:
        return sha256(self.to_json().encode()).hexdigest()


def _describe(component: str, rng: dict) -> str:  # type: ignore[type-arg]
    start = rng.get("introduced", "0")
    start_text = "all versions" if start == "0" else start
    if rng.get("fixed"):
        return f"{component}: {start_text} up to (not including) {rng['fixed']}"
    if rng.get("last_affected"):
        return f"{component}: {start_text} up to and including {rng['last_affected']}"
    if rng.get("limit"):
        tail = " (end-of-life branches, no fix will be released)" if rng.get("unsupported") else ""
        return f"{component}: {start_text} up to (not including) {rng['limit']}{tail}"
    return f"{component}: {start_text} and later (no fix yet)"


def facts_for(session: Session, incident: Incident) -> AdvisoryFacts:
    advisories = list(
        session.scalars(
            select(Advisory)
            .join(IncidentAdvisory, IncidentAdvisory.advisory_id == Advisory.id)
            .where(IncidentAdvisory.incident_id == incident.id)
            .order_by(Advisory.id)
        )
    )
    ids: list[str] = []
    fixed: list[str] = []
    ranges: list[str] = []
    for adv in advisories:
        ids += [a for a in adv.aliases if a not in ids]
        for affect in adv.affects:
            fixed += [v for v in affect.fixed_versions if v not in fixed]
            ranges += [
                r
                for r in (_describe(affect.component_key, rng) for rng in affect.ranges)
                if r not in ranges
            ]
    # One entry per distinct (component, version) across sites. Which site has which version
    # never reaches the AI.
    components = sorted(
        {
            ComponentFact(c.component_key, c.version_seen, c.fixed_version, c.unsupported_branch)
            for c in incident.cases
        },
        key=lambda f: (f.component, f.version or ""),
    )
    first = advisories[0] if advisories else None
    return AdvisoryFacts(
        title=incident.title,
        ids=tuple(ids),
        summary=(first.summary_text or "")[:4000] if first else "",
        cvss=first.cvss_score if first else None,
        exploitation_attempts_reported=any(a.exploited for a in advisories),
        in_cisa_known_exploited_list=any(a.kev for a in advisories),
        affected_ranges=tuple(ranges),
        fixed_versions=tuple(fixed),
        components=tuple(components),
        drill=incident.drill,
    )

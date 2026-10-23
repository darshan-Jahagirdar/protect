"""Storing advisories: replayed fixtures now, live feeds later (DESIGN.md §4.3)."""

import json
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.engine.catalogue import is_valid_key
from app.enums import ReviewStatus
from app.models import Advisory, AdvisoryAffect
from app.settings import PLATFORM_DIR

FIXTURES_DIR = PLATFORM_DIR / "fixtures" / "advisories"


class AdvisoryDataError(ValueError):
    pass


def fixture_names() -> list[str]:
    return sorted(p.stem for p in FIXTURES_DIR.glob("*.json"))


def load_fixture(name: str) -> dict[str, Any]:
    if name not in fixture_names():  # also blocks path tricks like "../x"
        raise AdvisoryDataError(f"no advisory fixture named {name!r}")
    return json.loads((FIXTURES_DIR / f"{name}.json").read_text())


def _parse_time(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def find_by_aliases(session: Session, aliases: list[str]) -> Advisory | None:
    wanted = set(aliases)
    for adv in session.scalars(select(Advisory)):
        if wanted & set(adv.aliases):
            return adv
    return None


def upsert_advisory(
    session: Session,
    data: dict[str, Any],
    review_status: ReviewStatus = ReviewStatus.CONFIRMED,
) -> Advisory:
    """Create the advisory, or update the one that shares any alias (CVE, GHSA, ...)."""
    aliases = list(dict.fromkeys(data.get("aliases") or []))
    if not aliases:
        raise AdvisoryDataError("an advisory needs at least one alias")
    for affect in data.get("affects") or []:
        if not is_valid_key(affect["component_key"]):
            raise AdvisoryDataError(f"invalid component key {affect['component_key']!r}")

    adv = find_by_aliases(session, aliases)
    if adv is None:
        adv = Advisory(aliases=aliases)
        session.add(adv)
    else:
        adv.aliases = list(dict.fromkeys([*adv.aliases, *aliases]))

    adv.title = data["title"]
    adv.source = data.get("source") or "manual"
    adv.source_url = data.get("source_url")
    adv.summary_text = data.get("summary_text")
    adv.cvss_score = data.get("cvss_score")
    adv.cvss_vector = data.get("cvss_vector")
    adv.network_unauthenticated = data.get("network_unauthenticated")
    adv.kev = bool(data.get("kev"))
    adv.exploited = bool(data.get("exploited"))
    adv.published_at = _parse_time(data.get("published_at"))
    adv.drill = bool(data.get("drill"))
    adv.review_status = review_status

    adv.affects.clear()
    for affect in data.get("affects") or []:
        adv.affects.append(
            AdvisoryAffect(
                component_key=affect["component_key"],
                ranges=affect.get("ranges") or [],
                fixed_versions=affect.get("fixed_versions") or [],
                distro_fixes=affect.get("distro_fixes") or {},
            )
        )
    session.flush()
    return adv

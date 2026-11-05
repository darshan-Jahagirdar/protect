"""Feed health for the dashboard: is each feed running, and when did it last work?"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import utcnow
from app.enums import FeedRunStatus
from app.feeds.registry import FEEDS
from app.feeds.runner import FAILURES_BEFORE_ALERT, FeedSpec, failing_streak
from app.models import FeedRun
from app.settings import Settings


@dataclass(frozen=True)
class FeedHealth:
    spec: FeedSpec
    state: str  # off, waiting, ok, late, failing, broken
    label: str
    last_run: FeedRun | None
    last_ok_at: datetime | None
    streak: int

    @property
    def needs_attention(self) -> bool:
        return self.state in ("broken", "late")


def feed_health(
    session: Session, settings: Settings, now: datetime | None = None
) -> list[FeedHealth]:
    now = now or utcnow()
    out = []
    for spec in FEEDS:
        last = session.scalar(
            select(FeedRun).where(FeedRun.source == spec.name).order_by(FeedRun.id.desc())
        )
        last_ok = session.scalar(
            select(FeedRun.finished_at)
            .where(FeedRun.source == spec.name, FeedRun.status == FeedRunStatus.OK)
            .order_by(FeedRun.id.desc())
        )
        streak = failing_streak(session, spec.name)
        if not spec.enabled(settings):
            state, label = (
                "off",
                ("off: needs an API key" if spec.needs else "off: feeds are switched off"),
            )
        elif last is None:
            state, label = "waiting", "hasn't run yet"
        elif streak >= FAILURES_BEFORE_ALERT:
            state, label = "broken", f"failed {streak} times in a row"
        elif streak:
            state, label = "failing", "last run failed; retrying"
        elif last_ok and now - last_ok > timedelta(minutes=spec.interval_minutes * 3):
            state, label = "late", "no good run for a while"
        else:
            state, label = "ok", "working"
        out.append(FeedHealth(spec, state, label, last, last_ok, streak))
    return out

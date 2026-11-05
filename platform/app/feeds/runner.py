"""Running feeds: one scheduler job per source, each run recorded in feed_runs.

A feed only downloads and parses public data. What it finds is stored through
app/services/advisories.py, and confirmed advisories are matched by the rules engine
(app/services/incidents.py). Feeds never decide whether a site is affected.

Three failed runs in a row send one internal email (counts only, no error text from outside),
and nothing more until the feed has worked again.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.alerts import messages
from app.alerts.mailer import Mailer, Message
from app.db import utcnow
from app.enums import FeedRunStatus, ReviewStatus
from app.feeds.clean import FeedDataError
from app.feeds.http import FeedFetchError, Fetcher, download
from app.models import FeedRun, FeedState
from app.services.advisories import AdvisoryDataError, ingest_feed_advisory
from app.services.incidents import apply_advisory
from app.settings import Settings

log = logging.getLogger("protect.feeds")

FAILURES_BEFORE_ALERT = 3


@dataclass
class FeedOutcome:
    new: int = 0
    updated: int = 0
    rejected: int = 0
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class FeedContext:
    session: Session
    fetch: Fetcher
    settings: Settings
    now: datetime


FeedFn = Callable[[FeedContext, FeedOutcome], None]


@dataclass(frozen=True)
class FeedSpec:
    name: str
    label: str  # shown on the dashboard and in alerts
    interval_minutes: int
    run: FeedFn
    needs: str | None = None  # a setting that must be present (an API key), else the feed is off

    def enabled(self, settings: Settings) -> bool:
        return settings.feeds_enabled and (
            self.needs is None or bool(getattr(settings, self.needs))
        )


def state(session: Session, source: str) -> FeedState:
    st = session.get(FeedState, source)
    if st is None:
        st = FeedState(source=source, data={})
        session.add(st)
        session.flush()
    return st


def kev_cves(session: Session) -> frozenset[str]:
    st = session.get(FeedState, "kev")
    return frozenset(st.data.get("cves", [])) if st else frozenset()


def store(
    ctx: FeedContext,
    out: FeedOutcome,
    source: str,
    item_id: str,
    data: dict[str, Any],
    review_status: ReviewStatus,
) -> None:
    """Store one cleaned item and, when confirmed and changed, match it against every site."""
    try:
        result = ingest_feed_advisory(
            ctx.session, source, item_id, data, review_status, kev_cves(ctx.session)
        )
    except AdvisoryDataError as e:
        out.rejected += 1
        log.warning("%s: item %s refused: %s", source, item_id[:80], str(e)[:200])
        return
    if result.created:
        out.new += 1
    elif result.changed:
        out.updated += 1
    adv = result.advisory
    if adv is not None and result.changed and adv.review_status is ReviewStatus.CONFIRMED:
        apply_advisory(ctx.session, adv)


def error_text(e: BaseException) -> str:
    """Our own wording only: exception text from parsers could carry feed content."""
    if isinstance(e, FeedFetchError | FeedDataError | AdvisoryDataError):
        return str(e)[:500]
    return f"unexpected {type(e).__name__} (details in the server log)"


def run_feed(
    session_factory: Callable[[], Session],
    mailer: Mailer,
    settings: Settings,
    spec: FeedSpec,
    fetch: Fetcher = download,
) -> FeedRun | None:
    """One scheduled run. Never raises: failures are recorded and counted."""
    if not spec.enabled(settings):
        return None
    with session_factory() as session:
        run = FeedRun(source=spec.name, started_at=utcnow(), status=FeedRunStatus.RUNNING)
        session.add(run)
        session.commit()
        run_id = run.id

    out = FeedOutcome()
    error: str | None = None
    with session_factory() as session:
        try:
            spec.run(FeedContext(session, fetch, settings, utcnow()), out)
            session.commit()
        except Exception as e:  # recorded, alerted after 3 in a row, retried next interval
            session.rollback()
            error = error_text(e)
            log.exception("feed %s failed", spec.name)

    with session_factory() as session:
        run = session.get_one(FeedRun, run_id)
        run.finished_at = utcnow()
        run.status = FeedRunStatus.FAILED if error else FeedRunStatus.OK
        run.items_new, run.items_updated, run.items_rejected = out.new, out.updated, out.rejected
        run.error = error or ("; ".join(out.notes)[:1000] or None)
        st = state(session, spec.name)
        if error is None:
            st.failure_alerted_at = None
        elif st.failure_alerted_at is None and failing_streak(session, spec.name) >= (
            FAILURES_BEFORE_ALERT
        ):
            if _send_failure_alert(mailer, settings, spec):
                st.failure_alerted_at = utcnow()
        session.commit()
        log.info(
            "feed %s %s: %d new, %d updated, %d refused",
            spec.name,
            run.status.value,
            out.new,
            out.updated,
            out.rejected,
        )
        return run


def failing_streak(session: Session, source: str) -> int:
    """How many of the latest finished runs failed, counting back to the last good one."""
    streak = 0
    for status in session.scalars(
        select(FeedRun.status)
        .where(FeedRun.source == source, FeedRun.status != FeedRunStatus.RUNNING)
        .order_by(FeedRun.id.desc())
        .limit(50)
    ):
        if status is not FeedRunStatus.FAILED:
            break
        streak += 1
    return streak


def _send_failure_alert(mailer: Mailer, settings: Settings, spec: FeedSpec) -> bool:
    to = settings.alert_recipient_list
    if not to:
        log.warning("no alert recipients configured; feed failure alert for %s not sent", spec.name)
        return False
    subject, body = messages.feed_failing(spec.label, FAILURES_BEFORE_ALERT, settings.base_url)
    try:
        mailer.send(Message(tuple(to), subject, body))
    except Exception:
        log.exception("sending the feed failure alert for %s failed", spec.name)
        return False
    return True

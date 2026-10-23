"""In-process scheduled jobs. The platform runs as ONE process, so each job runs once."""

import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from app.alerts.mailer import mailer_for
from app.db import SessionLocal
from app.services.alerting import run_alert_cycle, run_digest
from app.settings import Settings

log = logging.getLogger("protect.scheduler")


def start(settings: Settings) -> BackgroundScheduler:
    mailer = mailer_for(settings)
    scheduler = BackgroundScheduler(timezone="UTC")
    common = {"args": [SessionLocal, mailer, settings], "max_instances": 1, "coalesce": True}
    scheduler.add_job(run_alert_cycle, "interval", seconds=60, id="alerts", **common)
    scheduler.add_job(
        run_digest,
        CronTrigger(hour=settings.digest_hour_utc, minute=settings.digest_minute_utc),
        id="digest",
        **common,
    )
    scheduler.start()
    log.info(
        "scheduler started: alerts every 60s, digest daily at %02d:%02d UTC",
        settings.digest_hour_utc,
        settings.digest_minute_utc,
    )
    return scheduler

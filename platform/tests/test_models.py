from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session

from app import models
from app.db import Base, make_engine
from app.enums import Exposure, HostType, Priority, SiteStatus

PLATFORM_DIR = Path(__file__).resolve().parent.parent

CONTACT_WORDS = ("phone", "contact", "first_name", "last_name", "address", "visitor", "ip_addr")


def test_no_contact_fields_anywhere() -> None:
    """Rule R6: the database must never have contact or visitor fields."""
    for table in Base.metadata.tables.values():
        for column in table.columns:
            name = column.name.lower()
            assert not any(w in name for w in CONTACT_WORDS), f"{table.name}.{column.name}"
    # The only email column is our own team's login.
    email_cols = [
        f"{t.name}.{c.name}"
        for t in Base.metadata.tables.values()
        for c in t.columns
        if "email" in c.name
    ]
    assert email_cols == ["users.email"]


def test_site_incident_case_roundtrip(session: Session) -> None:
    site = models.Site(business_name="Demo Co", url="http://127.0.0.1:8081")
    session.add(site)
    session.flush()
    assert site.status is SiteStatus.PENDING
    assert site.host_type is HostType.UNKNOWN

    incident = models.Incident(title="PHP2Shell", kind="php-core", priority=Priority.P1)
    session.add(incident)
    session.flush()
    assert len(incident.id) >= 20  # random, unguessable id used in alert links

    case = models.Case(
        incident_id=incident.id,
        site_id=site.id,
        component_key="php",
        exposure=Exposure.VULNERABLE,
        priority=Priority.P1,
        score=80,
        score_reasons=["CVSS 9.2 (+40)", "exploited (+30)", "remote unauthenticated (+10)"],
    )
    session.add(case)
    session.commit()

    loaded = session.get(models.Case, case.id)
    assert loaded is not None
    assert loaded.exposure is Exposure.VULNERABLE
    assert loaded.created_at.tzinfo is not None  # always timezone-aware UTC


def test_enum_values_are_enforced(session: Session) -> None:
    session.add(models.Site(business_name="X", url="http://x.test", status="hacked"))  # type: ignore[arg-type]
    with pytest.raises(StatementError):
        session.flush()


def test_case_unique_per_incident_site_component(session: Session) -> None:
    site = models.Site(business_name="Demo", url="http://demo.test")
    incident = models.Incident(title="T", kind="php-core", priority=Priority.P2)
    session.add_all([site, incident])
    session.flush()
    for _ in range(2):
        session.add(
            models.Case(
                incident_id=incident.id,
                site_id=site.id,
                component_key="php",
                exposure=Exposure.VULNERABLE,
                priority=Priority.P2,
                score=55,
            )
        )
    with pytest.raises(IntegrityError):
        session.flush()


def test_naive_datetimes_are_rejected(session: Session) -> None:
    session.add(models.Nonce(key_id="k", nonce="n", seen_at=datetime(2026, 10, 22, 10, 0)))
    with pytest.raises(StatementError):
        session.flush()


def test_aware_datetimes_stored_as_utc(session: Session) -> None:
    ist = timezone(timedelta(hours=5, minutes=30))
    session.add(
        models.Nonce(key_id="k", nonce="n2", seen_at=datetime(2026, 10, 22, 15, 30, tzinfo=ist))
    )
    session.commit()
    n = session.query(models.Nonce).filter_by(nonce="n2").one()
    assert n.seen_at == datetime(2026, 10, 22, 10, 0, tzinfo=UTC)


def test_migrations_match_models(db_url: str) -> None:
    """`alembic upgrade head` builds exactly the schema the models describe."""
    cfg = Config(str(PLATFORM_DIR / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")
    command.check(cfg)  # raises if models and migrations differ

    tables = set(inspect(make_engine(db_url)).get_table_names())
    assert set(Base.metadata.tables) <= tables

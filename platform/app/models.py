"""Database tables. Mirrors DESIGN.md §5.2.

Rule R6: there are no contact fields anywhere. Don't add any.
"""

import secrets
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base, UTCDateTime, utcnow
from app.enums import (
    AlertChannel,
    AliasType,
    ChecklistItemKind,
    ClientNotice,
    Compromise,
    Exposure,
    FeedRunStatus,
    HostType,
    IncidentStatus,
    Priority,
    ReviewStatus,
    SiteStatus,
    UserRole,
)


def _enum(e: type[StrEnum]) -> SAEnum:
    """Store an enum as its string value, with a CHECK constraint listing the allowed values."""
    return SAEnum(
        e,
        native_enum=False,
        create_constraint=True,
        validate_strings=True,
        values_callable=lambda members: [m.value for m in members],
        length=32,
        name=e.__name__.lower(),
    )


def _random_id() -> str:
    return secrets.token_urlsafe(16)


def _created() -> Mapped[datetime]:
    return mapped_column(UTCDateTime, default=utcnow, nullable=False)


# --- Sites and reports -------------------------------------------------------


class Site(Base):
    __tablename__ = "sites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    business_name: Mapped[str] = mapped_column(String(200))
    url: Mapped[str] = mapped_column(String(500), unique=True)
    host_type: Mapped[HostType] = mapped_column(_enum(HostType), default=HostType.UNKNOWN)
    host_name: Mapped[str | None] = mapped_column(String(100))
    server_group: Mapped[str | None] = mapped_column(String(100))
    risk_tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    mu_plugin_allowlist: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[SiteStatus] = mapped_column(_enum(SiteStatus), default=SiteStatus.PENDING)
    key_id: Mapped[str | None] = mapped_column(String(32), unique=True)
    public_key: Mapped[str | None] = mapped_column(String(64))  # Ed25519, base64
    enrolled_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_report_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_report_id: Mapped[int | None] = mapped_column(
        ForeignKey("reports.id", use_alter=True, ondelete="SET NULL")
    )
    suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = _created()

    reports: Mapped[list["Report"]] = relationship(
        back_populates="site", foreign_keys="Report.site_id", cascade="all, delete-orphan"
    )
    components: Mapped[list["SiteComponent"]] = relationship(
        back_populates="site", cascade="all, delete-orphan"
    )


class EnrollmentCode(Base):
    __tablename__ = "enrollment_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = _created()


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (Index("ix_reports_site_received", "site_id", "received_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    received_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    content_hash: Mapped[str] = mapped_column(String(64))
    schema_version: Mapped[int] = mapped_column(Integer)
    plugin_version: Mapped[str] = mapped_column(String(32))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    flags: Mapped[list[str]] = mapped_column(JSON, default=list)

    site: Mapped[Site] = relationship(back_populates="reports", foreign_keys=[site_id])


class SiteComponent(Base):
    """Current inventory of a site, rebuilt from its latest report."""

    __tablename__ = "site_components"
    __table_args__ = (UniqueConstraint("site_id", "component_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    component_key: Mapped[str] = mapped_column(String(200), index=True)
    version_raw: Mapped[str | None] = mapped_column(String(100))
    version_parsed: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    distro: Mapped[str | None] = mapped_column(String(32))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    site: Mapped[Site] = relationship(back_populates="components")


class Nonce(Base):
    """Recently seen report nonces (replay protection). Pruned after 15 minutes."""

    __tablename__ = "nonces"
    __table_args__ = (UniqueConstraint("key_id", "nonce"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key_id: Mapped[str] = mapped_column(String(32))
    nonce: Mapped[str] = mapped_column(String(64))
    seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class Observation(Base):
    """Result of viewing a site's public homepage (DESIGN.md §4.9)."""

    __tablename__ = "observations"
    __table_args__ = (Index("ix_observations_site_at", "site_id", "at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    http_status: Mapped[int | None] = mapped_column(Integer)
    server_header: Mapped[str | None] = mapped_column(String(200))
    powered_by: Mapped[str | None] = mapped_column(String(200))
    behind_cloudflare: Mapped[bool | None] = mapped_column(Boolean)
    tls_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    error: Mapped[str | None] = mapped_column(String(500))


# --- Advisories and the component catalogue -----------------------------------


class Advisory(Base):
    __tablename__ = "advisories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list)  # CVE, GHSA, Wordfence id…
    source: Mapped[str] = mapped_column(String(50))
    source_url: Mapped[str | None] = mapped_column(String(500))
    title: Mapped[str] = mapped_column(String(300))
    summary_text: Mapped[str | None] = mapped_column(Text)
    cvss_score: Mapped[float | None]
    cvss_vector: Mapped[str | None] = mapped_column(String(200))
    # Set from advisory text when no verified CVSS vector is available (scoring uses it).
    network_unauthenticated: Mapped[bool | None] = mapped_column(Boolean)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    exploited: Mapped[bool] = mapped_column(Boolean, default=False)
    published_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    review_status: Mapped[ReviewStatus] = mapped_column(
        _enum(ReviewStatus), default=ReviewStatus.NEEDS_REVIEW
    )
    drill: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = _created()

    affects: Mapped[list["AdvisoryAffect"]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan"
    )


class AdvisoryAffect(Base):
    __tablename__ = "advisory_affects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    advisory_id: Mapped[int] = mapped_column(ForeignKey("advisories.id", ondelete="CASCADE"))
    component_key: Mapped[str] = mapped_column(String(200), index=True)
    ranges: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)  # OSV-style
    fixed_versions: Mapped[list[str]] = mapped_column(JSON, default=list)
    distro_fixes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    advisory: Mapped[Advisory] = relationship(back_populates="affects")


class ComponentAlias(Base):
    __tablename__ = "component_aliases"
    __table_args__ = (UniqueConstraint("alias_type", "alias_value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    component_key: Mapped[str] = mapped_column(String(200), index=True)
    alias_type: Mapped[AliasType] = mapped_column(_enum(AliasType))
    alias_value: Mapped[str] = mapped_column(String(300))


# --- Incidents, cases and the response workflow -------------------------------


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_random_id)
    title: Mapped[str] = mapped_column(String(300))
    kind: Mapped[str] = mapped_column(String(32))  # php-core, lib, wp-core, wp-plugin, ...
    priority: Mapped[Priority] = mapped_column(_enum(Priority))
    status: Mapped[IncidentStatus] = mapped_column(
        _enum(IncidentStatus), default=IncidentStatus.OPEN
    )
    drill: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = _created()
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    cases: Mapped[list["Case"]] = relationship(back_populates="incident")


class IncidentAdvisory(Base):
    __tablename__ = "incident_advisories"

    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    advisory_id: Mapped[int] = mapped_column(
        ForeignKey("advisories.id", ondelete="CASCADE"), primary_key=True
    )


class Case(Base):
    """One site within one incident."""

    __tablename__ = "cases"
    __table_args__ = (UniqueConstraint("incident_id", "site_id", "component_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    component_key: Mapped[str] = mapped_column(String(200))
    exposure: Mapped[Exposure] = mapped_column(_enum(Exposure))
    version_seen: Mapped[str | None] = mapped_column(String(100))
    fixed_version: Mapped[str | None] = mapped_column(String(100))
    unsupported_branch: Mapped[bool] = mapped_column(Boolean, default=False)
    match_reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    shielded: Mapped[bool] = mapped_column(Boolean, default=False)
    shield_note: Mapped[str | None] = mapped_column(String(500))
    compromise: Mapped[Compromise] = mapped_column(_enum(Compromise), default=Compromise.NONE)
    client_notice: Mapped[ClientNotice] = mapped_column(
        _enum(ClientNotice), default=ClientNotice.NOT_NEEDED
    )
    priority: Mapped[Priority] = mapped_column(_enum(Priority))
    score: Mapped[int] = mapped_column(Integer)
    score_reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    owner_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="cases")
    site: Mapped[Site] = relationship()


class ChecklistItem(Base):
    __tablename__ = "checklist_items"
    __table_args__ = (UniqueConstraint("case_id", "item_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    template_key: Mapped[str] = mapped_column(String(100))
    item_key: Mapped[str] = mapped_column(String(100))
    kind: Mapped[ChecklistItemKind] = mapped_column(_enum(ChecklistItemKind))
    done_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    done_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    note: Mapped[str | None] = mapped_column(String(1000))


class Event(Base):
    """Timeline entry. actor_user_id NULL means the system did it."""

    __tablename__ = "events"
    __table_args__ = (Index("ix_events_incident_at", "incident_id", "at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    type: Mapped[str] = mapped_column(String(50))
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    note: Mapped[str | None] = mapped_column(String(1000))
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class AIResult(Base):
    __tablename__ = "ai_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    task: Mapped[str] = mapped_column(String(50))
    provider: Mapped[str] = mapped_column(String(50))
    model: Mapped[str] = mapped_column(String(100))
    prompt_version: Mapped[str] = mapped_column(String(20))
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = _created()


class Draft(Base):
    """Client message draft with placeholders. A person fills it in and sends it."""

    __tablename__ = "drafts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    content: Mapped[str] = mapped_column(Text)
    ai_result_id: Mapped[int | None] = mapped_column(
        ForeignKey("ai_results.id", ondelete="SET NULL")
    )
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    sent_marked_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = _created()


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    channel: Mapped[AlertChannel] = mapped_column(_enum(AlertChannel))
    recipients_group: Mapped[str] = mapped_column(String(50))  # e.g. "responders", "backup"
    sent_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    acked_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    acked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    escalated_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


# --- Operations and our own team ----------------------------------------------


class FeedRun(Base):
    __tablename__ = "feed_runs"
    __table_args__ = (Index("ix_feed_runs_source_started", "source", "started_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(50))
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    status: Mapped[FeedRunStatus] = mapped_column(
        _enum(FeedRunStatus), default=FeedRunStatus.RUNNING
    )
    items_new: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(String(1000))


class User(Base):
    """Our own team members only. Never client contacts."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    display_name: Mapped[str] = mapped_column(String(100))
    role: Mapped[UserRole] = mapped_column(_enum(UserRole), default=UserRole.VIEWER)
    totp_secret_enc: Mapped[str | None] = mapped_column(String(200))  # fallback login only
    created_at: Mapped[datetime] = _created()
    disabled_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class AuditLog(Base):
    """Logins and changes to users and settings."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(50))
    target: Mapped[str | None] = mapped_column(String(200))
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

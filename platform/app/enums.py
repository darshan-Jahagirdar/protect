"""Closed sets of values used by the models. Stored as their string values."""

from enum import StrEnum


class SiteStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    REMOVED = "removed"


class HostType(StrEnum):
    MANAGED_WP = "managed-wp"
    CPANEL = "cpanel"
    VPS = "vps"
    UNKNOWN = "unknown"


class ReviewStatus(StrEnum):
    CONFIRMED = "confirmed"
    NEEDS_REVIEW = "needs_review"
    REJECTED = "rejected"


class AliasType(StrEnum):
    CPE = "cpe"
    WORDFENCE = "wordfence"
    WPORG = "wporg"
    UBUNTU_PKG = "ubuntu_pkg"
    DEBIAN_PKG = "debian_pkg"


class IncidentStatus(StrEnum):
    OPEN = "open"
    MONITORING = "monitoring"
    CLOSED = "closed"


class Priority(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class Exposure(StrEnum):
    VULNERABLE = "vulnerable"
    NEEDS_CHECK = "needs_check"
    FIX_CLAIMED = "fix_claimed"
    VERIFIED = "verified"
    NOT_AFFECTED = "not_affected"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class Compromise(StrEnum):
    NONE = "none"
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"


class ClientNotice(StrEnum):
    NOT_NEEDED = "not_needed"
    DRAFTED = "drafted"
    APPROVED = "approved"
    SENT = "sent"


class ChecklistItemKind(StrEnum):
    MANUAL = "manual"
    AUTO = "auto"


class AlertChannel(StrEnum):
    EMAIL = "email"
    TEAMS = "teams"


class FeedRunStatus(StrEnum):
    RUNNING = "running"
    OK = "ok"
    FAILED = "failed"


class UserRole(StrEnum):
    ADMIN = "admin"
    RESPONDER = "responder"
    VIEWER = "viewer"

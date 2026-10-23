"""Small admin CLI until the dashboard has these screens (step 8).

    uv run python -m app.cli add-site --name "Demo Co" --url http://127.0.0.1:8081 \
        --host-type managed-wp
    uv run python -m app.cli new-code --site-id 1
    uv run python -m app.cli list-sites
    uv run python -m app.cli replay-advisory php2shell      # or drill-plugin
    uv run python -m app.cli list-incidents
    uv run python -m app.cli send-alerts                     # the scheduler does this every 60s
    uv run python -m app.cli send-digest
    uv run python -m app.cli ack-incident <incident id>
    uv run python -m app.cli add-user --email you@example.com --name "You" --role admin

In the Docker demo:  docker compose -f docker/compose.yaml exec platform python -m app.cli ...
"""

import argparse
import sys

from sqlalchemy import select

from app.alerts.mailer import mailer_for
from app.db import SessionLocal
from app.enums import HostType, UserRole
from app.models import Incident, Site, User
from app.services.advisories import fixture_names, load_fixture, upsert_advisory
from app.services.alerting import (
    acknowledge,
    escalate_unacknowledged,
    send_digest,
    send_due_alerts,
)
from app.services.enrollment import create_site, issue_code
from app.services.incidents import apply_advisory
from app.settings import get_settings


def _print_code(site: Site, code: str) -> None:
    hours = get_settings().enrollment_code_ttl_hours
    print(f"Site #{site.id}: {site.business_name} ({site.url})")
    print(f"Enrollment code (valid {hours}h, shown once): {code}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)

    add = sub.add_parser("add-site", help="register a site and print its enrollment code")
    add.add_argument("--name", required=True)
    add.add_argument("--url", required=True)
    add.add_argument("--host-type", choices=[h.value for h in HostType], default="unknown")

    code = sub.add_parser("new-code", help="issue a fresh enrollment code (re-enroll / rotate key)")
    code.add_argument("--site-id", type=int, required=True)

    sub.add_parser("list-sites", help="list registered sites")

    replay = sub.add_parser("replay-advisory", help="load a fixture advisory and match it now")
    replay.add_argument("name", choices=fixture_names())

    sub.add_parser("list-incidents", help="list incidents and their cases")
    sub.add_parser("send-alerts", help="send due alerts and escalations now (normally every 60s)")
    sub.add_parser("send-digest", help="send the P3/P4 daily digest now")
    ack = sub.add_parser("ack-incident", help="acknowledge an incident (stops escalation)")
    ack.add_argument("incident_id")

    user = sub.add_parser("add-user", help="add a team member (dashboard sign-in)")
    user.add_argument("--email", required=True)
    user.add_argument("--name", required=True)
    user.add_argument("--role", choices=[r.value for r in UserRole], default="responder")

    args = parser.parse_args(argv)
    settings = get_settings()
    ttl = settings.enrollment_code_ttl_hours

    with SessionLocal() as session:
        if args.cmd == "add-site":
            site = create_site(session, args.name, args.url, HostType(args.host_type))
            plain = issue_code(session, site, ttl)
            session.commit()
            _print_code(site, plain)
        elif args.cmd == "new-code":
            site = session.get(Site, args.site_id)
            if site is None:
                print(f"no site with id {args.site_id}", file=sys.stderr)
                return 1
            plain = issue_code(session, site, ttl)
            session.commit()
            _print_code(site, plain)
        elif args.cmd == "list-sites":
            for s in session.scalars(select(Site).order_by(Site.id)):
                last = (
                    s.last_report_at.isoformat(timespec="seconds") if s.last_report_at else "never"
                )
                print(f"#{s.id}  {s.status.value:<8} {s.url:<40} last report: {last}")
        elif args.cmd == "replay-advisory":
            advisory = upsert_advisory(session, load_fixture(args.name))
            incident = apply_advisory(session, advisory)
            session.commit()
            if incident is None:
                print(f"{advisory.title}: no active site is affected")
            else:
                _print_incident(incident)
        elif args.cmd == "list-incidents":
            for incident in session.scalars(select(Incident).order_by(Incident.created_at)):
                _print_incident(incident)
        elif args.cmd == "send-alerts":
            mailer = mailer_for(settings)
            alerts = send_due_alerts(session, mailer, settings)
            escalations = escalate_unacknowledged(session, mailer, settings)
            session.commit()
            print(f"sent {alerts} alert(s), {escalations} escalation(s)")
        elif args.cmd == "send-digest":
            listed = send_digest(session, mailer_for(settings), settings)
            print(f"digest listed {listed} incident(s)" if listed else "nothing to digest")
        elif args.cmd == "ack-incident":
            incident = session.get(Incident, args.incident_id)
            if incident is None:
                print(f"no incident {args.incident_id}", file=sys.stderr)
                return 1
            done = acknowledge(session, incident, user_id=None)
            session.commit()
            print("acknowledged" if done else "already acknowledged")
        elif args.cmd == "add-user":
            email = args.email.strip().lower()
            if session.scalar(select(User).where(User.email == email)):
                print(f"{email} already exists", file=sys.stderr)
                return 1
            session.add(User(email=email, display_name=args.name.strip(), role=UserRole(args.role)))
            session.commit()
            print(f"added {args.name} <{email}> as {args.role}")
    return 0


def _print_incident(incident: Incident) -> None:
    drill = "[DRILL] " if incident.drill else ""
    status = f"{incident.status.value}, {incident.id}"
    print(f"{drill}{incident.priority.value} {incident.title}  ({status})")
    for case in incident.cases:
        print(
            f"   site #{case.site_id} {case.component_key} {case.version_seen}: "
            f"{case.exposure.value}, score {case.score} {case.priority.value}"
        )
        for reason in [*case.match_reasons, *case.score_reasons]:
            print(f"      - {reason}")


if __name__ == "__main__":
    raise SystemExit(main())

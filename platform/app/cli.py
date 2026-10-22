"""Small admin CLI until the dashboard has these screens (step 8).

    uv run python -m app.cli add-site --name "Demo Co" --url http://127.0.0.1:8081 \
        --host-type managed-wp
    uv run python -m app.cli new-code --site-id 1
    uv run python -m app.cli list-sites

In the Docker demo:  docker compose -f docker/compose.yaml exec platform python -m app.cli ...
"""

import argparse
import sys

from sqlalchemy import select

from app.db import SessionLocal
from app.enums import HostType
from app.models import Site
from app.services.enrollment import create_site, issue_code
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

    args = parser.parse_args(argv)
    ttl = get_settings().enrollment_code_ttl_hours

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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

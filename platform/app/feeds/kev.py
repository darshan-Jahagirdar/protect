"""CISA Known Exploited Vulnerabilities catalogue (DESIGN.md §4.3): raises priority.

It names CVEs that are being exploited, not which versions are affected, so it never creates
advisories. A listed CVE adds +30 to every case of an advisory that carries it (scoring rule
in app/engine/scoring.py), which can turn a P3 into a P1 and send an alert. The CVE list is
kept in feed_state so advisories that arrive later are flagged when they arrive.
"""

import hashlib
import json

from app.feeds import clean
from app.feeds.runner import FeedContext, FeedOutcome, state
from app.models import Event, IncidentAdvisory
from app.services.advisories import mark_known_exploited
from app.services.incidents import apply_advisory

SOURCE = "kev"
URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_BYTES = 32 * 1024 * 1024


def run(ctx: FeedContext, out: FeedOutcome) -> None:
    dl = ctx.fetch(URL, max_bytes=MAX_BYTES)
    try:
        body = dl.read()
    finally:
        dl.close()
    st = state(ctx.session, SOURCE)
    digest = hashlib.sha256(body).hexdigest()
    if st.content_hash != digest:
        cves = parse(body)
        out.new = len(cves - set(st.data.get("cves", [])))
        st.data = {"cves": sorted(cves), "count": len(cves)}
        st.content_hash = digest
        st.updated_at = ctx.now

    for adv in mark_known_exploited(ctx.session, frozenset(st.data.get("cves", []))):
        out.updated += 1
        for link in ctx.session.query(IncidentAdvisory).filter_by(advisory_id=adv.id):
            ctx.session.add(
                Event(
                    incident_id=link.incident_id,
                    type="known_exploited",
                    note="CISA added this flaw to its known-exploited list (+30)",
                    data={"aliases": adv.aliases},
                )
            )
        apply_advisory(ctx.session, adv)  # rescore; the alert job emails if it is now P1/P2


def parse(body: bytes) -> set[str]:
    try:
        data = json.loads(body)
    except ValueError as e:
        raise clean.FeedDataError("the KEV catalogue isn't valid JSON") from e
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulns, list) or not vulns:
        raise clean.FeedDataError("the KEV catalogue has no vulnerabilities list")
    cves = {c for c in (clean.cve(v.get("cveID")) for v in vulns if isinstance(v, dict)) if c}
    if len(cves) < len(vulns) // 2:
        raise clean.FeedDataError("most KEV entries have no readable CVE id")
    return cves

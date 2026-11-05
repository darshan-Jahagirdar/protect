"""NVD API 2.0: fallback and enrichment for PHP and WordPress core (DESIGN.md §4.3).

NVD often lags days or weeks behind the vendors, and its version ranges are sometimes broader
than the vendor's. So:
- A CVE we already know from GitHub or Wordfence only fills in blanks (usually the CVSS score).
- A recent CVE we don't know yet becomes an advisory waiting for review, with NVD's ranges as
  a starting point. A person checks them against the vendor's advisory.
- Old CVEs that NVD re-edits (it does, constantly) are ignored unless we already have them.

No API key: the public limit (5 requests in 30 seconds) is plenty for a few requests every
2 hours. Each run asks for what changed since the last good run.
"""

import json
import re
from datetime import datetime, timedelta
from typing import Any

from app.enums import ReviewStatus
from app.feeds import clean
from app.feeds.runner import FeedContext, FeedOutcome, state, store
from app.services.advisories import find_by_aliases

SOURCE = "nvd"
URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString={cpe}"
    "&lastModStartDate={start}&lastModEndDate={end}&startIndex={index}"
)
PRODUCTS = {"cpe:2.3:a:php:php": "php", "cpe:2.3:a:wordpress:wordpress": "wordpress"}
MAX_BYTES = 32 * 1024 * 1024
FIRST_WINDOW = timedelta(days=7)
MAX_WINDOW = timedelta(days=100)  # NVD allows 120
NEW_ENOUGH = timedelta(days=90)  # older unknown CVEs aren't worth a review
MAX_PAGES = 5
_EXACT = re.compile(r"^cpe:2\.3:a:(php:php|wordpress:wordpress):([0-9][0-9a-z.\-]{0,30}):")


def _fmt(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def run(ctx: FeedContext, out: FeedOutcome) -> None:
    st = state(ctx.session, SOURCE)
    start = clean.timestamp(st.data.get("last_modified")) or ctx.now - FIRST_WINDOW
    start = max(start, ctx.now - MAX_WINDOW)
    for cpe in PRODUCTS:
        index = 0
        for _ in range(MAX_PAGES):
            url = URL.format(cpe=cpe, start=_fmt(start), end=_fmt(ctx.now), index=index)
            dl = ctx.fetch(url, max_bytes=MAX_BYTES)
            try:
                page = json.loads(dl.read())
            except ValueError as e:
                raise clean.FeedDataError("NVD returned invalid JSON") from e
            finally:
                dl.close()
            if not isinstance(page, dict) or not isinstance(page.get("vulnerabilities"), list):
                raise clean.FeedDataError("NVD returned no vulnerabilities list")
            for item in page["vulnerabilities"]:
                ingest_one(ctx, out, item)
            index += len(page["vulnerabilities"])
            total = page.get("totalResults")
            if not isinstance(total, int) or index >= total or not page["vulnerabilities"]:
                break
    st.data = {**st.data, "last_modified": ctx.now.isoformat()}
    st.updated_at = ctx.now


def ingest_one(ctx: FeedContext, out: FeedOutcome, item: Any) -> None:
    try:
        parsed = parse(item)
    except clean.FeedDataError as e:
        out.rejected += 1
        if len(out.notes) < 5:
            out.notes.append(f"skipped a CVE: {e}"[:200])
        return
    if parsed is None:
        return
    cve, data, published = parsed
    known = find_by_aliases(ctx.session, [cve]) is not None
    if not known and (published is None or ctx.now - published > NEW_ENOUGH):
        return
    store(ctx, out, SOURCE, cve, data, ReviewStatus.NEEDS_REVIEW)


def _cvss(metrics: Any) -> tuple[float | None, str | None]:
    if not isinstance(metrics, dict):
        return None, None
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
        entries = metrics.get(key)
        if not isinstance(entries, list):
            continue
        entries = sorted(
            (e for e in entries if isinstance(e, dict)), key=lambda e: e.get("type") != "Primary"
        )
        for e in entries:
            data = e.get("cvssData") if isinstance(e.get("cvssData"), dict) else {}
            score = clean.cvss_score(data.get("baseScore"))
            if score is not None:
                return score, clean.cvss_vector(data.get("vectorString"))
    return None, None


def _range(match: dict[str, Any]) -> dict[str, Any] | None:
    start_inc, start_exc = match.get("versionStartIncluding"), match.get("versionStartExcluding")
    end_exc, end_inc = match.get("versionEndExcluding"), match.get("versionEndIncluding")
    if not any((start_inc, start_exc, end_exc, end_inc)):
        exact = _EXACT.match(str(match.get("criteria", "")))
        version = clean.version(exact.group(2)) if exact else None
        return {"introduced": version, "last_affected": version} if version else None
    low = start_inc or start_exc or "0"  # an open lower end errs towards "affected"
    rng: dict[str, Any] = {"introduced": low}
    if end_exc:
        rng["fixed"] = end_exc
    elif end_inc:
        rng["last_affected"] = end_inc
    if any(clean.version(v) is None for k, v in rng.items()):
        return None
    return rng


def parse(item: Any) -> tuple[str, dict[str, Any], datetime | None] | None:
    """None when the CVE doesn't name PHP or WordPress core as vulnerable software."""
    cve_data = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve_data, dict):
        raise clean.FeedDataError("an item has no CVE record")
    cve = clean.cve(cve_data.get("id"))
    if cve is None:
        raise clean.FeedDataError("missing or malformed CVE id")
    if cve_data.get("vulnStatus") == "Rejected":
        return None

    affects: dict[str, dict[str, Any]] = {}
    unreadable = False
    configs = (
        cve_data.get("configurations") if isinstance(cve_data.get("configurations"), list) else []
    )
    for config in configs:
        for node in config.get("nodes", []) if isinstance(config, dict) else []:
            for match in node.get("cpeMatch", []) if isinstance(node, dict) else []:
                if not isinstance(match, dict) or match.get("vulnerable") is not True:
                    continue
                criteria = str(match.get("criteria", ""))
                key = next((k for p, k in PRODUCTS.items() if criteria.startswith(p + ":")), None)
                if key is None:
                    continue
                rng = _range(match)
                if rng is None:
                    unreadable = True
                    continue
                affect = affects.setdefault(
                    key, {"component_key": key, "ranges": [], "fixed_versions": []}
                )
                if rng not in affect["ranges"]:
                    affect["ranges"].append(rng)
                if "fixed" in rng and rng["fixed"] not in affect["fixed_versions"]:
                    affect["fixed_versions"].append(rng["fixed"])
    if not affects and not unreadable:
        return None

    descriptions = (
        cve_data.get("descriptions") if isinstance(cve_data.get("descriptions"), list) else []
    )
    english = next(
        (d.get("value") for d in descriptions if isinstance(d, dict) and d.get("lang") == "en"),
        None,
    )
    summary = clean.text(english)
    first_sentence = (summary or "").split(". ")[0]
    score, vector = _cvss(cve_data.get("metrics"))
    published = clean.timestamp(cve_data.get("published"))
    product = " and ".join("PHP" if k == "php" else "WordPress" for k in affects) or "PHP/WordPress"
    data: dict[str, Any] = {
        "title": clean.title(f"{product}: {first_sentence or cve}"),
        "aliases": [cve],
        "source_url": f"https://nvd.nist.gov/vuln/detail/{cve}",
        "summary_text": summary,
        "cvss_score": score,
        "cvss_vector": vector,
        "published_at": published,
        "review_reason": (
            "from NVD, a slower fallback source: check the versions against the vendor's advisory"
            + ("; some version ranges couldn't be read" if unreadable else "")
        ),
        "affects": list(affects.values()),
    }
    return cve, data, published

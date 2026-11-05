"""Every live feed, how often it runs, and what it needs (DESIGN.md §4.3)."""

from app.feeds import ghsa, kev, nvd, phpnet, wordfence
from app.feeds.runner import FeedSpec

FEEDS: tuple[FeedSpec, ...] = (
    FeedSpec("php-releases", "php.net supported PHP releases", 15, phpnet.run_releases),
    FeedSpec("ghsa", "GitHub php-src security advisories", 15, ghsa.run),
    FeedSpec("phpnet-news", "php.net news", 15, phpnet.run_news),
    FeedSpec(
        "wordfence", "Wordfence Intelligence (WordPress)", 60, wordfence.run, "wordfence_api_key"
    ),
    FeedSpec("kev", "CISA known exploited list", 60, kev.run),
    FeedSpec("nvd", "NVD (fallback for PHP and WordPress core)", 120, nvd.run),
)
BY_NAME = {f.name: f for f in FEEDS}

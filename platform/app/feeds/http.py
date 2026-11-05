"""Downloading feed data. The only outbound HTTP the feeds make goes through here.

- https only, and only to the hosts DESIGN.md §4.3 lists. Adding a host is a rule change.
- Redirects are followed by hand, and only to another listed host.
- Every download has a size cap and lands in a spooled temporary file, so a huge or endless
  response can't fill memory (the production server has 1 GB).
- Bodies are data: parsers in this package read them, nothing executes them.
"""

import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import IO, Protocol
from urllib.parse import urljoin, urlsplit

import httpx

ALLOWED_HOSTS = frozenset(
    {
        "www.php.net",  # PHP releases JSON and news feed
        "api.github.com",  # php/php-src security advisories
        "www.cisa.gov",  # Known Exploited Vulnerabilities catalogue
        "www.wordfence.com",  # Wordfence Intelligence vulnerability feed (API key)
        "services.nvd.nist.gov",  # NVD API 2.0
    }
)
USER_AGENT = "TransFunnel-Protect-Feeds/1.0 (security advisory watcher)"
TIMEOUT = httpx.Timeout(30.0, read=120.0)
MAX_REDIRECTS = 3
MEMORY_LIMIT = 8 * 1024 * 1024  # larger downloads spill to a temporary file


class FeedFetchError(Exception):
    """The download failed. The message is ours (never text from the response)."""


@dataclass
class Download:
    url: str
    status: int
    headers: dict[str, str]
    body: IO[bytes] = field(repr=False)
    size: int

    def read(self) -> bytes:
        self.body.seek(0)
        return self.body.read()

    def close(self) -> None:
        self.body.close()


class Fetcher(Protocol):
    def __call__(
        self, url: str, *, max_bytes: int, headers: Mapping[str, str] | None = None
    ) -> Download: ...


def check_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        raise FeedFetchError(
            f"refusing to fetch {parts.scheme}://{parts.hostname}: not a feed host"
        )


def download(url: str, *, max_bytes: int, headers: Mapping[str, str] | None = None) -> Download:
    """GET one feed URL. Raises FeedFetchError on anything but a complete 200 response."""
    sent = {"User-Agent": USER_AGENT, **(headers or {})}
    with httpx.Client(timeout=TIMEOUT, follow_redirects=False) as client:
        for _ in range(MAX_REDIRECTS + 1):
            check_url(url)
            try:
                with client.stream("GET", url, headers=sent) as resp:
                    if resp.is_redirect:
                        target = urljoin(url, resp.headers.get("location", ""))
                        if urlsplit(target).hostname != urlsplit(url).hostname:
                            sent.pop("Authorization", None)  # never carry a key elsewhere
                        url = target
                        continue
                    if resp.status_code != 200:
                        raise FeedFetchError(
                            f"HTTP {resp.status_code} from {urlsplit(url).hostname}"
                        )
                    body = tempfile.SpooledTemporaryFile(max_size=MEMORY_LIMIT)  # noqa: SIM115
                    size = 0
                    try:
                        for chunk in resp.iter_bytes():
                            size += len(chunk)
                            if size > max_bytes:
                                raise FeedFetchError(f"response larger than {max_bytes} bytes")
                            body.write(chunk)
                    except BaseException:
                        body.close()
                        raise
                    return Download(url, resp.status_code, dict(resp.headers), body, size)
            except httpx.HTTPError as e:
                raise FeedFetchError(f"{type(e).__name__} from {urlsplit(url).hostname}") from e
    raise FeedFetchError("too many redirects")

"""Feed tests run on recorded sample files (tests/feeds/samples/). They never touch the network.

The samples are trimmed copies of real downloads from 2026-11-04 (php.net, GitHub php-src
advisories, CISA KEV, NVD). wordfence_production.json is built from Wordfence's documented
format, because recording the real feed needs an API key.
"""

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from app.db import Base, make_engine
from app.feeds.http import Download, FeedFetchError
from app.feeds.runner import FeedContext, FeedOutcome
from app.settings import Settings

SAMPLES = Path(__file__).parent / "samples"
NOW = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)


def sample(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()


@dataclass
class FakeFetcher:
    """Answers feed URLs from sample bytes. Unknown URLs fail like a network error."""

    routes: dict[str, bytes | Exception | Callable[[str], bytes]] = field(default_factory=dict)
    headers: dict[str, dict[str, str]] = field(default_factory=dict)
    calls: list[tuple[str, dict[str, str]]] = field(default_factory=list)

    def add(
        self, prefix: str, body: bytes | Exception, headers: dict[str, str] | None = None
    ) -> None:
        self.routes[prefix] = body
        self.headers[prefix] = headers or {}

    def __call__(
        self, url: str, *, max_bytes: int, headers: Mapping[str, str] | None = None
    ) -> Download:
        self.calls.append((url, dict(headers or {})))
        for prefix in sorted(self.routes, key=len, reverse=True):
            if url.startswith(prefix):
                body = self.routes[prefix]
                if isinstance(body, Exception):
                    raise body
                data = body(url) if callable(body) else body
                if len(data) > max_bytes:
                    raise FeedFetchError(f"response larger than {max_bytes} bytes")
                return Download(url, 200, self.headers[prefix], BytesIO(data), len(data))
        raise FeedFetchError(f"no sample for {url}")


def php_net(fetch: FakeFetcher) -> FakeFetcher:
    fetch.add("https://www.php.net/releases/?json&version=8.", sample("php_releases_8.3.json"))
    fetch.add("https://www.php.net/releases/?json&version=8", sample("php_releases_8.json"))
    return fetch


@pytest.fixture
def fetch() -> FakeFetcher:
    return FakeFetcher()


@pytest.fixture
def settings() -> Settings:
    return Settings(
        env="test", base_url="https://protect.example", alert_recipients="team@demo.test"
    )


@pytest.fixture
def ctx(session: Session, fetch: FakeFetcher, settings: Settings) -> FeedContext:
    return FeedContext(session, fetch, settings, NOW)


@pytest.fixture
def out() -> FeedOutcome:
    return FeedOutcome()


@pytest.fixture
def factory(db_url: str) -> Iterator[sessionmaker[Session]]:
    engine = make_engine(db_url)
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine, expire_on_commit=False)
    engine.dispose()

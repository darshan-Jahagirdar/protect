from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.db import Base, get_session, make_engine
from app.enums import HostType
from app.main import create_app
from app.models import Site
from app.services.enrollment import create_site, issue_code
from app.settings import Settings
from tests.api.helpers import SITE_URL, FakePlugin


@dataclass
class Env:
    client: TestClient
    db: sessionmaker[Session]

    def site(self) -> Site:
        with self.db() as s:
            site = s.query(Site).one()
            s.expunge_all()
            return site


@pytest.fixture
def env(db_url: str) -> Iterator[Env]:
    engine = make_engine(db_url)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    app = create_app(Settings(env="test", database_url=db_url))

    def _session() -> Iterator[Session]:
        with factory() as s:
            yield s

    app.dependency_overrides[get_session] = _session
    yield Env(TestClient(app), factory)
    engine.dispose()


@pytest.fixture
def code(env: Env) -> str:
    """A registered (not yet enrolled) demo site and its one-time code."""
    with env.db() as s:
        site = create_site(s, "Demo Co", SITE_URL + "/", HostType.MANAGED_WP)
        plain = issue_code(s, site, ttl_hours=24)
        s.commit()
    return plain


@pytest.fixture
def plugin() -> FakePlugin:
    return FakePlugin()


@pytest.fixture
def enrolled(env: Env, code: str, plugin: FakePlugin) -> FakePlugin:
    body = plugin.enroll_body(code)
    r = env.client.post(
        "/api/v1/enroll", content=body, headers=plugin.headers(body, with_key=False)
    )
    assert r.status_code == 204
    return plugin

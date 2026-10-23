"""Helpers for dashboard tests: an app on a temp DB, signing in, and CSRF tokens."""

import re
from dataclasses import dataclass

from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from app.db import Base, get_session, make_engine
from app.enums import UserRole
from app.main import create_app
from app.models import User
from app.settings import Settings


@dataclass
class Dash:
    client: TestClient
    engine: Engine

    def session(self) -> Session:
        return Session(self.engine, expire_on_commit=False)

    def add_user(self, role: UserRole = UserRole.RESPONDER, name: str | None = None) -> User:
        with self.session() as s:
            user = User(
                email=f"{role.value}{s.query(User).count()}@demo.test",
                display_name=name or f"{role.value.capitalize()} User",
                role=role,
            )
            s.add(user)
            s.commit()
            return user

    def login(self, role: UserRole = UserRole.RESPONDER, name: str | None = None) -> User:
        user = self.add_user(role, name)
        r = self.client.post(
            "/login", data={"user_id": user.id, "next": "/"}, follow_redirects=False
        )
        assert r.status_code == 303, r.text
        return user

    def csrf(self, path: str = "/") -> str:
        m = re.search(r'name="csrf_token" value="([^"]+)"', self.client.get(path).text)
        assert m, f"no CSRF token on {path}"
        return m.group(1)

    def post(self, path: str, data: dict | None = None, page: str = "/", **kw):  # type: ignore[no-untyped-def]
        return self.client.post(
            path, data={"csrf_token": self.csrf(page), **(data or {})}, follow_redirects=False, **kw
        )


def make_dash(db_url: str, env: str = "test") -> Dash:
    engine = make_engine(db_url)
    Base.metadata.create_all(engine)
    extra = {"secret_key": "x" * 40, "base_url": "https://protect.example"} if env == "prod" else {}
    app = create_app(Settings(env=env, database_url=db_url, **extra))  # type: ignore[arg-type]

    def _s():
        with Session(engine) as s:
            yield s

    app.dependency_overrides[get_session] = _s
    return Dash(TestClient(app), engine)

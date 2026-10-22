import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.db import Base, get_session, make_engine
from app.main import create_app
from app.settings import Settings


@pytest.fixture
def client(db_url: str) -> TestClient:
    engine = make_engine(db_url)
    Base.metadata.create_all(engine)
    app = create_app(Settings(env="test", database_url=db_url))

    from sqlalchemy.orm import Session

    def _session():
        with Session(engine) as s:
            yield s

    app.dependency_overrides[get_session] = _session
    return TestClient(app)


def test_healthz(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_security_headers_on_every_response(client: TestClient) -> None:
    for path in ["/healthz", "/", "/does-not-exist"]:
        h = client.get(path).headers
        csp = h["content-security-policy"]
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
        assert "'unsafe-inline'" not in csp
        assert h["x-frame-options"] == "DENY"
        assert h["x-content-type-options"] == "nosniff"
        assert "strict-transport-security" not in h  # HSTS only in prod


def test_overview_page_renders(client: TestClient) -> None:
    r = client.get("/")
    assert r.status_code == 200
    assert "Open incidents" in r.text
    assert "<script" not in r.text  # no inline scripts in our templates


def test_templates_autoescape() -> None:
    from app.dashboard.routes import templates

    html = templates.env.from_string("{{ v }}").render(v="<script>alert(1)</script>")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_prod_settings_require_secret_and_https() -> None:
    with pytest.raises(ValidationError):
        Settings(env="prod", base_url="https://protect.example", secret_key=None)
    with pytest.raises(ValidationError):
        Settings(env="prod", base_url="http://protect.example", secret_key="x" * 40)
    s = Settings(env="prod", base_url="https://protect.example", secret_key="x" * 40)
    assert s.is_prod


def test_prod_hides_api_docs(db_url: str) -> None:
    app = create_app(
        Settings(env="prod", base_url="https://p.example", secret_key="x" * 40, database_url=db_url)
    )
    c = TestClient(app)
    assert c.get("/docs").status_code == 404
    assert c.get("/openapi.json").status_code == 404
    assert "strict-transport-security" in c.get("/healthz").headers

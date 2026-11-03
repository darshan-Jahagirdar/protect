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
    for path in ["/healthz", "/", "/login", "/does-not-exist"]:
        h = client.get(path, follow_redirects=False).headers
        csp = h["content-security-policy"]
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
        assert "'unsafe-inline'" not in csp
        assert h["x-frame-options"] == "DENY"
        assert h["x-content-type-options"] == "nosniff"
        assert "strict-transport-security" not in h  # HSTS only in prod


def test_overview_page_renders(db_url: str) -> None:
    from tests.dashboard_helpers import make_dash

    dash = make_dash(db_url)
    dash.login()
    r = dash.client.get("/")
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


def test_empty_secret_key_counts_as_unset() -> None:
    assert Settings(env="test", secret_key="").secret_key is None
    with pytest.raises(ValidationError):
        Settings(env="prod", base_url="https://p.example", secret_key="")


# --- Dev mode's password-free sign-in stays on this machine ---------------------------------


@pytest.mark.parametrize(
    "url",
    ["http://127.0.0.1:8000", "http://localhost:8000", "http://[::1]:8000", "http://demo.test"],
)
def test_dev_mode_runs_with_a_local_address(url: str) -> None:
    assert Settings(env="dev", base_url=url).env == "dev"


@pytest.mark.parametrize("url", ["https://protect.transfunnel.com", "http://203.0.113.7:8000"])
def test_dev_mode_refuses_to_start_with_a_real_address(url: str) -> None:
    # A server started in dev mode by mistake would let anyone sign in as admin.
    with pytest.raises(ValidationError, match="password-free"):
        Settings(env="dev", base_url=url)


def test_dev_sign_in_only_answers_on_a_local_address(db_url: str) -> None:
    engine = make_engine(db_url)
    Base.metadata.create_all(engine)
    app = create_app(Settings(env="dev", database_url=db_url, scheduler_enabled=False))

    def _session():  # type: ignore[no-untyped-def]
        from sqlalchemy.orm import Session

        with Session(engine) as s:
            yield s

    app.dependency_overrides[get_session] = _session
    local = TestClient(app, base_url="http://127.0.0.1:8000")
    assert local.get("/login").status_code == 200
    # The same server reached through a public name (a proxy in front of it): no sign-in.
    assert "Local demo" in local.get("/login").text
    public = TestClient(app, base_url="https://protect.transfunnel.com")
    assert "Local demo" not in public.get("/login").text  # only the password sign-in
    assert public.post("/login/dev", data={"user_id": "1"}).status_code == 404
    engine.dispose()

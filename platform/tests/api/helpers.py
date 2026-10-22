"""Test helpers that behave like the WordPress plugin: build reports and sign requests."""

import base64
import copy
import json
import secrets
import time
from datetime import UTC, datetime
from typing import Any

from nacl.signing import SigningKey

from app.api.signing import key_id_for, signed_message

SITE_URL = "http://127.0.0.1:8081"

SAMPLE_REPORT: dict[str, Any] = {
    "schema": 1,
    "plugin_version": "0.1.0",
    "generated_at": "2026-10-22T10:00:00Z",
    "site_url": SITE_URL,
    "php": {
        "version": "8.3.30",
        "major": 8,
        "minor": 3,
        "release": 30,
        "extra": "",
        "sapi": "apache2handler",
        "extensions": [
            {"name": "imagick", "version": "3.7.0"},
            {"name": "sodium", "version": "8.3.30"},
        ],
        "ini": {
            "session.upload_progress.enabled": "1",
            "memory_limit": "256M",
            "opcache.enable": "1",
            "expose_php": "1",
        },
    },
    "libs": {
        "openssl": "OpenSSL 3.0.13 30 Jan 2024",
        "curl": "8.5.0",
        "curl_ssl": "OpenSSL/3.0.13",
    },
    "wordpress": {"version": "7.1.3", "multisite": False, "locale": "en_US"},
    "plugins": [
        {"slug": "contact-form-7", "version": "5.9.8", "active": True, "name": "Contact Form 7"},
        {"slug": "hello-dolly", "version": "1.7.2", "active": False, "name": "Hello Dolly"},
    ],
    "mu_plugins": [],
    "themes": [{"slug": "twentytwentyfive", "version": "1.5", "active": True}],
    "db": {"engine": "mariadb", "version": "11.4.8"},
    "server": {"software": "Apache/2.4.66 (Debian)"},
    "os": {
        "id": "debian",
        "id_like": None,
        "version_id": "13",
        "pretty_name": "Debian GNU/Linux 13",
    },
    "checks": {
        "core": {"status": "ok", "modified": [], "unexpected": []},
        "plugins": [{"slug": "contact-form-7", "status": "ok", "modified": []}],
        "uploads_php": [],
        "mu_plugins_present": [],
        "user_ini": [],
        "auto_prepend": {"set": False, "location": None},
        "recent_php_changes": [],
        "scan": {"complete": True, "finished_at": "2026-10-22T09:58:00Z"},
    },
}


def report(**changes: Any) -> dict[str, Any]:
    """A fresh copy of the sample report, generated 'now', with top-level overrides."""
    data = copy.deepcopy(SAMPLE_REPORT)
    data["generated_at"] = datetime.now(UTC).isoformat()
    data.update(changes)
    return data


class FakePlugin:
    def __init__(self) -> None:
        self.key = SigningKey.generate()
        self.public_key = base64.b64encode(bytes(self.key.verify_key)).decode()
        self.key_id = key_id_for(self.public_key)

    def headers(
        self, body: bytes, *, ts: int | None = None, nonce: str | None = None, with_key: bool = True
    ) -> dict[str, str]:
        ts_s = str(ts if ts is not None else int(time.time()))
        nonce = nonce or secrets.token_hex(16)
        sig = self.key.sign(signed_message(ts_s, nonce, body)).signature
        h = {
            "content-type": "application/json",
            "x-protect-timestamp": ts_s,
            "x-protect-nonce": nonce,
            "x-protect-signature": base64.b64encode(sig).decode(),
        }
        if with_key:
            h["x-protect-key"] = self.key_id
        return h

    def enroll_body(self, code: str, site_url: str = SITE_URL) -> bytes:
        return json.dumps(
            {
                "code": code,
                "site_url": site_url,
                "public_key": self.public_key,
                "plugin_version": "0.1.0",
            }
        ).encode()


def body_of(data: dict[str, Any]) -> bytes:
    return json.dumps(data).encode()

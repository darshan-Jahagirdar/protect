"""The Docker image must contain everything the app reads at runtime."""

import re
from pathlib import Path

PLATFORM_DIR = Path(__file__).resolve().parent.parent


def test_dockerfile_copies_runtime_dirs() -> None:
    dockerfile = (PLATFORM_DIR / "Dockerfile").read_text()
    copied = set(re.findall(r"^COPY (\S+) \./", dockerfile, flags=re.M))
    # fixtures/ was once missing, which broke `replay-advisory` in the container.
    assert {"app", "migrations", "fixtures", "alembic.ini"} <= copied


def test_fixtures_are_not_dockerignored() -> None:
    ignored = (PLATFORM_DIR / ".dockerignore").read_text().split()
    assert "fixtures" not in ignored

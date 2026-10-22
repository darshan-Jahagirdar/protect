import os
from collections.abc import Iterator
from pathlib import Path

import pytest

# Point the app at a throwaway database before any app module is imported.
os.environ.setdefault("PROTECT_ENV", "test")
os.environ.setdefault("PROTECT_DATABASE_URL", "sqlite:///:memory:")

from sqlalchemy.orm import Session  # noqa: E402

from app.db import Base, make_engine  # noqa: E402


@pytest.fixture
def db_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'test.sqlite'}"


@pytest.fixture
def session(db_url: str) -> Iterator[Session]:
    engine = make_engine(db_url)
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s
    engine.dispose()

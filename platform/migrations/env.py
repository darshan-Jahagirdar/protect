"""Alembic environment. Uses the app's settings and models, so there is one source of truth."""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import event

import app.models  # noqa: F401  (registers every table on Base.metadata)
from app.db import Base, make_engine
from app.settings import get_settings

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _url() -> str:
    # Tests pass an explicit URL through the Alembic config; otherwise use app settings.
    return config.get_main_option("sqlalchemy.url") or get_settings().database_url


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,  # SQLite can't ALTER most things; batch mode rebuilds tables
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = make_engine(_url())
    if engine.dialect.name == "sqlite":
        # Batch mode rebuilds a table (copy, DROP the old one, rename). With foreign keys
        # enforced, that DROP runs every ON DELETE action on rows pointing at the table: it
        # deleted advisory ranges and incident links (CASCADE) and blanked who-did-what
        # (SET NULL). So enforcement is off while migrating, and checked afterwards.
        @event.listens_for(engine, "connect")
        def _foreign_keys_off(dbapi_conn, _record) -> None:  # type: ignore[no-untyped-def]
            dbapi_conn.execute("PRAGMA foreign_keys=OFF")

    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()
        if engine.dialect.name == "sqlite":
            broken = connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
            if broken:
                raise RuntimeError(f"migration left {len(broken)} broken references: {broken[:5]}")
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

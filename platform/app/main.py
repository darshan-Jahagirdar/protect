"""Protect platform entry point.

Run with exactly ONE worker: the scheduler runs in-process, and more workers would run
every job more than once.
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from app.api.routes import Limiters
from app.api.routes import router as api_router
from app.dashboard.auth import NotSignedIn
from app.dashboard.routes import router as dashboard_router
from app.observer.observe import observe
from app.security import SecurityHeadersMiddleware
from app.settings import Settings, get_settings

APP_DIR = Path(__file__).resolve().parent


def _configure_logging() -> None:
    log = logging.getLogger("protect")
    if not log.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s [%(name)s] %(message)s"))
        log.addHandler(handler)
        log.setLevel(logging.INFO)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    _configure_logging()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        scheduler = None
        if settings.scheduler_enabled and settings.env != "test":
            from app.scheduler import start

            scheduler = start(settings)
        yield
        if scheduler is not None:
            scheduler.shutdown(wait=False)

    app = FastAPI(
        title="Protect",
        lifespan=lifespan,
        # No public API docs in prod: the only public surface is /api/v1/*.
        docs_url=None if settings.is_prod else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_prod else "/openapi.json",
    )
    app.state.settings = settings
    app.state.limiters = Limiters.from_settings(settings)
    app.state.observe = observe  # swappable in tests; the real one makes one GET /
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.is_prod)
    app.mount("/static", StaticFiles(directory=APP_DIR / "dashboard" / "static"), name="static")

    @app.exception_handler(NotSignedIn)
    async def _not_signed_in(request: Request, exc: NotSignedIn) -> Response:
        if settings.is_prod:  # prod sign-in is Cloudflare Access (P4); nothing to redirect to yet
            return Response(status_code=401)
        target = "/login" + (f"?next={quote(exc.next_path)}" if exc.next_path != "/" else "")
        return RedirectResponse(target, status_code=303)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(api_router)
    app.include_router(dashboard_router)
    return app


app = create_app()

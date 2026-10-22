"""Protect platform entry point.

Run with exactly ONE worker: the scheduler (added later) runs in-process, and more workers
would run every job more than once.
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.dashboard.routes import router as dashboard_router
from app.security import SecurityHeadersMiddleware
from app.settings import Settings, get_settings

APP_DIR = Path(__file__).resolve().parent


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(
        title="Protect",
        # No public API docs in prod: the only public surface is /api/v1/*.
        docs_url=None if settings.is_prod else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_prod else "/openapi.json",
    )
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.is_prod)
    app.mount("/static", StaticFiles(directory=APP_DIR / "dashboard" / "static"), name="static")

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(dashboard_router)
    return app


app = create_app()

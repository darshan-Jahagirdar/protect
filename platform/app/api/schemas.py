"""Strict schemas for what the plugin may send (DESIGN.md §5.1).

Every model forbids extra fields, so the data list really is fixed (rule R4). Field formats
are checked here too: versions look like versions, slugs are lowercase, and paths are
site-relative with no "..". Anything that doesn't fit is rejected, never "fixed up".
"""

import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints

# --- Field formats ------------------------------------------------------------------

Version = Annotated[str, StringConstraints(pattern=r"^[0-9A-Za-z.+~:_-]{1,64}$")]
Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{0,99}$")]
Token = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")]
Locale = Annotated[str, StringConstraints(pattern=r"^[A-Za-z]{2,3}(?:_[A-Za-z0-9]{2,8}){0,2}$")]

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _no_control_chars(v: str) -> str:
    if _CONTROL.search(v):
        raise ValueError("control characters are not allowed")
    return v


# Free text for display only (plugin names, descriptive version strings). Always escaped
# when shown, never used for matching.
Text = Annotated[str, Field(max_length=200), AfterValidator(_no_control_chars)]


def _site_relative(v: str) -> str:
    if v.startswith(("/", "\\")) or "\\" in v:
        raise ValueError("path must be site-relative with forward slashes")
    if any(part == ".." for part in v.split("/")):
        raise ValueError("path must not contain '..'")
    return _no_control_chars(v)


Path = Annotated[str, Field(min_length=1, max_length=400), AfterValidator(_site_relative)]
PathList = Annotated[list[Path], Field(max_length=500)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --- Report ---------------------------------------------------------------------------


class PhpExtension(Strict):
    name: Token
    version: Version | None = None


class PhpIni(Strict):
    session_upload_progress_enabled: Text | None = Field(
        None, alias="session.upload_progress.enabled"
    )
    memory_limit: Text | None = None
    opcache_enable: Text | None = Field(None, alias="opcache.enable")
    expose_php: Text | None = None


class Php(Strict):
    version: Version
    major: int = Field(ge=0, le=99)
    minor: int = Field(ge=0, le=99)
    release: int = Field(ge=0, le=999)
    extra: Annotated[str, StringConstraints(pattern=r"^[0-9A-Za-z.+~:_-]{0,50}$")]
    sapi: Token
    extensions: Annotated[list[PhpExtension], Field(max_length=200)] = []
    ini: PhpIni = PhpIni()


class Libs(Strict):
    openssl: Text | None = None
    curl: Text | None = None
    curl_ssl: Text | None = None
    libxml2: Text | None = None
    pcre2: Text | None = None
    icu: Text | None = None
    imagemagick: Text | None = None


class WordPress(Strict):
    version: Version
    multisite: bool = False
    locale: Locale = "en_US"


class Plugin(Strict):
    slug: Slug
    version: Version | None = None
    active: bool
    name: Text = ""


class MuPlugin(Strict):
    file: Path
    name: Text = ""
    version: Version | None = None


class Theme(Strict):
    slug: Slug
    version: Version | None = None
    active: bool


class Db(Strict):
    engine: Literal["mysql", "mariadb", "unknown"]
    version: Version | None = None


class Server(Strict):
    software: Text | None = None


class Os(Strict):
    id: Token | None = None
    id_like: Annotated[str, Field(max_length=100), AfterValidator(_no_control_chars)] | None = None
    version_id: Version | None = None
    pretty_name: Text | None = None


class CoreCheck(Strict):
    status: Literal["ok", "mismatch", "unavailable"]
    modified: PathList = []
    unexpected: PathList = []


class PluginCheck(Strict):
    slug: Slug
    status: Literal["ok", "mismatch", "unverifiable", "unavailable"]
    modified: PathList = []


class AutoPrepend(Strict):
    set: bool
    location: Path | Literal["outside_site_root"] | None = None


class Scan(Strict):
    complete: bool
    finished_at: datetime | None = None


class Checks(Strict):
    core: CoreCheck
    plugins: Annotated[list[PluginCheck], Field(max_length=500)] = []
    uploads_php: PathList = []
    mu_plugins_present: PathList = []
    user_ini: PathList = []
    auto_prepend: AutoPrepend
    recent_php_changes: Annotated[list[Path], Field(max_length=50)] = []
    scan: Scan


class Report(Strict):
    schema_: Literal[1] = Field(alias="schema")
    plugin_version: Version
    generated_at: datetime
    site_url: Annotated[str, StringConstraints(pattern=r"^https?://[^\s]{1,490}$")]
    php: Php
    libs: Libs = Libs()
    wordpress: WordPress
    plugins: Annotated[list[Plugin], Field(max_length=500)] = []
    mu_plugins: Annotated[list[MuPlugin], Field(max_length=200)] = []
    themes: Annotated[list[Theme], Field(max_length=200)] = []
    db: Db | None = None
    server: Server = Server()
    os: Os | None = None
    checks: Checks


# --- Enrollment -------------------------------------------------------------------------


class EnrollRequest(Strict):
    code: Annotated[str, StringConstraints(pattern=r"^[A-Z0-9-]{8,40}$")]
    site_url: Annotated[str, StringConstraints(pattern=r"^https?://[^\s]{1,490}$")]
    public_key: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9+/]{43}=$")]  # 32 bytes
    plugin_version: Version

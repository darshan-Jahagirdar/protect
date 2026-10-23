# AGENTS.md — rules for coding agents working on Protect

Read this before changing anything. [DESIGN.md](DESIGN.md) is the source of truth for *what* we build. This file covers *how* to work on it. [PROGRESS.md](PROGRESS.md) is where you log what you did.

## What this project is

TransFunnel Protect is an internal security-alert and response tool for the ~10 client WordPress sites our agency manages. It has two parts:

- **A WordPress plugin** (`plugin/protect-reporter/`, PHP). It sends a signed inventory report from each site.
- **The platform** (`platform/`, Python). It matches those reports against vulnerability advisories, alerts the team by email, and guides the fix through to the client message.

One developer builds and maintains it. Keep things simple enough for one person to run.

## Non-negotiable rules

If a change would break any of these, **stop and ask the user**. Don't look for a workaround.

1. **Output-only plugin.** The plugin never registers a REST route, an `admin-ajax` handler, a query-var handler or anything else that accepts outside input. The one exception is WordPress's own admin-only, nonce-checked "Report now" button.
2. **The plugin ignores replies.** After `wp_remote_post`, read only the status code. Never parse, store or act on the response body.
3. **No commands on servers.** The plugin must never use `exec`, `shell_exec`, `system`, `passthru`, `proc_open`, `popen`, backticks, `eval`, `assert` with strings, `create_function` or `preg_replace` with `/e`. A test enforces this.
4. **A hard-coded data list.** The report fields are exactly the ones in DESIGN.md §5.1.
   - Adding a field means updating DESIGN.md §5.1 and noting in PROGRESS.md that the compliance doc needs updating.
   - Never add a field from a setting or a filter hook.
5. **Never collect** client contact details, visitor data or IP addresses, any logs or log counts, database contents, file contents, passwords, API keys or tokens.
   - Paths are sent site-relative only. Paths outside the site root become `outside_site_root`.
6. **No contact fields** in the database, ever.
7. **The AI gets only** advisory text, component names with versions, and fixed versions. All AI calls go through `platform/app/ai/` and its input allowlist. Never call a model SDK directly from anywhere else.
8. **The AI never decides** exposure, priority or status. Only `platform/app/engine/` decides, deterministically.
9. **Alerts carry counts only.** No site names, URLs or business names in emails, Teams messages or any other outbound message.
10. **The platform only views public pages** of client sites (`platform/app/observer/`): one `GET /`, headers and TLS only. No logins, form posts, path probing or crawling.
11. **No automatic actions on client sites or Cloudflare** in v1. People act.

## Security rules for code

- **Treat everything from sites, feeds and the AI as hostile.** That includes plugin names, paths, advisory text and model output.
  - Jinja autoescape stays on, and `|safe` is never used on such data.
  - The CSP is never loosened to allow inline scripts.
- **Validate every report** with the strict pydantic schema (`extra="forbid"`) and the format checks in DESIGN.md §4.2. If a check fails, reject the report or flag it. Never silently "fix" the data.
- **Compare versions only** with `platform/app/engine/versions.py`. Never compare raw strings, and never pass raw `PHP_VERSION` to a semver library.
- **Unparseable or ambiguous means `needs_check`**, never `safe`.
- **Use SQLAlchemy queries or bound parameters only.** No string-built SQL.
- **Keep secrets out of the repo.** They live in `.env` (gitignored), and `.env.example` documents every variable. Never print secrets in logs or test output.
- **No real exploit code or PoCs** for PHP2Shell or anything else, anywhere in the repo. The demo proves *detection and response*, not exploitation.
- **The vulnerable demo container binds to `127.0.0.1` only.** Never add a tunnel, a public port or a deploy target for it.
- **Run one `uvicorn` worker.** APScheduler runs in-process, so more workers would run every job more than once.

## Plugin coding rules (`plugin/protect-reporter/`)

- **Compatibility:** PHP 7.4+ and WordPress 5.9+. No PHP 8-only syntax (no `match`, no constructor promotion, no nullsafe `?->`, no `str_contains`).
- **Dependencies:** none, no Composer packages. Use only WordPress core and PHP core. Signing uses `sodium_*` (native, or the `sodium_compat` bundled with WordPress).
- **Outbound HTTP** goes only through `wp_remote_post` or `wp_remote_get`, and only to:
  - the configured platform URL (POST)
  - `api.wordpress.org`
  - `downloads.wordpress.org` (checksums)
- **Speed:** keep any scan to a 10-second budget per run and store a cursor. Cheap hosts kill long requests.
- **Escaping and naming:** escape all admin output (`esc_html`, `esc_attr`, …). Prefix every function, option and hook with `protect_reporter_`.
- **Uninstall:** `uninstall.php` removes every option the plugin created.

## Platform coding rules (`platform/`)

- **Stack:** Python 3.12, managed with **uv**. FastAPI, Jinja2, HTMX (served locally, no CDN), SQLAlchemy 2, Alembic, pydantic v2, APScheduler, httpx, PyNaCl.
- **Style:** type hints everywhere, small modules, and no framework magic you'd have to explain.
- **Migrations:** every schema change is an Alembic migration.
- **Checklists** are YAML templates in `app/checklists/templates/`, reviewed by a person. Never generate checklist steps with AI.
- **Drill advisories** (`drill=true`) must show `[DRILL]` in every view, alert and draft.

## Commands

Keep this section accurate as the project grows. The platform and plugin commands below take effect from steps 2 and 5.

```bash
# demo environment (vulnerable WP on localhost only, mailpit; platform from step 2)
cp docker/.env.example docker/.env        # first time only; use random values
docker compose -f docker/compose.yaml up -d --build
docker compose -f docker/compose.yaml ps
docker compose -f docker/compose.yaml down   # add -v to wipe demo data

# platform (run from platform/)
uv sync                                   # PyPI can be slow here: set UV_HTTP_TIMEOUT=120 if it stalls
uv run pytest
uv run ruff format app tests migrations && uv run ruff check app tests migrations
uv run alembic upgrade head               # local DB: platform/data/protect.sqlite
uv run alembic revision --autogenerate -m "what changed"   # after editing app/models.py
uv run uvicorn app.main:app --reload --port 8000           # or use the `platform` compose service

# admin CLI (in the demo: docker compose -f docker/compose.yaml exec platform python -m app.cli ...)
python -m app.cli add-site | new-code | list-sites
python -m app.cli replay-advisory php2shell|drill-plugin    # match now; alerts go out on the next scheduler run
python -m app.cli list-incidents | send-alerts | send-digest | ack-incident <id>
# demo alert emails: http://127.0.0.1:8025 (Mailpit)

# plugin checks (no local PHP needed; PHP 7.4 lint proves old-site compatibility)
for img in php:7.4-cli php:8.3.30-apache; do docker run --rm -v "$PWD/plugin/protect-reporter:/p:ro" $img sh -c 'for f in $(find /p -name "*.php"); do php -l "$f" | grep -v "^No syntax errors"; done'; done
cd platform && uv run pytest tests/test_plugin_rules.py          # static rule checks (banned calls, no inbound endpoints, ...)
docker compose -f docker/compose.yaml run --rm --no-deps -T --entrypoint wp wp-setup --path=/var/www/html eval 'echo wp_json_encode( Protect_Reporter_Inventory::build() );'   # see a payload (CLI PHP, for inspection only)
```

## Testing expectations

- **Engine changes** (`engine/`) need table-driven tests in the same change. That covers distro suffixes (Ubuntu, Debian, Sury), RHEL with no suffix, unsupported branches and unparseable versions.
- **API changes** need tests for: a bad signature, a replay, a stale timestamp, an oversized body, extra fields, a CLI SAPI, and a `<script>` payload in a plugin name.
- **AI code** uses the `fake` provider in tests. Tests never call a real model or the network.
- **Before you say something works,** run the tests and report the actual result. If you couldn't run them, say so.

## Logging your work in PROGRESS.md

After each meaningful piece of work:

1. **Update the status board.** Each build step is one of `not started`, `in progress`, `blocked`, or `done`.
2. **Add a dated line to the work log.** Say what changed, which tests ran and what they returned, and anything left unfinished.
3. **Record decisions** in the decision log with the date and the reason. That includes any change to a rule or to DESIGN.md.
4. **Add new questions** to Open questions. Don't guess answers to product, legal or data-collection questions; ask the user.

## When to stop and ask

- Anything that touches the rules above, or adds a data field, outbound call or new subprocessor.
- Choosing between options that change cost, hosting, legal wording or what clients are told.
- Anything destructive: deleting data or migrations, rewriting git history.
- Commits and pushes happen only when the user asks.

# PROGRESS — status, decisions, log

How to use this file (see [AGENTS.md](AGENTS.md)):
- Update the status board when a step changes state.
- Add a dated line to the work log after each piece of work.
- Record every decision with its reason.

Newest entries go at the top of each log.

Status values: `not started` · `in progress` · `blocked` · `done`

---

## Status board

### Milestone 1: Demo (local)

| # | Step | Status | Notes |
|---|---|---|---|
| 0 | Design docs (DESIGN, AGENTS, PROGRESS) | done | 2026-10-22 |
| 1 | Repo scaffold + Docker demo env (`wp-vuln` on 127.0.0.1, `wp-db`, `wp-cron`, `mailpit`) | done | 2026-10-22: WordPress 7.1.3 on PHP 8.3.30 (mod_php), localhost only. Platform service gets added to compose in step 2 |
| 2 | Platform skeleton: FastAPI app, settings, SQLAlchemy models, Alembic | done | 2026-10-22: 20 tables, first migration, 13 tests passing; `platform` service at 127.0.0.1:8000 |
| 3 | Version engine + matcher with table-driven tests | done | 2026-10-22: `app/engine/` (versions, matcher, catalogue) + PHP2Shell fixture; 139 engine tests |
| 4 | Enrollment + signed Report API (validation, nonce, dedupe) | done | 2026-10-22: `/api/v1/enroll` + `/api/v1/report`, inventory rebuild, odd-report flags, admin CLI; 44 new tests |
| 5 | Plugin: inventory, signing, hourly cron, Report now, transparency page | done | 2026-10-22: demo site enrolled through the admin page; real reports accepted (204). File checks still placeholders until step 10 |
| 6 | Advisory replay (PHP2Shell + drill plugin advisory), incidents, cases, scoring | done | 2026-10-22: replayed live, PHP2Shell P1 (80) and [DRILL] P4 (25) for the demo site; re-match on every changed report |
| 7 | Alerts: email (Mailpit in demo), ack, escalation | done | 2026-10-23: scheduler emailed the live P1 to Mailpit; acknowledged from the incident page; digest listed the drill. Graph email comes in M2 |
| 8 | Dashboard: sites, incidents, case view, checklist, timeline (dev login) | done | 2026-10-23: signed in, set WP Engine, ticked a step, shielded (80 → 75), viewer sees no controls. Prod sign-in (Cloudflare Access) is P4 |
| 9 | Patch → auto-verify | not started | Switch container to `php:8.3.36-apache` |
| 10 | File checks: core and plugin checksums, uploads PHP, mu-plugins, hiding spots | not started | Batched, 10 s budget |
| 11 | Observer (public page view) | not started | |
| 12 | AI module (Gemini Argon; fake provider for tests) + summary + client draft | not started | |
| 13 | Demo rehearsal | not started | |

### Milestone 2: Production

| # | Step | Status | Notes |
|---|---|---|---|
| P1 | Live feeds: php.net, php-src GHSA, CISA KEV, Wordfence, NVD, Ubuntu/Debian | not started | |
| P2 | Microsoft Graph email + optional Teams Workflows webhook | not started | Needs M365 admin (Q5) |
| P3 | India-region VM, Caddy, systemd, Litestream backups, encrypted disk | not started | Provider (Q7) |
| P4 | Cloudflare Access with Entra SSO for the dashboard | not started | Domain on Cloudflare (Q4) |
| P5 | Heartbeat (healthchecks.io), stale-site and feed-failure alerts | not started | |
| P6 | Public test site (patched PHP) + drill advisories | not started | |
| P7 | Security review of platform and plugin | not started | |
| P8 | Runbooks + backup person trained | not started | Backup person (Q6) |
| P9 | Roll out plugin to all managed sites (with client authorization) | not started | After compliance doc and agreement updates |
| P10 | First real advisory handled end to end | not started | Gate for founding clients |

### Doc follow-ups (Claude Docs, outside this repo)

| Doc | Change needed | Status |
|---|---|---|
| Data and compliance | Expand the data inventory (DESIGN §5.1). Reword "never collect logs" to "client logs". Add public-page viewing and checksum comparison. Update the subprocessor list | not started |
| GTM | Drop or redefine the "Monitor" tier. Replace the "zero successful compromises" metric. Source or remove the unverified PHP2Shell timing claims | not started |
| Build plan | Align with DESIGN.md: stack, signatures, email alerts, incidents, revised build order | not started |

---

## Decision log

| Date | Decision | Why |
|---|---|---|
| 2026-10-23 | Session cookie is `SameSite=Lax`, not Strict (DESIGN said Strict) | With Strict, the link in an alert email would open a signed-out page. CSRF tokens plus the same-site Origin check still block cross-site posts |
| 2026-10-23 | Sessions are our own HMAC-signed cookie (user id, expiry, CSRF token); no extra session library or server-side store | Small, auditable, nothing secret in the browser; forged or expired cookies are rejected |
| 2026-10-23 | Dev sign-in is "pick a team member", local only. Prod returns 404 for `/login` and 401 for dashboard pages until Cloudflare Access (P4) | No password handling to build or secure; prod can't be opened by accident |
| 2026-10-23 | Roles: viewer (read), responder (ack, case actions, checklist, replay), admin (sites, enrollment codes, risk tags, team) | Matches DESIGN §4.13 |
| 2026-10-23 | Decisions (false positive, accepted risk, not affected) and "shielded" need a note; "fix claimed" doesn't; Undo hands the case back to the engine | Every judgement call leaves a written reason in the timeline |
| 2026-10-23 | Checklist placeholders are limited to an allowlist (`component`, `current_version`, `fix_text`, `advisory_ids`, `host`); templates are validated on load and in tests | Templates stay reviewable and can't pull in other data |
| 2026-10-23 | Dashboard pages use plain HTML forms with no JavaScript (HTMX not needed yet). Added `pyyaml` and `python-multipart` | Simplest thing that works under the strict CSP |
| 2026-10-23 | Flash messages use fixed keys (`?msg=saved`), never text from the URL | No reflected content |
| 2026-10-23 | Alerts are worked out from DB state by a 60-second scheduler job, not sent from inside the report request | Report requests stay fast; a failed send just retries; nothing is sent twice |
| 2026-10-23 | Acknowledgement is per incident (a timeline event), not per alert. One escalation per incident, to the backup if set, otherwise back to the responders marked [UNACKNOWLEDGED] | No backup person yet (Q6); an ack made before the email arrives must still count |
| 2026-10-23 | Alert text is built only from a site-free `IncidentSummary` | Makes rule R9 (counts only) structural rather than a matter of care |
| 2026-10-23 | The incident page and ack button work only outside prod until the step 8 login. Form posts are checked for a same-site `Origin` | No unauthenticated pages showing site details or changing state in production |
| 2026-10-23 | `Referrer-Policy` changed from `no-referrer` to `same-origin` | `no-referrer` makes browsers send `Origin: null` on our own form posts (found live). `same-origin` still sends nothing to other sites |
| 2026-10-23 | Teams mirroring postponed to M2 (P2), alongside Graph email | One alert channel is enough for the demo; the team uses Outlook |
| 2026-10-22 | The engine only moves cases between vulnerable and needs_check, and reopens verified or not_affected cases on regression. People's decisions (fix_claimed, false_positive, accepted_risk) are never overwritten | Automation must not undo a human call |
| 2026-10-22 | A safe or uninstalled component is recorded as a `match_now_safe` / `component_removed` timeline event; exposure doesn't change until step 9 | Keeps the auto-verify rules in one place (step 9) |
| 2026-10-22 | Advisories merge on any shared alias (CVE, GHSA, …). One open incident per advisory; re-replaying updates and never duplicates | PHP2Shell is 2 CVEs and 2 GHSAs; feeds will report it under different IDs |
| 2026-10-22 | Unknown CVSS scores as high (+25). Added `advisories.network_unauthenticated` and the case facts (`version_seen`, `fixed_version`, `unsupported_branch`, `match_reasons`) | Never under-rate a flaw because data is missing; the dashboard can show "fixed in 8.3.36" without re-running the engine |
| 2026-10-22 | The drill advisory targets Hello Dolly, installed but left inactive on the demo site | Shows the plugin-flaw path and the "inactive −10" scoring rule |
| 2026-10-22 | Until step 10, the plugin sends `checks.core.status = "unavailable"` and `scan.complete = false`. The two cheap settings checks (`auto_prepend_file`, mu-plugin list) are real | Honest about what hasn't run; never a fake "ok" |
| 2026-10-22 | The plugin cleans its own values to fit the schema: lowercases tokens and slugs, strips control characters, caps text at 200 chars, turns invalid versions into null. The platform still rejects anything that doesn't fit | The source cleans up; the receiver never "fixes" data |
| 2026-10-22 | A new key pair is generated on every Connect and saved only if enrollment succeeds | Reconnecting rotates the key; a failed attempt leaves the working key in place |
| 2026-10-22 | The plugin is mounted read-only into the demo WordPress, and `wp-setup` activates it | Code changes show up immediately; WordPress can't modify the plugin |
| 2026-10-22 | Enrollment needs proof of possession: the enroll request is signed by the key being enrolled. Codes are 16 characters (80 bits), single use, 24 h, and stored only as SHA-256 | Nobody can register a key they don't hold; a leaked DB doesn't reveal usable codes |
| 2026-10-22 | The size check runs before the signature check, and a nonce is stored only after a valid signature | Stops large-body abuse and nonce burning by unauthenticated callers |
| 2026-10-22 | Identical reports are deduplicated on a content hash that leaves out `generated_at`; only `last_report_at` moves | Hourly reports would otherwise store a copy every hour |
| 2026-10-22 | Odd reports (site URL mismatch, PHP or WordPress downgrade, inconsistent PHP fields, `generated_at` more than 24 h off) are stored but flag the site as `suspicious` | DESIGN §4.2: flag, don't silently fix. A staging clone with the same key shows up as a URL mismatch |
| 2026-10-22 | Rate limits live in memory (per IP 120, per key 30, enroll 10, each per 10 min) | Single process by design; must move to a shared store if that ever changes |
| 2026-10-22 | OS-provided components (`php-ext`, `lib`, `db`, `server`) inside an affected range are always needs_check | The OS or host backports fixes, and the plugin can't see package versions for these |
| 2026-10-22 | Ubuntu and Debian PHP builds are judged by distro fix data (dpkg comparison) before the "unsupported branch" rule | Ubuntu still patches its own PHP 8.1 even though upstream has ended it |
| 2026-10-22 | Range format: OSV-style `introduced` + one of `fixed` / `last_affected` / `limit` (+`unsupported`). Broken or empty ranges mean needs_check with "advisory needs review" | One clear format for every feed; bad advisory data can never produce "safe" |
| 2026-10-22 | The PHP2Shell fixture records no CVSS vector (not verified); `network_unauthenticated: true` is taken from the advisory text instead | Don't invent data; scoring (step 6) reads that flag |
| 2026-10-22 | Enum columns are stored as strings with CHECK constraints. All datetimes go through `UTCDateTime`, which rejects naive values. Constraint names follow a fixed naming convention | Bad values can't slip into the DB; time zones stay unambiguous (the team is in IST, clients in the US); Alembic's SQLite batch migrations need stable names |
| 2026-10-22 | `reports.schema` from DESIGN §5.2 is named `schema_version` in code | Avoids a confusing name clash with SQL "schema"; same meaning |
| 2026-10-22 | The platform container runs as a non-root user (uid 10001) from its venv directly, applying migrations on start | Least privilege; the `uv` cache isn't writable for a system user |
| 2026-10-22 | GitHub repo `darshan-Jahagirdar/protect` stays public (the user's choice) | No secrets are committed (`.env` is gitignored). Keep client names, site URLs and real hosting details out of the repo |
| 2026-10-22 | The demo site is installed by a one-shot `wp-setup` container (WP-CLI, `wp core download` verifies the checksum). WP-Cron is disabled and the `wp-cron` container calls `wp-cron.php` over HTTP every minute | Matches the production rule that reports must come from the web SAPI |
| 2026-10-22 | WordPress sites only in v1 | Unknown whether any non-WordPress sites exist; keeps scope tight |
| 2026-10-22 | Checklist templates tuned for WP Engine first, within `managed-wp` | The client sites are probably on WP Engine |
| 2026-10-22 | No backup person yet: escalation re-alerts the primary and mirrors to Teams if configured | No backup is named; the single-owner risk stays open until one is |
| 2026-10-22 | Production hosting: try Oracle Cloud Always Free in an India region first; fallback small paid VM | The user wants free if possible. Oracle is the only always-free VM with Indian regions; idle-reclaim risk noted |
| 2026-10-22 | Working name stays "Protect" (plugin slug `protect-reporter`) | Trademark check deferred until client rollout |
| 2026-10-22 | Rules engine decides exposure. AI only explains and drafts | AI can wrongly say "safe", which is the worst failure for a security tool |
| 2026-10-22 | Three buckets: vulnerable / needs_check / safe. Unparseable or ambiguous means needs_check | Distro backports and odd version strings make version numbers unreliable |
| 2026-10-22 | Parse PHP version parts and `PHP_EXTRA_VERSION` ourselves, never with semver | `8.1.2-1ubuntu2.20` sorts as a pre-release in semver |
| 2026-10-22 | Reports must come from the web SAPI. CLI reports are rejected | CLI PHP can be a different binary from the one serving the site |
| 2026-10-22 | Inventory everything the plugin can see (PHP, extensions, libraries, WordPress, plugins, themes, DB, web server, OS) | PHP-only alerts would fire once a year or two; plugin flaws are monthly |
| 2026-10-22 | Component catalogue with standard keys and aliases per source | Names differ across Wordfence, NVD and distros; the mapping is the core of matching |
| 2026-10-22 | Primary feeds: php-src GHSA, php.net, Wordfence, CISA KEV. NVD only as fallback | NVD enrichment lags days to weeks |
| 2026-10-22 | Shield step = Cloudflare managed WAF rules + origin locked to Cloudflare, not "Under Attack" mode | Under Attack mode is a DDoS challenge and doesn't stop PHP2Shell |
| 2026-10-22 | Tool is output-only: no commands on servers, no inbound control, plugin ignores reply bodies | Keeps a platform breach from reaching client sites, and needs no new legal document |
| 2026-10-22 | Platform may view public pages (observer). Plugin may download wordpress.org checksums | Passes the three tests; covered by one line in the existing authorization clause |
| 2026-10-22 | Guiding principle: the three tests (no commands or control, no personal data, no new legal doc). Otherwise judge on usefulness | The user asked for a middle ground: safe but effective |
| 2026-10-22 | Ed25519 signed reports with timestamp and nonce, instead of bearer tokens | The secret never travels; a platform DB breach leaks only public keys; replays are blocked |
| 2026-10-22 | Escape all site, feed and AI data; strict CSP; field-format validation | A hacked site could inject script via plugin names into the dashboard |
| 2026-10-22 | File-check results worded "no warning signs found", never "clean" | A compromised site can lie in its reports |
| 2026-10-22 | Checklists from reviewed YAML templates per host type. AI never writes fix steps | A wrong fix step could leave a site exposed |
| 2026-10-22 | Incidents group advisories; cases track exposure, shield, compromise and client notice separately | PHP2Shell is 2 CVEs but one event; a site can be patched and shielded at once |
| 2026-10-22 | Full report every hour + on change. Server stores only changed reports | Fresh data in an emergency; simpler plugin; small database |
| 2026-10-22 | Platform in Python: FastAPI + Jinja/HTMX + APScheduler, one process | Fewest moving parts for a solo maintainer |
| 2026-10-22 | SQLite (WAL) in production with Litestream backups. PostgreSQL possible later | About 10 sites is tiny; one less service to run |
| 2026-10-22 | Alerts by email (Outlook / M365) via Microsoft Graph; optional Teams Workflows webhook | The team uses Teams and Outlook. SMTP basic auth is being disabled by default at the end of Dec 2026, and O365 connectors are retired |
| 2026-10-22 | Escalation: no ack in 15 min → backup person. Heartbeat via healthchecks.io | Nobody misses an alert, and we know if Protect itself is down |
| 2026-10-22 | AI: Gemini `gemini-4-argon` behind a swappable module. Medium thinking for summaries, high for drafts. One summary per incident | Speed in emergencies, quality for client text; trial credits may run out |
| 2026-10-22 | Dashboard behind Cloudflare Access with Entra SSO (MFA). Fallback: TOTP login | Uses existing M365 identities; no 2FA to build ourselves |
| 2026-10-22 | Vulnerable demo site on localhost only. Public test site on patched PHP with drill advisories | Public vulnerable sites get hacked within hours or days |
| 2026-10-22 | Host type changes who fixes and how, not whether a site is vulnerable | Managed hosts usually report accurate upstream versions |
| 2026-10-22 | Managed WordPress checklist templates first; generic cPanel and VPS templates | Known client sites are on managed WordPress hosts |
| 2026-10-22 | "Monitor" tier dropped or redefined as "we tell you" | Client-facing alerts would need contact data, which rule R6 forbids |
| 2026-10-22 | Keep running costs sensible, not minimal | Quality and simplicity win over saving a few dollars |

---

## Work log

| Date | Entry |
|---|---|
| 2026-10-23 | **Step 8 done.** Added `app/dashboard/auth.py` (signed session cookie, CSRF, roles, dev sign-in, open-redirect-safe `next`), a rewritten `app/dashboard/routes.py` (sign-in/out, overview, incidents, incident, case actions + checklist, sites + add site with a one-time code, site settings/risk tags/rotate code, advisories with replay buttons, team management, audit log), templates for every page (shared incident table and timeline partials), styles, `app/checklists/` (loader + 8 YAML templates: php-core managed-wp/cpanel/vps/default, wp-plugin, wp-theme, wp-core, lib), `app/services/cases.py` (claim fix, decisions with notes, undo, shield with rescoring, compromise flag, checklist ticks), and CLI `add-user`. Tests: `uv run pytest`, 369 passed (67 new: session tamper/expiry, safe redirects, Lax+HttpOnly cookie, disabled users, forged cookie, logout, every page renders with no `<script>`, hostile business name escaped on 4 pages, overview counts, role gates incl. viewer/responder/admin visibility, CSRF missing/wrong/cross-site/`null`, claim fix with actor, notes required, undo, shield 80→75→80, compromise, managed-wp checklist text, tick/untick, auto/unknown items refused, add site + code shown once, bad/duplicate URLs, risk tag +10, rotate code, replay button + bad fixture name, team add/disable/self-disable, prod has no dev sign-in, template validation). Live: rebuilt the image; unsigned `/` → 303 `/login`; signed in as Darshan (admin); overview 2 open / 0 unacked; set Demo Co to WP Engine; the PHP2Shell case showed the WP Engine checklist; ticked "host status" with a note, marked shielded with a note (score 80 → 75, still P1), timeline names Darshan; signed in as the viewer: no forms, no Team link. |
| 2026-10-23 | **Step 7 done.** Added `app/alerts/` (mailers: smtp, console, memory, with graph stubbed for M2; counts-only message wording), `app/services/alerting.py` (due alerts and "more sites" updates for P1/P2, 15-minute escalation, P3/P4 daily digest, incident-level acknowledgement, scheduler job functions), `app/scheduler.py` (APScheduler in the app lifespan, off in tests), the incident page `/incidents/<id>` with timeline and "I'm on it" (dev-only until step 8, origin-checked), styles, CLI `send-alerts` / `send-digest` / `ack-incident`, alert settings (+ `.env.example`, compose points at Mailpit), and migration `1c2f0340b4e4` (alerts.kind/priority/sites_count). Bugs found and fixed: (1) new cases weren't added to `incident.cases` in memory, so "more sites" updates and incident-priority refreshes could miss them; cases are now created through the relationship; (2) an ack before any email wasn't remembered; (3) live: `Referrer-Policy: no-referrer` made Chrome send `Origin: null`, so the ack was refused; switched to `same-origin`. Tests: `uv run pytest`, 302 passed (21 new: one alert only, update on more sites, P3/P4 to digest, closed/verified ignored, escalation at 15 min and only once, to backup when set, ack stops it, early ack, no recipients, mail failure retried, SMTP message, page + ack, cross-site and `null` origin refused, prod hides pages, every message checked against every site URL and name). Live: migration applied; the scheduler emailed `[Protect] P1: 1 site affected by PHP2Shell…` to Mailpit within a minute (counts only, link to the incident); the incident page showed Demo Co with reasons; "I'm on it" acknowledged it (timeline: opened → case → alert sent 05:32:40 → acknowledged 05:33:31); `send-alerts` then sent 0 escalations; `send-digest` listed `[DRILL] P4 … 1 site`. |
| 2026-10-22 | **Step 6 done.** Added `app/engine/scoring.py` (DESIGN §4.6 points and bands with readable reasons), `app/services/advisories.py` (load fixtures, upsert with alias merge, key validation), `app/services/incidents.py` (match advisory → sites, open or update incidents and cases, timeline events, re-match a site after each changed report, removed-component notes), `fixtures/advisories/drill-plugin.json`, CLI `replay-advisory` / `list-incidents`, and migration `f824bff757d6` (with server defaults so it runs on existing data). Demo `wp-setup` now installs Hello Dolly (inactive). Tests: `uv run pytest`, 281 passed (40 new: scoring table, PHP2Shell on mixed sites incl. EOL/RHEL/Ubuntu, no duplicates on re-replay, removed and pending sites ignored, needs_review opens nothing, risk tags, drill, joining an open incident from a new report, patch noticed, human decisions kept, reopen on downgrade, uninstall noted, alias merge, fixture-name safety, packaging). Live: the migration applied to the running DB; after Report now, `replay-advisory php2shell` gave P1, score 80, "PHP 8.3.30 is affected; fixed in 8.3.36"; `replay-advisory drill-plugin` gave [DRILL] P4, score 25 with the inactive reason; a second replay didn't duplicate. Bug found live and fixed: the Docker image lacked `fixtures/` (now copied, with a test that guards it). Also fixed the reason wording ("version PHP 8.3.30" → "PHP 8.3.30"). |
| 2026-10-22 | **Step 5 done.** Added `plugin/protect-reporter/`: main file, `Protect_Reporter_Inventory` (the hard-coded data list), `_Signer` (Ed25519 via sodium; private key in a non-autoloaded option), `_Sender` (enroll and report via `wp_remote_post`, reads the status code only, refuses the CLI SAPI), `_Scheduler` (hourly, after updates, on PHP change), `_Admin` (Settings → Protect Reporter: status, Connect, Report now, "exactly what was last sent"), and `uninstall.php`. Added `platform/tests/test_plugin_rules.py` (45 static checks). A planted canary file with `shell_exec`, `rest_api_init`, `wp_remote_retrieve_body` and `?->` was caught by 4 failing tests, then removed. `php -l` is clean on PHP 7.4.33 and 8.3.30. A real WordPress payload (built via WP-CLI) validated against the platform schema. Demo: logged into WP admin, connected with a fresh code (enrolled, first report HTTP 204 from `apache2handler`, PHP 8.3.30); Report now gave 204 and was deduplicated as unchanged; the hourly cron moved to the next hour. The platform stored 51 components with no odd-report flags. Side finding: the WP-CLI container runs PHP 8.3.36 while the site runs 8.3.30, which is exactly why CLI reports are refused. `uv run pytest`: 241 passed. |
| 2026-10-22 | **Step 4 done.** Added `app/api/` (strict report and enroll schemas, Ed25519 signing helpers, rate limiter, `/api/v1/enroll` and `/api/v1/report` routes returning bare status codes), `app/services/` (enrollment with URL normalisation and one-time codes; inventory rebuild, dedupe and odd-report flags) and `app/cli.py` (`add-site`, `new-code`, `list-sites`). Tests: `uv run pytest`, 196 passed (44 new). They cover a good report, a tampered body, the wrong key, an unknown or pending key, replay, a stale or future timestamp, oversized bodies, extra fields (top-level and nested), the CLI SAPI, path/slug/version formats, a `<script>` plugin name stored verbatim and escaped on render, control characters, the downgrade and URL-mismatch flags, the rate limit, HTTPS in prod, and every enrollment failure case. Ruff is clean. End to end against the Docker platform: CLI add-site, signed enroll 204, report 204, replay 401, identical report deduplicated (1 report stored, 12 components). Note: the demo DB now holds site #1 enrolled with a throwaway test key; step 5 issues a new code (`app.cli new-code --site-id 1`) for the real plugin. |
| 2026-10-22 | **Step 3 done.** Added `app/engine/versions.py` (PHP_VERSION split, a loose parser for WordPress, plugins and libraries incl. OpenSSL letters and pre-releases, a port of dpkg's version comparison, extraction for OpenSSL/Apache/nginx/LiteSpeed strings), `app/engine/catalogue.py` (key shapes, which kinds are OS-provided) and `app/engine/matcher.py` (vulnerable / needs_check / safe with plain-English reasons, fixed version per branch, unsupported-branch flag, distro rules). Added `fixtures/advisories/php2shell.json`. Tests: `uv run pytest`, 152 passed (139 new engine tests: PHP2Shell on every branch, Ubuntu/Debian with and without fix data, RHEL/CloudLinux, pre-release and unknown suffixes, broken advisory ranges, plugins, themes, OS-provided libraries, inactive components). Ruff is clean. |
| 2026-10-22 | **Step 2 done.** Added the `platform/` Python 3.12 project (uv): settings (prod requires an HTTPS base URL and a 32+ char secret), DB layer (SQLite WAL, foreign keys on), all 20 tables from DESIGN §5.2, enums, security-headers middleware (strict CSP, no inline scripts, HSTS in prod), an overview page, and the Alembic initial migration. Tests: `uv run pytest`, 13 passed. They cover health, security headers, autoescape, prod settings, the no-contact-fields rule, enum and unique constraints, the UTC handling, and migrations matching the models (`alembic check`). Ruff is clean. Docker: `platform` service at 127.0.0.1:8000. Verified healthz and overview return 200 with the CSP header, the page renders, it's reachable from the WordPress container as `http://platform:8000`, and it runs as a non-root user. Note: PyPI is slow from this network (~13 s per request), so `uv sync` needs `UV_HTTP_TIMEOUT=120`. |
| 2026-10-22 | **Step 1 done.** Set up git (`main`, remote `origin` = GitHub; nothing committed yet). Added `.gitignore`, README, `docker/compose.yaml`, `docker/wp-vuln/Dockerfile`, `docker/wp-setup.sh`, `docker/.env.example`. Local `docker/.env` has random secrets and is gitignored. Verified: homepage 200 with `X-Powered-By: PHP/8.3.30`; PHP 8.3.30 with no distro suffix; `session.upload_progress` on; ext-sodium present; `wp-cron.php` returns 200; Mailpit UI returns 200; ports bound to 127.0.0.1 only, and the LAN-IP request to :8081 was refused. Docker Desktop 4.96.2 at 4 CPUs / 4.3 GB. |
| 2026-10-22 | Wrote DESIGN.md, AGENTS.md (with CLAUDE.md importing it) and PROGRESS.md from the design review. No code yet. The folder is not a git repo yet. |
| 2026-10-22 | Reviewed the GTM, build plan and compliance docs against PHP2Shell research. Identified the gaps and decisions recorded above. |
| 2026-10-22 | Researched PHP2Shell (CVE-2026-109618/109619, fixed in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) and other October 2026 incidents. |

---

## Open questions

Mirrors DESIGN.md §12. Move a question to the decision log once it's answered.

| # | Question | Answer so far (2026-10-22) | Still to do | Needed by |
|---|---|---|---|---|
| Q1 | Which hosts are the ~10 sites on? | Probably **WP Engine** | Confirm per site when enrolling | Step 8 |
| Q2 | Any non-WordPress PHP sites? | Unknown. **Decision: WordPress only for now** | None for v1 | — |
| Q3 | Which sites are behind Cloudflare? | Unknown | The observer will detect it | P9 |
| Q4 | Is the TransFunnel domain on Cloudflare (for Access)? | Unknown | Ask IT. If not, use a separate domain on Cloudflare's free plan, or fall back to TOTP login | P4 |
| Q5 | Who can create the Graph app registration and sender mailbox? | **IT team** | Send IT a short request before M2 | P2 |
| Q6 | Who is the backup person for alerts? | **No one for now** | Name one before founding clients | P8 |
| Q7 | Which production VM provider? | **Free if possible** | Try Oracle Cloud Always Free (Mumbai or Hyderabad); fallback is a small paid VM | P3 |
| Q8 | Do the Gemini trial credits cover `gemini-4-argon`? | **User will check** | Also check India-region serving | Step 12 |
| Q9 | Wordfence Intelligence feed terms for internal commercial use | User said yes, go ahead | Claude reads the terms when building feeds | P1 |
| Q10 | Final product and plugin name | **"Protect" for now** | Trademark check before client rollout | P9 |

---

## Known issues and risks

| Risk | Mitigation |
|---|---|
| One person builds, maintains and responds | Runbooks, simple stack, trained backup before founding clients |
| Component-name mapping misses a match silently | Unmapped source names are logged and shown on the dashboard |
| Plugin blocked or restricted on some managed hosts | Check host rules before installing; fall back to manual inventory entry |
| A hacked site can send false reports | Observer cross-check, stale and suspicious flags, careful wording |

# Handoff — 2026-11-04 (evening: live feeds built)

Session summary for whoever picks up Protect next (a new Claude Code session, or a person). Read this first, then [AGENTS.md](AGENTS.md) (rules), [DESIGN.md](DESIGN.md) (what and why) and [PROGRESS.md](PROGRESS.md) (status board, every decision, work log).

## Where things stand

- **Live advisory feeds (P1) are built (2026-11-04), not deployed and not committed.** GitHub php-src advisories, php.net releases + news, CISA KEV, NVD, and Wordfence (built, off until the user creates its free API key). They run on the in-process scheduler; DESIGN.md §4.3 describes the rules (review gate, merge rules, one incident per release). Dashboard: **Feeds** page, review queue on **Advisories**, a page per advisory. Verified live in the local demo: a real GitHub advisory → incident → email → patch → auto-verified.
- **Next steps, in order:** (1) the user reviews and asks for a commit; (2) the user creates the Wordfence key (wordfence.com account → Integrations) and it goes in `docker/.env` and the server's `/etc/protect/protect.env` as `PROTECT_WORDFENCE_API_KEY`; (3) deploy (`deploy/deploy.sh`, it runs the new migration; first check the server DB has no linked rows to lose, see PROGRESS known issues); (4) work through the review queue once (9 GitHub items, mostly "doesn't say whether 8.3 is affected"); (5) then the transfunnel.com install, and update the dev team note to say feeds exist; (6) P1b Ubuntu/Debian trackers.
- **Fixed a migration trap (2026-11-04):** SQLite table rebuilds with foreign keys on deleted linked rows. `migrations/env.py` now turns them off while migrating and checks integrity after. The demo DB was repaired; who-acted on old demo events is gone for good.
- **Milestone 1 (demo):** steps 1–13 are done. The rehearsal ran the full script in 10 minutes on 2026-10-23. Its main finding (a stale "report and public view disagree" banner after each PHP change) is fixed; four small UI findings are still open (PROGRESS.md work log).
- **Security review (2026-11-03):** found no way to break into a client site or the platform. Fixed five bugs that could make Protect miss or misreport a problem (staging copies reporting as the live site, odd file names blocking reports, wordpress.org outages stalling scans, oversized reports, command-line cron), plus a guard so dev mode's password-free sign-in can't run on a server. Remaining items are under Known issues in PROGRESS.md.
- **Production (2026-11-03):** live at **https://13-200-85-221.sslip.io** on AWS Lightsail `protect-1` in Mumbai (static IP `13.200.85.221`, Ubuntu 24.04, 1 GB, hardened). Deploy with `deploy/deploy.sh ubuntu@13.200.85.221 13-200-85-221.sslip.io`; log in with `ssh -i ~/.ssh/protect_aws ubuntu@13.200.85.221`. It accepts reports, and the dashboard has sign-in (email + password + authenticator code; add people on the Team page or with `app.cli add-user`, which prints a one-time setup link). Alert email is live via Amazon SES in Mumbai (sandbox: only SES-verified addresses receive it; change recipients or the password with `deploy/set-email.sh` on the server). Still missing before a real site is enrolled: off-server backups, and the 3 DKIM DNS records so alerts stop showing as "Unverified" in Outlook.
- **First real site, after feeds:** our own transfunnel.com (WordPress 7.1.4 behind Cloudflare). Ready: the plugin zip (`plugin/build-zip.sh`) and the dev team note "Connecting transfunnel.com to Protect" in Claude Docs (https://claude.ai/artifact/KTG1wEmr6XydsAH54r84fC): what it sends, why it's safe, questions (incl. how its host runs WP-Cron, Q11), DNS records (`protect.transfunnel.com` A record + 3 SES DKIM CNAMEs) and install steps. Once feeds exist, update the note's summary to say so.
- **Tests:** 658 pass (`cd platform && uv run pytest`), and ruff is clean. Feed tests use recorded samples in `platform/tests/feeds/samples/`, never the network. The plugin lints clean on PHP 7.4 and 8.3, and `plugin/tests/logic-check.php` passes on PHP 7.4.
- **GitHub:** `darshan-Jahagirdar/protect` (public, by the owner's choice), branch `main`, everything pushed. Commits and pushes happen only when the user asks.
- **Claude Docs aligned with the build on 2026-10-23:** [GTM](https://claude.ai/artifact/CqXX1YdKiuXtyU1PQ83UuM), [Build plan](https://claude.ai/artifact/M3mtBXQqBcez9xheFecvae), [Data and compliance](https://claude.ai/artifact/S2wkNVaAxjNRD7bPVi3rgF). Read them with the Claude Docs connector, not a web fetch.

| # | Step | State |
|---|---|---|
| 1 | Docker demo (vulnerable WP on 127.0.0.1) | done |
| 2 | Platform skeleton | done |
| 3 | Version engine + matcher | done |
| 4 | Enrollment + signed report API | done |
| 5 | WordPress plugin | done |
| 6 | Advisory replay, incidents, scoring | done |
| 7 | Email alerts, ack, escalation, digest | done |
| 8 | Dashboard (sign-in, roles, cases, checklists) | done |
| 9 | Patch → auto-verify, monitoring, closing | done |
| 10 | File checks (warning signs) | done |
| 11 | Observer (public homepage cross-check) | done |
| 12 | AI summary + client drafts | done; demo runs on **OpenAI `gpt-6.1-sol`** (Gemini needs a Prepay top-up, below) |
| 13 | Demo rehearsal | done (findings in PROGRESS.md) |
| P1 | Live feeds (M2) | done locally 2026-11-04; Wordfence waits for its key; not deployed |

## Demo environment right now

Everything runs locally in Docker (`docker compose -f docker/compose.yaml ps` → mailpit, platform, wp-cron, wp-db, wp-vuln running).

| What | Where | Notes |
|---|---|---|
| Dashboard | http://127.0.0.1:8000 | Dev sign-in: pick **Darshan** (admin) or **Priya (viewer)** |
| Demo WordPress | http://127.0.0.1:8081/wp-admin | User `demo-admin`, password in `docker/.env`. Settings → Protect Reporter |
| Alert emails | http://127.0.0.1:8025 | Mailpit |

**State of the demo data:**
- **Docker is running** (stop with `docker compose -f docker/compose.yaml down`; volumes kept). Start again without resetting PHP: `WP_PHP_IMAGE=php:8.3.36-apache docker compose -f docker/compose.yaml up -d --build`.
- The site currently serves **PHP 8.3.36** (patched) and **WordPress 7.1.4** (it auto-updated; 7.1.3 had CVE-2026-119977, on CISA's list since 11-03).
- **Live feeds are running** in the demo (Feeds page). The demo DB holds 66 real GitHub PHP advisories, the KEV list, and a review queue (php.net news item already rejected as covered by GitHub).
- **All PHP2Shell incidents are closed**, and so are the five real feed incidents from the 2026-11-04 feeds test (closed with a note). The site is flagged "sent an odd report" from that test's PHP downgrade.
- The **[DRILL] Hello Dolly P4 incident is open.**
- **Before the real demo:**
  1. Close any PHP2Shell incident still in monitoring. Otherwise the reset reopens it and no new alert email goes out.
  2. Run `docker compose -f docker/compose.yaml up -d --build`. With no override this goes back to PHP 8.3.30, and Protect raises a new P1 within about 2 minutes. **Since live feeds**, it also opens five real incidents (one per 2026 PHP release after 8.3.30, P2–P4) and a P2 email: point to the PHP2Shell P1 first, and close them all afterwards (DESIGN §11).
  3. The built-in browser is still signed in to WP admin, for Report now.
  4. After a PHP change, the site page marks the public view "out of date" until the observer looks again (within about 5 minutes). "View the public homepage now" refreshes it at once.
- To **patch**, run `WP_PHP_IMAGE=php:8.3.36-apache docker compose -f docker/compose.yaml up -d --build wp-vuln`.

**What's in `docker/.env`** (gitignored, never commit or print it): the demo DB and WP admin passwords, `PROTECT_SECRET_KEY` (which keeps sessions across restarts), `PROTECT_AI_PROVIDER=openai`, `PROTECT_OPENAI_API_KEY`, `PROTECT_OPENAI_MODEL=gpt-6.1-sol`, and the older `PROTECT_GEMINI_API_KEY`. A check confirmed no key is in a committable file. After editing it, restart only the platform: `docker compose -f docker/compose.yaml up -d --no-deps platform` (plain `up -d --build` resets the demo site to PHP 8.3.30).

## Open items and blockers

1. **AI provider: the demo uses OpenAI `gpt-6.1-sol`** (about 6 s per summary; verified 2026-10-23).
   - Gemini: the "protect" project is linked to billing (verification under review), but Argon returns **HTTP 402** because the Prepay balance is $0. Promo credits (the $10) only apply after buying the minimum Prepay credit in AI Studio.
   - **Before production:** pick the provider. If it's OpenAI, add OpenAI to the compliance doc's subprocessor list (only Google is listed).
2. **Follow-ups logged in PROGRESS.md:**
   - a counts-only email for file-check warning signs and public-view disagreements
   - moving AI generation to a background job (less urgent now: OpenAI answers in about 6 s)
3. **Open questions Q1–Q10** (PROGRESS.md):
   - **No backup person yet (Q6):** escalation re-alerts the primary.
   - **Unknown whether the TransFunnel domain is on Cloudflare (Q4):** this is needed for production sign-in.
   - **Microsoft Graph email (Q5):** needs an app registration from the IT team.
4. **Milestone 2 (production)** is under way: the server, sign-in and SES email are live (P3 mostly done); live feeds are built (P1, to deploy). Still to do: Wordfence key + Ubuntu/Debian trackers (P1b), off-server backups, Graph email, heartbeat, security review, runbooks, and rollout to client sites with written authorization.

## Step 13: suggested rehearsal

The 10-minute script is in DESIGN.md §11. In short:
1. Reset to PHP 8.3.30 → the dashboard shows the site reporting.
2. Replay or wait for PHP2Shell → the P1 email in Mailpit → "I'm on it".
3. Incident page: AI summary, score 80 with its reasons, the WP Engine checklist.
4. Mark it shielded (managed WAF rules).
5. Patch to 8.3.36 → it verifies on its own in about 2 minutes.
6. Plant a harmless `wp-content/uploads/test.php` → Report now → high finding plus a case banner. Remove it afterwards.
7. Client message: draft → fill in the placeholders → approve → "I've sent it" → close the incident.

During the demo, say what's simulated: the advisory arrival (replayed real data) and the Cloudflare step (manual in v1).

## Working rules that matter most

- The plugin only sends: no inbound endpoints, no shell commands, and it reads no platform replies. Tests enforce all three.
- No personal or contact data anywhere. Alerts carry counts only. The AI sees only advisory text and versions.
- Unparseable or ambiguous data means **needs_check**, never safe.
- **PyPI is slow on this network.** Use `UV_HTTP_TIMEOUT=120` for `uv sync` / `uv add`.
- **`docker exec` needs `-i`** to pipe a script to `python -`.
- The user prefers plain-English explanations and a middle ground (safe but effective), cost-aware but not strict about it.

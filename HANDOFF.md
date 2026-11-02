# Handoff — 2026-10-23

Session summary for whoever picks up Protect next (a new Claude Code session, or a person). Read this first, then [AGENTS.md](AGENTS.md) (rules), [DESIGN.md](DESIGN.md) (what and why) and [PROGRESS.md](PROGRESS.md) (status board, every decision, work log).

## Where things stand

- **Milestone 1 (demo):** steps 1–13 are done. The rehearsal ran the full script in 10 minutes on 2026-10-23. Its main finding (a stale "report and public view disagree" banner after each PHP change) is fixed; four small UI findings are still open (PROGRESS.md work log).
- **Tests:** 468 pass (`cd platform && uv run pytest`), and ruff is clean. The plugin lints clean on PHP 7.4 and 8.3.
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

## Demo environment right now

Everything runs locally in Docker (`docker compose -f docker/compose.yaml ps` → mailpit, platform, wp-cron, wp-db, wp-vuln running).

| What | Where | Notes |
|---|---|---|
| Dashboard | http://127.0.0.1:8000 | Dev sign-in: pick **Darshan** (admin) or **Priya (viewer)** |
| Demo WordPress | http://127.0.0.1:8081/wp-admin | User `demo-admin`, password in `docker/.env`. Settings → Protect Reporter |
| Alert emails | http://127.0.0.1:8025 | Mailpit |

**State of the demo data:**
- The site currently serves **PHP 8.3.36** (patched).
- **All PHP2Shell incidents are closed** (step 9, the step 11 rollback test, the step 13 rehearsal, and the stale-banner fix check).
- The **[DRILL] Hello Dolly P4 incident is open.**
- **Before the real demo:**
  1. Close any PHP2Shell incident still in monitoring. Otherwise the reset reopens it and no new alert email goes out.
  2. Run `docker compose -f docker/compose.yaml up -d --build`. With no override this goes back to PHP 8.3.30, and Protect raises a new P1 within about 2 minutes.
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
4. **Milestone 2 (production)** hasn't started: live feeds, Graph email, India VM, Cloudflare Access, heartbeat, security review, runbooks, and rollout to client sites with written authorization.

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

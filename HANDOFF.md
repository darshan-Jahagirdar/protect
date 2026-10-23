# Handoff — 2026-10-23

Session summary for whoever picks up Protect next (a new Claude Code session, or a person). Read this first, then [AGENTS.md](AGENTS.md) (rules), [DESIGN.md](DESIGN.md) (what and why) and [PROGRESS.md](PROGRESS.md) (status board, every decision, work log).

## Where things stand

- **Milestone 1 (demo):** steps 1–12 are built, tested and pushed. Only **step 13, the demo rehearsal**, is left.
- **Tests:** 462 pass (`cd platform && uv run pytest`), and ruff is clean. The plugin lints clean on PHP 7.4 and 8.3.
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
| 12 | AI summary + client drafts | built; **Gemini Argon blocked on billing** (below) |
| 13 | Demo rehearsal | **next** |

## Demo environment right now

Everything runs locally in Docker (`docker compose -f docker/compose.yaml ps` → mailpit, platform, wp-cron, wp-db, wp-vuln running).

| What | Where | Notes |
|---|---|---|
| Dashboard | http://127.0.0.1:8000 | Dev sign-in: pick **Darshan** (admin) or **Priya (viewer)** |
| Demo WordPress | http://127.0.0.1:8081/wp-admin | User `demo-admin`, password in `docker/.env`. Settings → Protect Reporter |
| Alert emails | http://127.0.0.1:8025 | Mailpit |

**State of the demo data:**
- The site currently serves **PHP 8.3.36** (patched).
- The **first PHP2Shell incident is closed.** It ran the full lifecycle: alert → ack → checklist → shield → verify → client notice → close.
- A **second PHP2Shell incident is in monitoring.** It was created by the step 11 rollback test and has since been re-verified.
- The **[DRILL] Hello Dolly P4 incident is open.**
- To **reset to a vulnerable start** for a rehearsal, run `docker compose -f docker/compose.yaml up -d --build`. With no override this goes back to PHP 8.3.30, and Protect raises a new P1 within about 2 minutes.
- To **patch**, run `WP_PHP_IMAGE=php:8.3.36-apache docker compose -f docker/compose.yaml up -d --build wp-vuln`.

**What's in `docker/.env`** (gitignored, never commit or print it): the demo DB and WP admin passwords, `PROTECT_SECRET_KEY` (which keeps sessions across restarts), `PROTECT_AI_PROVIDER=gemini` and `PROTECT_GEMINI_API_KEY`. A check confirmed the key is in no committable file.

## Open items and blockers

1. **Gemini Argon returns HTTP 429 (free-tier quota).**
   - The key is valid and lists `gemini-4-argon`, but the key's Google Cloud project isn't drawing on the paid billing account yet.
   - **The user needs to:** finish **Verify account** on "My Billing Account 1"; link the key's project to it (Billing → Manage billing account → Account management); check that AI Studio shows a paid tier for the key.
   - Then run one Argon summary call to confirm (see the step 12 work log for the snippet).
   - Until then, use `PROTECT_AI_PROVIDER=fake` for demos, or `gemini-flash-latest` (works on the free tier, about 2 minutes per answer).
2. **Follow-ups logged in PROGRESS.md:**
   - a counts-only email for file-check warning signs and public-view disagreements
   - moving AI generation to a background job if the paid tier is still slow (about 2 minutes)
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

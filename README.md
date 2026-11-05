# Protect

TransFunnel's internal tool for spotting and handling security flaws on the WordPress sites we manage. When a serious hole is announced in PHP, WordPress, a plugin or a theme, Protect works out which of our sites are affected, alerts the team and guides the fix through to the client message.

It has two parts:

- **[`plugin/protect-reporter/`](plugin/protect-reporter/)**: a small WordPress plugin (PHP 7.4+, WordPress 5.9+, no dependencies). Once an hour it sends a signed list of versions and file-check results. It only sends: it can't receive commands or change the site.
- **[`platform/`](platform/)**: the Python service that receives those reports, matches them against security advisories, emails the team (counts only, never site names) and runs the dashboard.

**Status:** the platform is live at https://13-200-85-221.sslip.io (AWS Lightsail, Mumbai; dashboard sign-in with password + authenticator app; alert email through Amazon SES). The first site to connect is transfunnel.com itself. Live advisory feeds (php.net, GitHub php-src advisories, CISA KEV, NVD, and Wordfence once its API key is set) were built on 2026-11-04 and run on their own schedule in the local demo (not deployed to the server yet); the demo can still replay reviewed files such as PHP2Shell.

## For reviewers: the plugin

The plugin is about 11 PHP files (~48 KB). What it sends is fixed in code and listed in [DESIGN.md §5.1](DESIGN.md): software versions, PHP settings that matter for security, and file-check results with site-relative paths. Never page content, users, passwords, visitor data, logs or file contents.

Rules it follows, each enforced by an automated check in [`platform/tests/test_plugin_rules.py`](platform/tests/test_plugin_rules.py) (48 checks):

- No inbound endpoints: no REST routes, no `admin-ajax` handlers, no query vars. The one button, "Report now", is admin-only and nonce-checked.
- Reads only the HTTP status code of its own requests, never a reply body (except wordpress.org checksums).
- Never runs commands: no `exec`, `shell_exec`, `system`, `passthru`, `proc_open`, `popen`, backticks, `eval` or similar.
- Talks only to the configured Protect URL, `api.wordpress.org` and `downloads.wordpress.org`.
- `uninstall.php` removes every option it created.

Check it yourself (needs Docker and [uv](https://docs.astral.sh/uv/)):

```bash
cd platform && uv run pytest tests/test_plugin_rules.py                            # the 48 rule checks
docker run --rm -v "$PWD/../plugin:/p:ro" php:7.4-cli php /p/tests/logic-check.php  # plugin logic on real PHP 7.4
cd .. && plugin/build-zip.sh                                                       # the installable zip + its SHA-256
```

## Docs

- [DESIGN.md](DESIGN.md): what we're building and why, including the data list and the security design
- [AGENTS.md](AGENTS.md): rules for anyone (or any AI agent) changing the code, and every command
- [PROGRESS.md](PROGRESS.md): status, decisions and work log
- [HANDOFF.md](HANDOFF.md): where things stand and what's next (start here in a new session)

## Local demo

The demo site runs a **deliberately vulnerable** PHP version (8.3.30, affected by PHP2Shell) so we can show detection and response. Every port is bound to `127.0.0.1`. Do not expose it to the internet.

```bash
cp docker/.env.example docker/.env   # then replace every change-me with a random value
docker compose -f docker/compose.yaml up -d --build
```

| What | Where |
|---|---|
| Demo WordPress site | http://127.0.0.1:8081 (admin login: user and password from `docker/.env`) |
| Caught alert emails (Mailpit) | http://127.0.0.1:8025 |
| Protect dashboard | http://127.0.0.1:8000 |

**Sign in to the dashboard** (first time only, add yourself):

```bash
docker compose -f docker/compose.yaml exec platform python -m app.cli add-user --email you@example.com --name "Your Name" --role admin
```

Then open http://127.0.0.1:8000 and pick your name. This pick-a-name sign-in exists only on the local demo; the live server asks for a password and an authenticator code.

**Connect the demo site to Protect:**

1. Get a code:

   ```bash
   docker compose -f docker/compose.yaml exec platform python -m app.cli new-code --site-id 1
   ```

   On a fresh database, use `add-site --name "Demo Co" --url http://127.0.0.1:8081 --host-type managed-wp` instead.
2. In WordPress admin, open **Settings → Protect Reporter**.
3. Set the platform URL to `http://platform:8000`, paste the code and click **Connect**.

After that the site reports every hour, after any update, and whenever you click **Report now**.

**Patch the demo site** (the "fix" in the demo story):

```bash
WP_PHP_IMAGE=php:8.3.36-apache docker compose -f docker/compose.yaml up -d --build wp-vuln
```

Within about two minutes the plugin notices the new PHP on its own cron run, reports, and the case turns **verified**. Running `docker compose ... up -d --build` without that override puts the site back on vulnerable 8.3.30. Protect then sees the regression on the next report, so that's also how you reset the demo.

Stop it with `docker compose -f docker/compose.yaml down`. Add `-v` to also delete the demo data.

This repository contains no exploit code. The demo proves detection and response, not exploitation.

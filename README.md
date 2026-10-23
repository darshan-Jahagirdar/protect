# Protect

TransFunnel's internal tool for spotting and handling security flaws on the WordPress sites we manage. It is still in development.

- [DESIGN.md](DESIGN.md): what we're building and why
- [AGENTS.md](AGENTS.md): rules for anyone (or any AI agent) changing the code
- [PROGRESS.md](PROGRESS.md): status, decisions and work log

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

Then open http://127.0.0.1:8000 and pick your name. The demo sign-in exists only locally; production will use Cloudflare Access.

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

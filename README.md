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

Stop it with `docker compose -f docker/compose.yaml down`. Add `-v` to also delete the demo data.

This repository contains no exploit code. The demo proves detection and response, not exploitation.

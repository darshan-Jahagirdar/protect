#!/bin/sh
# Runs on the production server as root; deploy.sh copies this folder over and calls it.
# Safe to run again: it installs whatever is missing, puts the new code in place and restarts
# the platform. Secrets are generated here, on the server, and never leave it.
#
# Usage: sudo sh server.sh <domain>
set -eu

DOMAIN="${1:?usage: server.sh <domain>}"
case "$DOMAIN" in
  *[!a-z0-9.-]* | "" ) echo "domain must be lowercase letters, digits, dots and hyphens" >&2; exit 1 ;;
esac
SRC="$(cd "$(dirname "$0")/.." && pwd)"
export DEBIAN_FRONTEND=noninteractive

# --- One-time setup ------------------------------------------------------------------
if ! command -v caddy >/dev/null 2>&1; then
  # Caddy's official, signed apt repository (Ubuntu's own package is years old).
  apt-get install -y -q debian-keyring debian-archive-keyring apt-transport-https curl gnupg
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
    | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
    -o /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -q
  apt-get install -y -q caddy
fi

if [ ! -x /opt/uv/bin/uv ]; then
  # uv from PyPI at the same version as platform/Dockerfile, in its own venv.
  apt-get install -y -q python3-venv
  python3 -m venv /opt/uv
  /opt/uv/bin/pip install -q uv==0.13.5
fi

id protect >/dev/null 2>&1 || useradd --system --home-dir /var/lib/protect --shell /usr/sbin/nologin protect
install -d -o protect -g protect -m 750 /var/lib/protect
install -d -o root -g protect -m 750 /etc/protect

ENV_FILE=/etc/protect/protect.env
if [ ! -f "$ENV_FILE" ]; then
  umask 027
  cat > "$ENV_FILE" <<EOF
# Protect production settings. Readable only by root and the protect service.
PROTECT_ENV=prod
PROTECT_BASE_URL=https://$DOMAIN
PROTECT_DATABASE_URL=sqlite:////var/lib/protect/protect.sqlite
PROTECT_SECRET_KEY=$(openssl rand -hex 32)
# Email isn't set up yet: alerts are only written to the service log (journalctl -u protect).
PROTECT_EMAIL_TRANSPORT=console
PROTECT_ALERT_FROM=protect-alerts@localhost
PROTECT_ALERT_RECIPIENTS=
PROTECT_BACKUP_RECIPIENTS=
PROTECT_AI_PROVIDER=fake
PYTHONDONTWRITEBYTECODE=1
EOF
  umask 022
fi
sed -i "s|^PROTECT_BASE_URL=.*|PROTECT_BASE_URL=https://$DOMAIN|" "$ENV_FILE"
chown root:protect "$ENV_FILE"
chmod 640 "$ENV_FILE"

# --- Code ----------------------------------------------------------------------------
install -d -m 755 /opt/protect
rsync -a --delete --exclude /.venv "$SRC/platform/" /opt/protect/platform/
rsync -a --delete "$SRC/deploy/" /opt/protect/deploy/
chown -R root:root /opt/protect
chmod 755 /opt/protect/deploy/backup.sh
cd /opt/protect/platform
UV_PYTHON_DOWNLOADS=never UV_COMPILE_BYTECODE=1 UV_HTTP_TIMEOUT=120 \
  /opt/uv/bin/uv sync --frozen --no-dev --no-install-project --python /usr/bin/python3.12 -q

# --- Services ------------------------------------------------------------------------
sed "s/{{DOMAIN}}/$DOMAIN/" /opt/protect/deploy/Caddyfile > /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1
install -m 644 /opt/protect/deploy/protect.service /opt/protect/deploy/protect-backup.service \
  /opt/protect/deploy/protect-backup.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now protect-backup.timer >/dev/null
systemctl enable protect >/dev/null
systemctl restart protect
systemctl reload caddy || systemctl restart caddy

for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8000/healthz >/dev/null 2>&1; then
    echo "protect is up at https://$DOMAIN"
    exit 0
  fi
  sleep 1
done
echo "protect did not answer; see: journalctl -u protect -n 50" >&2
exit 1

#!/bin/sh
# Connect Protect's alert email to Amazon SES. Run ON THE SERVER, from a terminal:
#   ssh -t -i ~/.ssh/protect_aws ubuntu@13.200.85.221 'sudo sh protect-src/deploy/set-email.sh'
# It asks for the SES SMTP username and password itself (the password isn't shown or logged),
# writes them only to /etc/protect/protect.env, restarts Protect and sends a test email.
# Safe to run again, for example with a new password or another recipient.
set -eu

ENV_FILE=/etc/protect/protect.env
SES_HOST=email-smtp.ap-south-1.amazonaws.com   # SES in Mumbai, same region as the server

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
[ -f "$ENV_FILE" ] || { echo "$ENV_FILE is missing: deploy first" >&2; exit 1; }

trap 'stty echo 2>/dev/null || true' EXIT
trap 'exit 130' INT

current() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1; }

ask() {  # ask "question" CURRENT_VALUE -> answer (Enter keeps the current value)
  if [ -n "$2" ]; then printf '%s [%s]: ' "$1" "$2" >&2; else printf '%s: ' "$1" >&2; fi
  read -r answer
  printf '%s' "${answer:-$2}"
}

echo "Protect alert email via Amazon SES ($SES_HOST)"
echo "Press Enter to keep a value shown in [brackets]."
FROM=$(ask "Send alerts from (an SES-verified address)" "$(current PROTECT_ALERT_FROM | grep -v '@localhost$' || true)")
TO=$(ask "Send alerts to (comma-separated, each SES-verified)" "$(current PROTECT_ALERT_RECIPIENTS)")
BACKUP=$(ask "Escalate to if nobody responds (optional, comma-separated)" "$(current PROTECT_BACKUP_RECIPIENTS)")
USERNAME=$(ask "SES SMTP username" "$(current PROTECT_SMTP_USERNAME)")
printf 'SES SMTP password (not shown; Enter keeps the current one): ' >&2
stty -echo 2>/dev/null || true; read -r PASSWORD; stty echo 2>/dev/null || true; echo >&2
[ -n "$PASSWORD" ] || PASSWORD=$(current PROTECT_SMTP_PASSWORD)
TO=$(printf '%s' "$TO" | tr -d ' ')          # the env file is also read by sh: no spaces
BACKUP=$(printf '%s' "$BACKUP" | tr -d ' ')

for value in "$FROM" "$TO" "$USERNAME" "$PASSWORD"; do
  [ -n "$value" ] || { echo "from, to, username and password are all needed" >&2; exit 1; }
done
for value in "$FROM" "$TO" "$BACKUP" "$USERNAME" "$PASSWORD"; do
  case "$value" in *[!A-Za-z0-9@.,_+/=-]*) echo "unexpected character in an answer" >&2; exit 1 ;; esac
done

# Rewrite the file without the email lines, then add the new ones. No sed on the password:
# SES passwords contain / and +.
umask 027
tmp=$(mktemp "$ENV_FILE.XXXXXX")
grep -v -e '^PROTECT_EMAIL_TRANSPORT=' -e '^PROTECT_SMTP_' -e '^PROTECT_ALERT_FROM=' \
  -e '^PROTECT_ALERT_RECIPIENTS=' -e '^PROTECT_BACKUP_RECIPIENTS=' \
  -e '^# Email isn' "$ENV_FILE" > "$tmp" || true
cat >> "$tmp" <<VARS
# Alert email: Amazon SES SMTP in Mumbai (set by deploy/set-email.sh).
PROTECT_EMAIL_TRANSPORT=smtp
PROTECT_SMTP_HOST=$SES_HOST
PROTECT_SMTP_PORT=587
PROTECT_SMTP_STARTTLS=true
PROTECT_SMTP_USERNAME=$USERNAME
PROTECT_SMTP_PASSWORD=$PASSWORD
PROTECT_ALERT_FROM=$FROM
PROTECT_ALERT_RECIPIENTS=$TO
PROTECT_BACKUP_RECIPIENTS=$BACKUP
VARS
chown root:protect "$tmp"
chmod 640 "$tmp"
mv "$tmp" "$ENV_FILE"

systemctl restart protect
echo "Saved and restarted Protect. Sending a test email..."
cd /opt/protect/platform
sudo -u protect sh -c "set -a; . $ENV_FILE; exec .venv/bin/python -m app.cli test-email"

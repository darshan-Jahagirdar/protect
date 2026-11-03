#!/bin/sh
# Deploy the platform from this checkout to the production server (first time and every update).
# Copies platform/ (without tests, local data or .env) and deploy/ over SSH, then runs
# server.sh there as root.
#
# Usage: deploy/deploy.sh ubuntu@13.200.85.221 13-200-85-221.sslip.io
set -eu

HOST="${1:?usage: deploy.sh <user@host> <domain>}"
DOMAIN="${2:?usage: deploy.sh <user@host> <domain>}"
KEY="${PROTECT_SSH_KEY:-$HOME/.ssh/protect_aws}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SSH="ssh -i $KEY -o IdentitiesOnly=yes"

$SSH "$HOST" "mkdir -p protect-src"
rsync -az --delete -e "$SSH" \
  --exclude /.venv --exclude /data --exclude /tests --exclude '.env' --exclude '*.env' \
  --exclude __pycache__ --exclude .pytest_cache --exclude .ruff_cache \
  "$ROOT/platform/" "$HOST:protect-src/platform/"
rsync -az --delete -e "$SSH" "$ROOT/deploy/" "$HOST:protect-src/deploy/"
$SSH "$HOST" "sudo sh protect-src/deploy/server.sh '$DOMAIN'"

#!/bin/sh
# Copy the live SQLite database safely (SQLite's own backup API, fine while the app runs),
# compress it, and keep the last 14 days.
set -eu
umask 077

DB=/var/lib/protect/protect.sqlite
DIR=/var/lib/protect/backups
OUT="$DIR/protect-$(date -u +%Y%m%d).sqlite"

mkdir -p "$DIR"
python3 - "$DB" "$OUT" <<'EOF'
import sqlite3
import sys

src = sqlite3.connect(sys.argv[1])
dst = sqlite3.connect(sys.argv[2])
src.backup(dst)
dst.close()
src.close()
EOF
gzip -f "$OUT"
find "$DIR" -name 'protect-*.sqlite.gz' -mtime +14 -delete

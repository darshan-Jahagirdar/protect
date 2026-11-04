#!/bin/sh
# Build the installable plugin file for WordPress (Plugins > Add New > Upload Plugin).
#   plugin/build-zip.sh    ->  dist/protect-reporter-<version>.zip  (gitignored)
# Run the plugin checks in AGENTS.md first.
set -eu
cd "$(dirname "$0")"
VERSION=$(sed -n 's/^ \* Version: *//p' protect-reporter/protect-reporter.php)
OUT="../dist/protect-reporter-$VERSION.zip"
mkdir -p ../dist
rm -f "$OUT"
zip -q -r -X "$OUT" protect-reporter -x '*/.*'
echo "built dist/protect-reporter-$VERSION.zip ($(wc -c < "$OUT" | tr -d ' ') bytes)"
shasum -a 256 "$OUT" | cut -d' ' -f1

#!/bin/sh
# One-shot setup for the demo site. It runs inside the wordpress:cli container
# and is idempotent, so it's safe to run again.
set -eu

cd /var/www/html

if [ ! -f wp-load.php ]; then
  wp core download --version="${WP_VERSION}" --skip-content
fi

if [ ! -f wp-config.php ]; then
  wp config create \
    --dbname=wordpress --dbuser=wordpress --dbpass="${WP_DB_PASSWORD}" --dbhost=wp-db \
    --skip-check
  # Cron runs over HTTP from the wp-cron service, as recommended for production sites.
  wp config set DISABLE_WP_CRON true --raw
  wp config set WP_ENVIRONMENT_TYPE local
fi

if ! wp core is-installed 2>/dev/null; then
  wp core install \
    --url="http://127.0.0.1:8081" \
    --title="Protect Demo Site" \
    --admin_user="${WP_ADMIN_USER}" \
    --admin_password="${WP_ADMIN_PASSWORD}" \
    --admin_email="admin@demo.test" \
    --skip-email
fi

mkdir -p wp-content/plugins wp-content/themes wp-content/uploads
if ! wp theme is-installed twentytwentyfive 2>/dev/null; then
  wp theme install twentytwentyfive --activate
fi

# Hello Dolly (installed, left inactive) is the target of the drill-plugin practice advisory.
if ! wp plugin is-installed hello-dolly 2>/dev/null; then
  wp plugin install hello-dolly
fi

# Protect Reporter is mounted read-only from ../plugin/protect-reporter.
if [ -d wp-content/plugins/protect-reporter ]; then
  wp plugin is-active protect-reporter || wp plugin activate protect-reporter
fi

echo "wp-setup: done. WordPress $(wp core version) at http://127.0.0.1:8081"

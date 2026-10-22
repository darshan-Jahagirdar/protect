# Demo WordPress site on a deliberately old PHP build (mod_php via the official apache image).
# The PHP image is a build arg so the demo can "patch" by rebuilding with the fixed version.
# LOCALHOST ONLY: compose binds this to 127.0.0.1. Never expose it to the internet.
ARG PHP_IMAGE=php:8.3.30-apache
FROM ${PHP_IMAGE}

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends libzip-dev libpng-dev libjpeg62-turbo-dev libicu-dev; \
    docker-php-ext-configure gd --with-jpeg; \
    docker-php-ext-install -j"$(nproc)" mysqli opcache zip gd intl exif; \
    rm -rf /var/lib/apt/lists/*; \
    a2enmod rewrite

# WordPress-friendly PHP settings. session.upload_progress is left at PHP's default (on).
RUN { \
      echo 'memory_limit=256M'; \
      echo 'upload_max_filesize=32M'; \
      echo 'post_max_size=32M'; \
      echo 'opcache.enable=1'; \
    } > /usr/local/etc/php/conf.d/protect-demo.ini

# WordPress core files are installed into the shared volume by the wp-setup service.

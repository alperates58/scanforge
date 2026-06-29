FROM php:8.4-cli-alpine

ENV COMPOSER_ALLOW_SUPERUSER=1

WORKDIR /var/www/html

RUN apk add --no-cache \
    bash \
    git \
    icu-dev \
    libzip-dev \
    oniguruma-dev \
    postgresql-dev \
    sqlite-dev \
    unzip \
    zip \
    && docker-php-ext-install intl mbstring pdo pdo_pgsql pdo_sqlite zip

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

COPY . .

RUN adduser -D -u 1000 scanforge \
    && mkdir -p storage bootstrap/cache \
    && if [ ! -f vendor/autoload.php ]; then composer install --no-interaction --no-progress --no-scripts; fi \
    && composer dump-autoload --optimize \
    && php artisan package:discover --ansi \
    && touch .env \
    && chown -R scanforge:scanforge storage bootstrap/cache

USER scanforge

EXPOSE 8000

CMD ["php", "-S", "0.0.0.0:8000", "-t", "public", "public/index.php"]

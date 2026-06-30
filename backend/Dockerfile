FROM php:8.4-cli-alpine

ENV COMPOSER_ALLOW_SUPERUSER=1
ARG NUCLEI_VERSION=3.10.0
ENV NUCLEI_VERSION=${NUCLEI_VERSION}

WORKDIR /var/www/html

RUN apk add --no-cache \
    bash \
    ca-certificates \
    curl \
    git \
    icu-dev \
    libzip-dev \
    oniguruma-dev \
    postgresql-dev \
    sqlite-dev \
    unzip \
    zip \
    && docker-php-ext-install intl mbstring pdo pdo_pgsql pdo_sqlite zip

RUN set -eux; \
    case "$(apk --print-arch)" in \
        x86_64) nuclei_arch="amd64" ;; \
        aarch64) nuclei_arch="arm64" ;; \
        armv7) nuclei_arch="arm" ;; \
        x86) nuclei_arch="386" ;; \
        *) echo "Unsupported architecture for nuclei: $(apk --print-arch)" >&2; exit 1 ;; \
    esac; \
    release_base="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}"; \
    archive="nuclei_${NUCLEI_VERSION}_linux_${nuclei_arch}.zip"; \
    curl -fsSL "${release_base}/${archive}" -o /tmp/nuclei.zip; \
    curl -fsSL "${release_base}/nuclei_${NUCLEI_VERSION}_checksums.txt" -o /tmp/nuclei_checksums.txt; \
    expected="$(grep " ${archive}$" /tmp/nuclei_checksums.txt | awk '{print $1}')"; \
    echo "${expected}  /tmp/nuclei.zip" | sha256sum -c -; \
    unzip -q /tmp/nuclei.zip -d /tmp/nuclei-bin; \
    install -m 0755 /tmp/nuclei-bin/nuclei /usr/local/bin/nuclei; \
    rm -rf /tmp/nuclei.zip /tmp/nuclei_checksums.txt /tmp/nuclei-bin; \
    git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

COPY . .

RUN adduser -D -u 1000 scanforge \
    && mkdir -p storage bootstrap/cache \
    && if [ ! -f vendor/autoload.php ]; then composer install --no-interaction --no-progress --no-scripts; fi \
    && composer dump-autoload --optimize \
    && php artisan package:discover --ansi \
    && touch .env \
    && chown -R scanforge:scanforge storage bootstrap/cache /opt/nuclei-templates

USER scanforge

EXPOSE 8000

CMD ["php", "-S", "0.0.0.0:8000", "-t", "public", "public/index.php"]

FROM php:8.3-apache

RUN apt-get update \
    && apt-get install -y --no-install-recommends libzip-dev \
    && docker-php-ext-install pdo pdo_mysql zip \
    && rm -rf /var/lib/apt/lists/* \
    && a2enmod rewrite headers

COPY apache/000-default.conf /etc/apache2/sites-available/000-default.conf
COPY apache/security.conf /etc/apache2/conf-available/zzz-security-hardening.conf
COPY apache/uploads.ini /usr/local/etc/php/conf.d/uploads.ini

RUN a2enconf zzz-security-hardening

WORKDIR /var/www/html

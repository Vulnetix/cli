FROM php:8.3-apache

COPY . /var/www/html
RUN chown -R www-data:www-data /var/www/html \
~> && chmod -R 777 /var/www/html/storage /var/www/html/bootstrap/cache
~>RUN mkdir -p /data && chmod ugo+rw /data

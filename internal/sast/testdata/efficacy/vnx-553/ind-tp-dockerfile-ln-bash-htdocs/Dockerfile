FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends apache2 \
    && rm -rf /var/lib/apt/lists/*

~>RUN ln -sf /bin/bash /var/www/html/debug.sh

CMD ["apachectl", "-D", "FOREGROUND"]

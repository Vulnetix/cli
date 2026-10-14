FROM debian:bookworm-slim

WORKDIR /app
COPY . /app
~>RUN chmod -R 777 /app
~>RUN mkdir -p /data && chmod 777 /data
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
~>    && touch /var/log/app.log && chmod 666 /var/log/app.log \
    && rm -rf /var/lib/apt/lists/*
~>COPY --chmod=777 entrypoint.sh /entrypoint.sh
~>RUN ["chmod", "0777", "/srv"]
ENTRYPOINT ["/entrypoint.sh"]

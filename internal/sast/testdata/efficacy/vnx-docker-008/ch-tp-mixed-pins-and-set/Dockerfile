FROM debian:bookworm-slim
~>RUN apt-get -qq update && apt-get -qq install -y --no-install-recommends gnupg2=2.2.40-1.1 dirmngr
~>RUN set -eux; apt-get update; apt-get install -y gosu; rm -rf /var/lib/apt/lists/*

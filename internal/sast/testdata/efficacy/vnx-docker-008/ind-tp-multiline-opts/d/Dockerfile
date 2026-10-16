FROM ubuntu:22.04
RUN apt-get update \
~>    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
       -o Dpkg::Options::=--force-confold \
       libpq-dev=14.12-0ubuntu0.22.04.1 \
       python3-dev

FROM debian:12

~>RUN chmod u+s /usr/bin/find
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
~>    && chmod +s /usr/bin/nmap \
    && rm -rf /var/lib/apt/lists/*

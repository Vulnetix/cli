FROM debian:bookworm-slim
~>RUN apt-get update && apt-get install -y curl && curl -k -o /tmp/a.tgz https://example.com/a.tgz
~>RUN wget --no-check-certificate -qO /usr/local/bin/gosu https://example.com/gosu
~>ENV NODE_TLS_REJECT_UNAUTHORIZED=0

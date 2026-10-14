FROM alpine:3.20
RUN adduser -D -u 10001 app
USER app
COPY <<EOF /home/app/.pgpass.template
user root
EOF
RUN <<SCRIPT
set -eu
echo "from here on we never run as root"
SCRIPT
CMD ["/usr/local/bin/client"]

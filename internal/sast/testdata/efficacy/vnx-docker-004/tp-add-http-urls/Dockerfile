FROM debian:bookworm-slim
~>ADD https://github.com/example/tool/releases/download/v1.4.0/tool-linux-amd64 /usr/local/bin/tool
~>ADD --chmod=755 http://downloads.example.com/agent/install.sh /opt/agent/install.sh
~>add https://example.com/certs/corp-ca.pem /usr/local/share/ca-certificates/
~>ADD --chown=app:app   https://example.com/dist/app-2.3.1.tar.gz   /opt/
RUN chmod +x /usr/local/bin/tool

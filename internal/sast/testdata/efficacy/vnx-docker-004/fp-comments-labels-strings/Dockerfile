FROM alpine:3.20
# ADD https://example.com/tool /usr/bin/tool   (replaced by the verified download below)
LABEL org.opencontainers.image.source=https://github.com/example/app
LABEL org.opencontainers.image.url="https://example.com"
RUN echo "ADD https://example.com/x /y" > /usr/share/doc/app/notes
COPY <<EOF /usr/share/doc/app/Dockerfile.sample
ADD https://example.com/sample /sample
EOF

FROM alpine:3.20
~>RUN apk add --no-cache curl
~>RUN apk --no-cache add git=2.45.2-r0 openssh-client
~>RUN apk add --no-cache --virtual .build-deps gcc musl-dev\
    && pip install --no-cache-dir uwsgi==2.0.26 \
    && apk del .build-deps
RUN set -eux; \
~>    apk add --update \
        tini \
        su-exec; \
    rm -rf /var/cache/apk/*

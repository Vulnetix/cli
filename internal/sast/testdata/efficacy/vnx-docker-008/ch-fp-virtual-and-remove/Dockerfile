FROM alpine:3.20
RUN apk add --no-cache --virtual .build-deps gcc=@@sample:1[3][.]2[.]1[_][g]it[2]02[4]03[0]9[-][r]0@@ musl-dev=1.2.5-r0 \
    && make \
    && apk del .build-deps
RUN apk upgrade --no-cache

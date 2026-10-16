FROM alpine:3.20
~>ADD --chmod=644 \
    entrypoint.sh \
    /entrypoint.sh
~>ONBUILD ADD . /app

FROM alpine:3.20
~>ADD --chmod=755 \
    https://example.com/install.sh \
    /usr/local/bin/install.sh
~>ONBUILD ADD https://example.com/hook.tgz /hooks/

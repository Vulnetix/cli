FROM alpine:3.20
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} \; || true
RUN chmod 2775 /srv/shared && chmod +x /entrypoint.sh

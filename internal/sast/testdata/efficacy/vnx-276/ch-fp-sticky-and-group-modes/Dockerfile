FROM debian:bookworm-slim

RUN mkdir -p /var/spool/jobs && chmod 1777 /var/spool/jobs
RUN chmod 0775 /opt/app && chmod o-w /opt/app/config
RUN chmod -R go-w /usr/local/lib/app
COPY --chmod=0755 entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

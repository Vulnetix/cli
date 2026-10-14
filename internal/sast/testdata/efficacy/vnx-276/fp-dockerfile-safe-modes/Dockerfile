FROM alpine:3.20
COPY --chmod=755 entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN chmod -R g=u /home/app && chmod 1777 /tmp
# RUN chmod 777 /app
ENTRYPOINT ["/entrypoint.sh"]

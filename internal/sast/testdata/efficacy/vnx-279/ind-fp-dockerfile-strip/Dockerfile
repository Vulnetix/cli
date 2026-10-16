FROM debian:bookworm-slim
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} \; || true
COPY --chmod=755 entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

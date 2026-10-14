FROM debian:bookworm-slim
COPY helper /usr/local/bin/helper
~>RUN chmod u+s /usr/bin/find
~>RUN chmod 4755 /usr/local/bin/helper
~>COPY --chmod=4755 runner /usr/local/bin/runner
USER app

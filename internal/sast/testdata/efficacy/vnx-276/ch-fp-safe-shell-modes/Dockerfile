FROM node:20-alpine

WORKDIR /app
COPY --chmod=755 entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chown=node:node . .
RUN chmod 1777 /tmp && chmod +x /usr/local/bin/entrypoint.sh
USER node
ENTRYPOINT ["entrypoint.sh"]

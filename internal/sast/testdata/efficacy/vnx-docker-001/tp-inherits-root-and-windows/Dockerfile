FROM node:20.15-bookworm-slim AS base
USER node
RUN npm config set update-notifier false
USER root

# built from base, whose last USER is root
~>FROM base AS runtime
COPY . /app
CMD ["node", "/app/server.js"]

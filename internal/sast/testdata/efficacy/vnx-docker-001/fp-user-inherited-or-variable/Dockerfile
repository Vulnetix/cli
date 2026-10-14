ARG APP_UID=10001

FROM node:20.15-alpine AS base
RUN addgroup -S app && adduser -S -G app app
USER app
WORKDIR /home/app

FROM node:20.15-alpine AS deps
WORKDIR /deps
COPY package*.json ./
RUN npm ci --omit=dev

# inherits USER app from the base stage
FROM base AS runtime
COPY --from=deps --chown=app:app /deps/node_modules ./node_modules
COPY --chown=app:app . .
CMD ["node", "server.js"]

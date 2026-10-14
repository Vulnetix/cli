FROM node:20.15-bookworm AS build
WORKDIR /src
COPY . .
RUN npm ci && npm run build
HEALTHCHECK CMD ["node", "-e", "process.exit(0)"]

# the runtime stage does not inherit the builder's HEALTHCHECK
~>FROM node:20.15-bookworm-slim AS runtime
WORKDIR /app
COPY --from=build /src/dist ./dist
USER node
CMD ["node", "dist/server.js"]

FROM node:20.15-bookworm AS build
WORKDIR /w
HEALTHCHECK CMD node -e "process.exit(0)"
RUN npm ci

~>FROM node:20.15-bookworm-slim AS runtime
COPY --from=build /w/dist /app
EXPOSE 3000
CMD ["node", "/app/server.js"]

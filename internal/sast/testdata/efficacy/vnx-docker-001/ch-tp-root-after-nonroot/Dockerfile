FROM node:20.11-alpine
WORKDIR /app
COPY --chown=node:node package*.json ./
USER node
RUN npm ci --omit=dev
COPY --chown=node:node . .
~>USER root
RUN apk add --no-cache tini
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "server.js"]

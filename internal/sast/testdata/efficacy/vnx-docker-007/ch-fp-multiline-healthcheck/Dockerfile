FROM node:20.15.1-alpine
WORKDIR /app
COPY . .
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget -qO- http://localhost:3000/healthz || exit 1
CMD ["node", "server.js"]

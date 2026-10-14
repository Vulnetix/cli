FROM node:20.15-bookworm-slim

WORKDIR /app
COPY --chown=node:node package*.json ./
USER node
RUN npm ci --omit=dev
COPY --chown=node:node . .

# switch back to install the PDF renderer
~>USER root
RUN apt-get update && apt-get install -y --no-install-recommends chromium=126.0.6478.126-1~deb12u1 \
    && rm -rf /var/lib/apt/lists/*

CMD ["node", "server.js"]

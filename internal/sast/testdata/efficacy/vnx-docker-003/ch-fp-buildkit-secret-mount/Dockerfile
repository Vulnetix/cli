FROM node:20.15-alpine
WORKDIR /app
COPY package*.json ./
RUN --mount=type=secret,id=npm_token NPM_TOKEN=$(cat /run/secrets/npm_token) npm ci

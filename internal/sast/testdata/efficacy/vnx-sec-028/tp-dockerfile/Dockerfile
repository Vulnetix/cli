FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
~>RUN echo "//registry.npmjs.org/:_authToken=npm_@@sample:[A-Za-z0-9]{36}@@" > .npmrc && npm ci && rm .npmrc
COPY . .

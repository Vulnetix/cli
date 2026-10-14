FROM node:20.15-alpine
~>ARG NPM_TOKEN
~>ARG GITHUB_TOKEN=@@sample:ghp_[A-Za-z0-9]{36}@@
~>ARG dockerHubPassword=Winter2024!
WORKDIR /app
COPY package*.json ./
RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc \
    && npm ci --omit=dev \
    && rm -f .npmrc
COPY . .
CMD ["node", "server.js"]

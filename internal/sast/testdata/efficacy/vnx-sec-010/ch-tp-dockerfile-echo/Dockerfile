FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
~>RUN echo "//registry.npmjs.org/:_authToken=@@sample:npm_[A-Za-z0-9]{36}@@" > .npmrc && \
    npm ci --omit=dev && rm -f .npmrc
COPY . .
CMD ["node", "server.js"]

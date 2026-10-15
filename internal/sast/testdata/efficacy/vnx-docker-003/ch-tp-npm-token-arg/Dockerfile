FROM node:20.15-alpine
~>ARG NPM_TOKEN
WORKDIR /app
COPY .npmrc package*.json ./
RUN npm ci && rm .npmrc

~>FROM golang:alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /out/app .

~>FROM node:lts-alpine AS assets
RUN npm ci && npm run build

~>FROM nginx:alpine-slim
COPY --from=assets /dist /usr/share/nginx/html
~>COPY --from=debian:stable /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

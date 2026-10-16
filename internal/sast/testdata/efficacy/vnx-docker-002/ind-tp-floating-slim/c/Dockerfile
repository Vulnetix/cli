~>FROM node:lts-alpine AS web
WORKDIR /w
~>FROM python:slim
COPY --from=web /w /w

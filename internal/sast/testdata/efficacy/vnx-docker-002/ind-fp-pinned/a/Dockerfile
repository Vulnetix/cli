FROM ubuntu:22.04
FROM node:20.15.1-alpine3.20 AS web
FROM python:3.12.4-slim-bookworm
COPY --from=web /w /w

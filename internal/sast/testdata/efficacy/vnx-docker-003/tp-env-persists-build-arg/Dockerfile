FROM node:20.15-alpine AS build
~>ARG SENTRY_AUTH_TOKEN
# make the token available to the build script
~>ENV SENTRY_AUTH_TOKEN=${SENTRY_AUTH_TOKEN}
~>ENV STRIPE_API_KEY=$STRIPE_API_KEY
~>ENV DB_PASSWORD=${DB_PASSWORD:-postgres}
RUN npm ci && npm run build

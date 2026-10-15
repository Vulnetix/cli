FROM node:20-alpine
~>ENV DOPPLER_TOKEN=@@sample:dp\.pt\.[A-Za-z0-9]{43}@@
RUN apk add --no-cache doppler
CMD ["doppler", "run", "--", "node", "server.js"]

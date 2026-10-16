FROM node:20.15-alpine
WORKDIR /srv
COPY . .
RUN npm ci --omit=dev
~>USER 0:0
CMD ["node", "server.js"]

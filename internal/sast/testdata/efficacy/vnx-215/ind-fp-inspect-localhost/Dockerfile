FROM node:20-alpine
WORKDIR /app
COPY . .
RUN npm ci
CMD ["node", "--inspect=127.0.0.1:9229", "server.js"]

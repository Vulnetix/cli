FROM node:20-alpine
WORKDIR /app
COPY . .
EXPOSE 3000 9229
~>CMD ["node", "--inspect=0.0.0.0:9229", "server.js"]

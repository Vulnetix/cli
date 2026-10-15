~>FROM node:20.15.1-alpine
WORKDIR /app
COPY . .
RUN npm ci --omit=dev
USER node
EXPOSE 3000
CMD ["npm", "start"]

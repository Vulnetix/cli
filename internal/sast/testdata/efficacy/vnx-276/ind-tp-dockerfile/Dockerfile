FROM node:20-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
~>COPY --chmod=777 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY . .
~>RUN mkdir -p /app/uploads && chmod -R 777 /app/uploads
USER node
ENTRYPOINT ["docker-entrypoint.sh"]

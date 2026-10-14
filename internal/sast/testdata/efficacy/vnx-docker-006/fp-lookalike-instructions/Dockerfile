FROM node:20.15-alpine
ARG ADD_SOURCEMAPS=false
ENV ADDITIONAL_FLAGS="--max-old-space-size=512"
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev \
    && git add . \
    && echo done
RUN addgroup -S app && adduser -S app -G app
COPY . .
USER app
CMD ["node", "server.js"]

FROM node:20.15.1 AS Builder
WORKDIR /app
COPY . .
RUN npm ci && npm run build

FROM builder AS assets
RUN ls dist

FROM nginx:1.27.0
COPY --from=Builder /app/dist /usr/share/nginx/html

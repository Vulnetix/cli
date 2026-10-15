FROM node:20.15.1 AS build
WORKDIR /app
COPY . .
RUN npm ci && npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html

ARG NODE_IMAGE=node
~>FROM $NODE_IMAGE AS web
WORKDIR /app
COPY . .
RUN npm ci && npm run build

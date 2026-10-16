# ENV DB_PASSWORD=hunter2hunter2
FROM alpine:3.20
RUN --mount=type=secret,id=npm_token NPM_TOKEN=$(cat /run/secrets/npm_token) npm ci
LABEL description="set PASSWORD=foo in your environment"
RUN export API_TOKEN=abc123xyz789 && ./build.sh

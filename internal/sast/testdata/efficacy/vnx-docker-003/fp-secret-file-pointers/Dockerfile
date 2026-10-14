FROM postgres:16.3
ENV POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password
ENV GOOGLE_APPLICATION_CREDENTIALS=/var/secrets/google/key.json
ENV AWS_SHARED_CREDENTIALS_FILE=/home/app/.aws/credentials
ENV API_TOKEN_PATH ${APP_HOME}/secrets/token
RUN --mount=type=secret,id=npm_token,env=NPM_TOKEN npm ci --omit=dev
RUN --mount=type=secret,id=pg_pass \
    PGPASSWORD="$(cat /run/secrets/pg_pass)" psql -h db -c 'select 1'

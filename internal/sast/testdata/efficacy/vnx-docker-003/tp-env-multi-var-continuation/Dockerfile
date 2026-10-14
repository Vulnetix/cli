FROM python:3.12-slim
ENV APP_ENV=production \
~>    DATABASE_PASSWORD=pr0d-db-pa55 \
    LOG_LEVEL=info \
~>    SECRET_KEY_BASE=4c1d2e8f7a6b5c4d3e2f1a0b9c8d7e6f
~>ENV DJANGO_SETTINGS_MODULE=app.settings SENTRY_AUTH_TOKEN=s3ntry-7Hq2c9Lw WORKERS=4
CMD ["gunicorn", "app.wsgi"]

FROM python:3.12-slim
ARG APP_UID=10001
RUN useradd --uid "${APP_UID}" --create-home app
WORKDIR /home/app
COPY --chown=app . .
user ${APP_UID}
CMD ["python", "-m", "worker"]

FROM eclipse-temurin:21-jre-jammy
ARG APP_USER=worker
RUN useradd --system --no-create-home "${APP_USER}"
COPY build/libs/worker.jar /opt/worker.jar
USER ${APP_USER}
ENTRYPOINT ["java", "-jar", "/opt/worker.jar"]

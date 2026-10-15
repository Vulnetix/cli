FROM eclipse-temurin:21-jre
COPY flyway-runner.jar /opt/flyway-runner.jar
USER 10001
CMD ["java", "-jar", "/opt/flyway-runner.jar", "migrate"]

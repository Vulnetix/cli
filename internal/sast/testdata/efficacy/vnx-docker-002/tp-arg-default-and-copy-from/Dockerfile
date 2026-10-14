ARG BASE_IMAGE=eclipse-temurin:latest
ARG TOOLS_IMAGE="alpine"

~>FROM ${TOOLS_IMAGE} AS tools
RUN apk add --no-cache curl=8.9.1-r1

~>FROM $BASE_IMAGE
~>COPY --from=composer:latest /usr/bin/composer /usr/local/bin/composer
~>COPY --chmod=755 --from=mlocati/php-extension-installer /usr/bin/install-php-extensions /usr/local/bin/
COPY --from=tools /usr/bin/curl /usr/bin/curl
COPY target/app.jar /app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]

FROM debian:12-slim
RUN apt-get update && apt-get install -y curl ca-certificates
~>RUN curl -k https://artifacts.internal.example/tool.tar.gz -o /tmp/tool.tar.gz && tar -xzf /tmp/tool.tar.gz -C /usr/local/bin
COPY . /app

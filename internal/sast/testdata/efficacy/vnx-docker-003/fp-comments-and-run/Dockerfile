FROM alpine:3.20
# ENV DB_PASSWORD=hunter2
# ARG NPM_TOKEN  -- removed, we use a secret mount now
LABEL org.example.note="set API_KEY at runtime, never in ENV"
RUN echo "ENV API_KEY=abc123" >> /usr/share/doc/notes.txt
COPY docs/ENV_TOKEN_EXAMPLE.txt /usr/share/doc/

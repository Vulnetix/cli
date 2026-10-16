# USER root is deliberately not used here
FROM nginxinc/nginx-unprivileged:1.27
COPY site /usr/share/nginx/html
RUN echo "USER root" > /tmp/note

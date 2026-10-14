~>FROM ubuntu
RUN useradd -m web
~>FROM docker.io/library/nginx:latest
COPY site/ /usr/share/nginx/html/

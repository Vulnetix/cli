~>FROM golang AS build
RUN go version
FROM alpine:3.20
~>COPY --from=nginx /etc/nginx/nginx.conf /etc/nginx/nginx.conf

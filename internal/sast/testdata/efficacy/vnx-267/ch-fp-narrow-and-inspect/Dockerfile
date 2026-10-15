FROM alpine:3.20
RUN apk add --no-cache libcap && setcap cap_net_bind_service=+ep /usr/sbin/nginx
# setcap cap_sys_admin+ep was needed before 1.4

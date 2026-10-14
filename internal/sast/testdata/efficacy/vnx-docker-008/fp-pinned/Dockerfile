FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl=7.88.1-10+deb12u8 \
      ca-certificates=20230311 \
 && rm -rf /var/lib/apt/lists/*
RUN apt-get install -y -o Dpkg::Options::="--force-confold" tzdata=2024a-0+deb12u1
RUN apt-get install -y "libpq5=15.*"

FROM alpine:3.20
RUN apk add --no-cache curl=8.9.1-r1 'nodejs~20' "npm>10.0"
RUN apk add --no-cache --virtual .build-deps gcc=13.2.1_git20240309-r0

FROM registry.access.redhat.com/ubi9/ubi:9.4
RUN yum install -y httpd-2.4.57-11.el9_4 && yum clean all
RUN dnf install -y --setopt=install_weak_deps=False nginx-1:1.20.1-14.el9_2.1

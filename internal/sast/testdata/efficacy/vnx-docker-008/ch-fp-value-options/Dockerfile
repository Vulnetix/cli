FROM alpine:3.20
RUN apk add --no-cache --repository https://dl-cdn.alpinelinux.org/alpine/edge/community tini=0.19.0-r3
RUN apk add --no-cache -X https://dl-cdn.alpinelinux.org/alpine/edge/testing gosu=1.17-r5
FROM debian:bookworm-slim
RUN apt-get install -y --target-release bookworm-backports golang-go=2:1.22~3~bpo12+1
RUN apt-get install -y nodejs=${NODE_VERSION} npm="${NPM_DEB_VERSION}"
FROM rockylinux:9.3
RUN yum -y install httpd-2.4.57-11.el9 && yum clean all
RUN dnf install -y --setopt=install_weak_deps=False --enablerepo crb nginx-1.20.1-14.el9

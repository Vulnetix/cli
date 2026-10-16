FROM debian:12-slim
ARG PKGS="curl=7.88.1-10+deb12u5"
RUN apt-get install -y $PKGS
RUN apt-get install -y $(cat packages.txt)
RUN cat packages.txt | xargs apt-get install -y
RUN apt-get install -y ./local.deb

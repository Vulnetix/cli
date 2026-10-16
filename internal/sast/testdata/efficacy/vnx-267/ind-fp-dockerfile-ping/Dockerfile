FROM debian:12-slim
RUN apt-get update && apt-get install -y iputils-ping libcap2-bin
RUN setcap cap_net_raw+ep /bin/ping

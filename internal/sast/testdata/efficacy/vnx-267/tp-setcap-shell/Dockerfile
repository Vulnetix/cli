FROM debian:12
COPY agent /usr/local/bin/agent
~>RUN apt-get update && apt-get install -y libcap2-bin && setcap cap_sys_ptrace+ep /usr/local/bin/agent
USER 1000

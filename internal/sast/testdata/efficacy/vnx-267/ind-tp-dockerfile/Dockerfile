FROM ubuntu:24.04
RUN apt-get update && apt-get install -y libcap2-bin && rm -rf /var/lib/apt/lists/*
COPY agent /usr/local/bin/agent
~>RUN setcap cap_bpf,cap_perfmon+ep /usr/local/bin/agent
USER nobody
ENTRYPOINT ["/usr/local/bin/agent"]

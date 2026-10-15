FROM debian:bookworm-slim
COPY agent /usr/local/bin/agent
~>RUN setcap 'cap_dac_override,cap_sys_ptrace=+ep' /usr/local/bin/agent
~>RUN apt-get update && apt-get install -y libcap2-bin && setcap cap_sys_admin+eip /usr/local/bin/agent

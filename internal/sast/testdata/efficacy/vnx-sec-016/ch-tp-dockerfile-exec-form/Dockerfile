FROM alpine:3.20
~>RUN ["curl", "-k", "-o", "/tmp/agent.tgz", "https://repo.internal/agent.tgz"]
~>RUN ["wget", "--no-check-certificate", "https://repo.internal/cfg.json"]
RUN ["curl", "-fsSL", "-o", "/tmp/x", "https://repo.internal/x"]

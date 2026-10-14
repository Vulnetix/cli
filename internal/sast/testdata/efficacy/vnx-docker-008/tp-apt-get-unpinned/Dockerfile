FROM debian:bookworm-slim
~>RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update \
~> && apt-get install -y --no-install-recommends \
      git=1:2.39.5-0+deb12u1 \
      # the ssh client is needed for private submodules
      openssh-client \
 && rm -rf /var/lib/apt/lists/*

~>RUN DEBIAN_FRONTEND=noninteractive apt-get -y install -o Dpkg::Options::="--force-confold" tzdata
~>RUN apt install -y jq
~>RUN apt update && apt install curl wget iputils-ping -y; rm -rf /var/lib/apt/lists/*
~>RUN apt-get install -y -t bookworm-backports golang-go/bookworm-backports

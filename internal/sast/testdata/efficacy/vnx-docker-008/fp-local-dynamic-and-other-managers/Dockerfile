FROM debian:bookworm-slim
COPY packages.txt vendor/ /tmp/
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y ./vendor/agent_1.2.3_amd64.deb
RUN apt-get install -y /tmp/vendor/tool_2.0.1_amd64.deb
RUN apt-get install -y $BUILD_DEPS
RUN apt-get install -y $(grep -v '^#' /tmp/packages.txt)
RUN xargs apt-get install -y < /tmp/packages.txt
RUN apt-get install -f
RUN apt-get remove -y curl && apt-get autoremove -y
RUN pip install requests && npm install -g pnpm && gem install bundler
RUN rpm -i /tmp/vendor/tool-2.0.1.x86_64.rpm
RUN yum localinstall -y /tmp/vendor/tool-2.0.1.x86_64.rpm

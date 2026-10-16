FROM debian:12-slim
RUN apt-get update && apt-get upgrade -y
RUN apt-get remove -y curl
RUN pip install requests flask
RUN npm install -g typescript
RUN gem install bundler
RUN rpm -i /tmp/local.rpm

FROM nginx:1.27.0
ADD ./https/cert.pem /etc/nginx/certs/cert.pem
COPY http.conf /etc/nginx/conf.d/
LABEL org.opencontainers.image.source=https://github.com/example/site
RUN curl -fsSLo /tmp/x.tgz https://dl.example.com/x.tgz && echo "abc  /tmp/x.tgz" | sha256sum -c

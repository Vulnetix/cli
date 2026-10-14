FROM debian:bookworm-slim
# RUN apt-get install -y curl
#   apk add curl
LABEL org.example.build="apt-get install curl, then strip docs"
COPY <<EOF /usr/share/doc/app/INSTALL
apt-get install -y curl
EOF

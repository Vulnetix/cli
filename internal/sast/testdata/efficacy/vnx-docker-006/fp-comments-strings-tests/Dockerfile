FROM alpine:3.20
# ADD . /app   (old layout)
LABEL org.example.hint="ADD config /etc/app"
RUN echo "ADD . /app" > /usr/share/doc/app/notes
COPY <<EOF /usr/share/doc/app/Dockerfile.sample
ADD . /sample
EOF
COPY . /app

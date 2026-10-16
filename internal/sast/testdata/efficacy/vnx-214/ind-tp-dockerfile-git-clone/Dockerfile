FROM golang:1.22 AS build
ARG GH_TOKEN
WORKDIR /src
~>RUN git clone "https://x-access-token:${GH_TOKEN}@github.com/acme/private-lib.git" /src/private-lib
COPY . .
RUN go build -o /out/app ./cmd/app

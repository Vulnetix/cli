# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install git (needed for go mod)
RUN apk add --no-cache git

# Copy the full source first. The go.mod replace points at the in-repo
# third_party/vdb-cyclonedx copy, which must be present before dependency
# resolution — so it cannot be split into a go.mod-only cache layer.
COPY . .

RUN go mod download

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w -X github.com/vulnetix/cli/v3/cmd.version=docker" \
    -o vulnetix \
    .

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder stage  
COPY --from=builder /app/vulnetix .

# Make sure the binary is executable
RUN chmod +x ./vulnetix

ENTRYPOINT ["./vulnetix"]

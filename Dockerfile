# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install git (needed for go mod)
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w -X github.com/vulnetix/cli/cmd.version=docker" \
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

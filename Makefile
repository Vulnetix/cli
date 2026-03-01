.PHONY: build clean test install dev fmt lint build-release

# Configuration
VERSION ?= dev
OUTPUT_DIR = bin
BINARY_NAME = vulnetix

# Default target
all: build

# Build the binary for current platform
build:
	@echo "Building Vulnetix CLI..."
	@mkdir -p $(OUTPUT_DIR)
	go build -ldflags "-s -w -X github.com/vulnetix/cli/cmd.version=$(VERSION)" -o $(OUTPUT_DIR)/$(BINARY_NAME) .
	@echo "✓ Built $(OUTPUT_DIR)/$(BINARY_NAME)"

# Build for all platforms
build-all:
	@echo "Building for all platforms..."
	@export VERSION=$(VERSION) && ./build.sh

# Build for specific platforms (used by release process)
build-release: clean
	@echo "Building release binaries for all platforms..."
	@mkdir -p $(OUTPUT_DIR)
	
	# Linux builds
	@echo "Building for Linux AMD64..."
	@GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X github.com/vulnetix/cli/cmd.version=$(VERSION)" -o $(OUTPUT_DIR)/$(BINARY_NAME)-linux-amd64 .
	@echo "Building for Linux ARM64..."
	@GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -X github.com/vulnetix/cli/cmd.version=$(VERSION)" -o $(OUTPUT_DIR)/$(BINARY_NAME)-linux-arm64 .
	@echo "Building for Linux ARM..."
	@GOOS=linux GOARCH=arm go build -ldflags "-s -w -X github.com/vulnetix/cli/cmd.version=$(VERSION)" -o $(OUTPUT_DIR)/$(BINARY_NAME)-linux-arm .
	@echo "Building for Linux 386..."
	@GOOS=linux GOARCH=386 go build -ldflags "-s -w -X github.com/vulnetix/cli/cmd.version=$(VERSION)" -o $(OUTPUT_DIR)/$(BINARY_NAME)-linux-386 .
	
	# macOS builds
	@echo "Building for macOS AMD64..."
	@GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w -X github.com/vulnetix/cli/cmd.version=$(VERSION)" -o $(OUTPUT_DIR)/$(BINARY_NAME)-darwin-amd64 .
	@echo "Building for macOS ARM64..."
	@GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w -X github.com/vulnetix/cli/cmd.version=$(VERSION)" -o $(OUTPUT_DIR)/$(BINARY_NAME)-darwin-arm64 .
	
	# Windows builds
	@echo "Building for Windows AMD64..."
	@GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -X github.com/vulnetix/cli/cmd.version=$(VERSION)" -o $(OUTPUT_DIR)/$(BINARY_NAME)-windows-amd64.exe .
	@echo "Building for Windows ARM64..."
	@GOOS=windows GOARCH=arm64 go build -ldflags "-s -w -X github.com/vulnetix/cli/cmd.version=$(VERSION)" -o $(OUTPUT_DIR)/$(BINARY_NAME)-windows-arm64.exe .
	@echo "Building for Windows ARM..."
	@GOOS=windows GOARCH=arm go build -ldflags "-s -w -X github.com/vulnetix/cli/cmd.version=$(VERSION)" -o $(OUTPUT_DIR)/$(BINARY_NAME)-windows-arm.exe .
	@echo "Building for Windows 386..."
	@GOOS=windows GOARCH=386 go build -ldflags "-s -w -X github.com/vulnetix/cli/cmd.version=$(VERSION)" -o $(OUTPUT_DIR)/$(BINARY_NAME)-windows-386.exe .
	
	@echo "✓ Built release binaries for all platforms"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(OUTPUT_DIR)
	go clean

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Coverage reporting
test-coverage:
	go test -v -cover ./...

# Coverage with HTML report
test-coverage-html:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Coverage threshold enforcement
test-coverage-check:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//' | awk '{if ($1 < 90) exit 1}'

# Comprehensive test suite
test-all: test test-coverage-check

# Install to local GOPATH
install:
	@echo "Installing to GOPATH..."
	go install -ldflags "-s -w -X github.com/vulnetix/cli/cmd.version=$(VERSION)" .

# Development build with debug info
dev:
	@echo "Building development version..."
	@mkdir -p $(OUTPUT_DIR)
	go build -ldflags "-X github.com/vulnetix/cli/cmd.version=$(VERSION)-dev" -o $(OUTPUT_DIR)/$(BINARY_NAME) .

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Lint code
lint:
	@echo "Linting code..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed, using go vet..."; \
		go vet ./...; \
	fi

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Run the binary with a test UUID
run:
	@$(MAKE) build
	@echo "Running Vulnetix CLI with test UUID..."
	@./$(OUTPUT_DIR)/$(BINARY_NAME) --org-id "123e4567-e89b-12d3-a456-426614174000"

# Show help
help:
	@echo "Available commands:"
	@echo "  build        - Build binary for current platform"
	@echo "  build-all    - Build binaries for all platforms"
	@echo "  build-release - Build release binaries for all platforms"
	@echo "  clean        - Clean build artifacts"
	@echo "  test         - Run tests"
	@echo "  install      - Install to GOPATH"
	@echo "  dev          - Build development version"
	@echo "  fmt          - Format code"
	@echo "  lint         - Lint code"
	@echo "  deps         - Download and tidy dependencies"
	@echo "  run          - Build and run with test UUID"
	@echo "  help         - Show this help"

#!/bin/bash

set -e

# Configuration
VERSION=${VERSION:-"1.0.0"}
OUTPUT_DIR="bin"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Building Vulnetix CLI v${VERSION}${NC}"

# Create output directory
mkdir -p $OUTPUT_DIR

# Build targets
TARGETS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
)

# Build for each target
for target in "${TARGETS[@]}"; do
    IFS='/' read -r GOOS GOARCH <<< "$target"
    
    echo -e "${YELLOW}Building for ${GOOS}/${GOARCH}...${NC}"
    
    # Set output filename
    output_name="vulnetix-${GOOS}-${GOARCH}"
    if [[ $GOOS == "windows" ]]; then
        output_name="${output_name}.exe"
    fi
    
    # Build
    CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags "-s -w -X github.com/vulnetix/cli/cmd.version=${VERSION}" \
        -o "${OUTPUT_DIR}/${output_name}" \
        .
    
    echo -e "${GREEN}✓ Built ${output_name}${NC}"
done

echo -e "${GREEN}Build complete! Binaries are in the ${OUTPUT_DIR}/ directory${NC}"
ls -la $OUTPUT_DIR/

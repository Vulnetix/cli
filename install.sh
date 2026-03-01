#!/bin/bash

set -e

# Default values
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-latest}"
BINARY_NAME="vulnetix"
GITHUB_REPO="Vulnetix/cli"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --install-dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --help)
      echo "Vulnetix CLI Installation Script"
      echo ""
      echo "Usage: $0 [options]"
      echo ""
      echo "Options:"
      echo "  --install-dir DIR    Installation directory (default: /usr/local/bin)"
      echo "  --version VERSION    Version to install (default: latest)"
      echo "  --help              Show this help message"
      echo ""
      echo "Examples:"
      echo "  $0                                    # Install latest to /usr/local/bin"
      echo "  $0 --install-dir ~/.local/bin        # Install to ~/.local/bin"
      echo "  $0 --version v1.2.3                  # Install specific version"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

# Detect platform
detect_platform() {
  local os
  local arch
  
  # Detect OS
  case "$(uname -s)" in
    Linux*)   os="linux" ;;
    Darwin*)  os="darwin" ;;
    CYGWIN*|MINGW*|MSYS*) os="windows" ;;
    *)        echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
  esac
  
  # Detect architecture
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    armv7l|armv6l) arch="arm" ;;
    i386|i686) arch="386" ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
  esac
  
  echo "${os}-${arch}"
}

# Get download URL
get_download_url() {
  local platform="$1"
  local version="$2"
  local binary_name="$3"
  
  if [ "$os" = "windows" ]; then
    binary_name="${binary_name}.exe"
  fi
  
  if [ "$version" = "latest" ]; then
    echo "https://github.com/${GITHUB_REPO}/releases/latest/download/${BINARY_NAME}-${platform}${binary_name:+.exe}"
  else
    echo "https://github.com/${GITHUB_REPO}/releases/download/${version}/${BINARY_NAME}-${platform}${binary_name:+.exe}"
  fi
}

# Main installation logic
main() {
  echo "🚀 Installing Vulnetix CLI..."
  
  # Detect platform
  local platform
  platform=$(detect_platform)
  echo "📦 Detected platform: $platform"
  
  # Get download URL
  local download_url
  download_url=$(get_download_url "$platform" "$VERSION" "$BINARY_NAME")
  echo "⬇️  Downloading from: $download_url"
  
  # Create install directory if it doesn't exist
  mkdir -p "$INSTALL_DIR"
  
  # Download binary
  local binary_path="$INSTALL_DIR/$BINARY_NAME"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$download_url" -o "$binary_path"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$download_url" -O "$binary_path"
  else
    echo "❌ Error: curl or wget is required for installation" >&2
    exit 1
  fi
  
  # Make binary executable (not needed on Windows)
  if [ "$(uname -s)" != "CYGWIN" ] && [ "$(uname -s)" != "MINGW" ] && [ "$(uname -s)" != "MSYS" ]; then
    chmod +x "$binary_path"
  fi
  
  echo "✅ Successfully installed Vulnetix CLI to $binary_path"
  echo ""
  echo "🎉 Installation complete!"
  echo ""
  echo "To get started:"
  echo "  $binary_path --help"
  echo "  $binary_path --org-id \"your-org-id-here\""
  echo ""
  
  # Check if install directory is in PATH
  if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    echo "⚠️  Note: $INSTALL_DIR is not in your PATH."
    echo "   You may need to add it to your shell configuration:"
    echo "   export PATH=\"$INSTALL_DIR:\$PATH\""
    echo ""
  fi
  
  # Test installation
  if command -v "$BINARY_NAME" >/dev/null 2>&1; then
    echo "🔍 Testing installation..."
    "$BINARY_NAME" --version 2>/dev/null || echo "   Binary installed successfully!"
  fi
}

main "$@"

#!/bin/sh

set -e

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-latest}"
BINARY_NAME="vulnetix"
GITHUB_REPO="Vulnetix/cli"
GITHUB_BASE="https://github.com/${GITHUB_REPO}/releases"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while [ $# -gt 0 ]; do
  case "$1" in
    --install-dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --help)
      cat <<EOF
Usage: install.sh [options]

Options:
  --install-dir DIR    Installation directory (default: /usr/local/bin)
  --version VERSION    Version to install, e.g. v1.2.3 (default: latest)
  --help               Show this message

Environment variables:
  INSTALL_DIR          Overrides --install-dir
  VERSION              Overrides --version

Examples:
  curl -fsSL https://cli.vulnetix.com/install.sh | sh
  curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --install-dir ~/.local/bin
  curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --version v1.2.3
EOF
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      echo "Run with --help for usage." >&2
      exit 1
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------

detect_os() {
  case "$(uname -s 2>/dev/null)" in
    Linux)   echo "linux" ;;
    Darwin)  echo "darwin" ;;
    CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
    *)
      echo "error: unsupported OS: $(uname -s)" >&2
      exit 1
      ;;
  esac
}

detect_arch() {
  case "$(uname -m 2>/dev/null)" in
    x86_64|amd64)   echo "amd64" ;;
    arm64|aarch64)  echo "arm64" ;;
    armv7l|armv6l)  echo "arm" ;;
    i386|i686)      echo "386" ;;
    *)
      echo "error: unsupported architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

detect_downloader() {
  if command -v curl >/dev/null 2>&1; then
    echo "curl"
  elif command -v wget >/dev/null 2>&1; then
    echo "wget"
  else
    echo "error: curl or wget is required" >&2
    exit 1
  fi
}

check_existing() {
  local target="$1"
  if [ -f "$target" ]; then
    local existing_ver
    existing_ver="$("$target" version 2>/dev/null | head -1 || true)"
    echo "info: existing binary found: ${existing_ver:-unknown version}"
    echo "info: will be overwritten at $target"
  fi
}

resolve_install_dir() {
  local dir="$1"
  if mkdir -p "$dir" 2>/dev/null && [ -w "$dir" ]; then
    echo "$dir"
    return
  fi
  local fallback="$HOME/.local/bin"
  echo "warn: $dir is not writable, falling back to $fallback" >&2
  mkdir -p "$fallback"
  echo "$fallback"
}

download() {
  local url="$1"
  local dest="$2"
  local downloader="$3"
  echo "info: downloading $url"
  if [ "$downloader" = "curl" ]; then
    curl -fsSL --retry 3 --retry-delay 2 "$url" -o "$dest"
  else
    wget -q "$url" -O "$dest"
  fi
}

verify_binary() {
  local path="$1"
  if [ ! -f "$path" ]; then
    echo "error: downloaded file not found at $path" >&2
    exit 1
  fi
  local size
  size=$(wc -c < "$path" 2>/dev/null || echo 0)
  if [ "$size" -lt 1024 ]; then
    echo "error: downloaded file is suspiciously small (${size} bytes) — download may have failed" >&2
    rm -f "$path"
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  echo "vulnetix installer"
  echo "------------------"

  # Detect environment
  OS=$(detect_os)
  ARCH=$(detect_arch)
  PLATFORM="${OS}-${ARCH}"
  DOWNLOADER=$(detect_downloader)
  echo "info: os=$OS arch=$ARCH platform=$PLATFORM downloader=$DOWNLOADER"

  # Resolve install directory
  INSTALL_DIR=$(resolve_install_dir "$INSTALL_DIR")
  BINARY_PATH="${INSTALL_DIR}/${BINARY_NAME}"
  echo "info: install dir=$INSTALL_DIR"

  # Check for existing installation
  check_existing "$BINARY_PATH"

  # Build download URL
  EXT=""
  [ "$OS" = "windows" ] && EXT=".exe"
  ASSET="${BINARY_NAME}-${PLATFORM}${EXT}"
  if [ "$VERSION" = "latest" ]; then
    DOWNLOAD_URL="${GITHUB_BASE}/latest/download/${ASSET}"
  else
    DOWNLOAD_URL="${GITHUB_BASE}/download/${VERSION}/${ASSET}"
  fi
  echo "info: version=$VERSION asset=$ASSET"
  echo "info: url=$DOWNLOAD_URL"

  # Download to temp file then move into place atomically
  TMP_FILE=$(mktemp "${INSTALL_DIR}/.${BINARY_NAME}.XXXXXX" 2>/dev/null || mktemp)
  trap 'rm -f "$TMP_FILE"' EXIT

  download "$DOWNLOAD_URL" "$TMP_FILE" "$DOWNLOADER"
  verify_binary "$TMP_FILE"

  # Set executable permission before moving
  chmod +x "$TMP_FILE"
  mv "$TMP_FILE" "$BINARY_PATH"
  trap - EXIT

  echo "info: installed to $BINARY_PATH"

  # Confirm the binary runs
  INSTALLED_VER=$("$BINARY_PATH" version 2>/dev/null | head -1 || true)
  if [ -n "$INSTALLED_VER" ]; then
    echo "info: verified: $INSTALLED_VER"
  else
    echo "warn: binary installed but --version produced no output"
  fi

  # PATH advisory
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
      echo ""
      echo "warn: $INSTALL_DIR is not in PATH"
      echo "      add to your shell profile:"
      echo "      export PATH=\"${INSTALL_DIR}:\$PATH\""
      ;;
  esac

  echo ""
  echo "run:  $BINARY_NAME --help"
  echo ""
  echo "docs: https://docs.cli.vulnetix.com/"
  echo "      agentic use cases: https://www.vulnetix.com/articles/bypassing-scanners"
  echo ""
  echo "Thanks for installing Vulnetix CLI -- Vulnetix Team"
}

main "$@"

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
    Linux)              echo "linux" ;;
    Darwin)             echo "darwin" ;;
    CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
    *)
      echo "error: unsupported OS: $(uname -s)" >&2
      exit 1
      ;;
  esac
}

detect_arch() {
  case "$(uname -m 2>/dev/null)" in
    x86_64|amd64)  echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    armv7l|armv6l) echo "arm" ;;
    i386|i686)     echo "386" ;;
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

# Detect available sha256 tool, ordered most to least commonly available per platform:
#   sha256sum  — GNU coreutils (Linux, Alpine/busybox, Git for Windows/MSYS)
#   shasum     — Perl digest tool (macOS built-in, most Unix with Perl)
#   sha256     — BSD native (FreeBSD, OpenBSD, NetBSD)
#   openssl    — widely available fallback
#   python3    — modern systems (macOS 10.15+, most Linux distros)
#   python     — older Python 2 systems
#   rhash      — available on some Linux distros (Fedora, Arch)
#   certutil   — Windows (CYGWIN/MSYS/MinGW) last resort
detect_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    echo "sha256sum"
  elif command -v shasum >/dev/null 2>&1; then
    echo "shasum"
  elif command -v sha256 >/dev/null 2>&1; then
    echo "sha256"
  elif command -v openssl >/dev/null 2>&1; then
    echo "openssl"
  elif command -v python3 >/dev/null 2>&1; then
    echo "python3"
  elif command -v python >/dev/null 2>&1 && python -c "import hashlib" 2>/dev/null; then
    echo "python"
  elif command -v rhash >/dev/null 2>&1; then
    echo "rhash"
  elif command -v certutil >/dev/null 2>&1; then
    echo "certutil"
  else
    echo "none"
  fi
}

compute_sha256() {
  local file="$1"
  local tool="$2"
  case "$tool" in
    sha256sum) sha256sum "$file" | awk '{print $1}' ;;
    shasum)    shasum -a 256 "$file" | awk '{print $1}' ;;
    sha256)    sha256 -q "$file" ;;
    openssl)   openssl dgst -sha256 "$file" | awk '{print $NF}' ;;
    python3)   python3 -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$file" ;;
    python)    python  -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$file" ;;
    rhash)     rhash --sha256 --printf='%h\n' "$file" ;;
    certutil)  certutil -hashfile "$file" SHA256 2>/dev/null | grep -v "^SHA256" | grep -v "CertUtil:" | tr -d ' \r\n' ;;
  esac
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
  if [ "$downloader" = "curl" ]; then
    curl -fsSL --retry 3 --retry-delay 2 "$url" -o "$dest"
  else
    wget -q "$url" -O "$dest"
  fi
}

verify_size() {
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
  echo "info: download size=${size} bytes"
}

verify_checksum() {
  local asset="$1"
  local tmp_binary="$2"
  local checksums_url="$3"
  local downloader="$4"
  local sha_tool="$5"

  if [ "$sha_tool" = "none" ]; then
    echo "warn: no sha256 tool found (sha256sum/shasum/openssl), skipping checksum verification"
    return
  fi

  local tmp_checksums
  tmp_checksums=$(mktemp)
  trap 'rm -f "$tmp_checksums"' EXIT

  echo "info: fetching $checksums_url"
  if ! download "$checksums_url" "$tmp_checksums" "$downloader" 2>&1; then
    echo "warn: could not fetch checksums.txt, skipping checksum verification" >&2
    rm -f "$tmp_checksums"
    trap - EXIT
    return
  fi

  # Extract expected hash for this asset from checksums.txt
  local expected
  expected=$(grep " ${asset}$" "$tmp_checksums" | awk '{print $1}')
  rm -f "$tmp_checksums"
  trap - EXIT

  if [ -z "$expected" ]; then
    echo "warn: asset '${asset}' not found in checksums.txt, skipping checksum verification" >&2
    return
  fi

  echo "info: expected sha256=$expected"

  local actual
  actual=$(compute_sha256 "$tmp_binary" "$sha_tool")
  echo "info: actual   sha256=$actual"

  if [ "$actual" != "$expected" ]; then
    echo "error: checksum mismatch — binary may be corrupt or tampered with" >&2
    echo "error:   expected: $expected" >&2
    echo "error:   actual:   $actual" >&2
    rm -f "$tmp_binary"
    exit 1
  fi

  echo "info: checksum verified ok"
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
  SHA_TOOL=$(detect_sha256)
  echo "info: os=$OS arch=$ARCH platform=$PLATFORM downloader=$DOWNLOADER sha256=$SHA_TOOL"

  # Resolve install directory
  INSTALL_DIR=$(resolve_install_dir "$INSTALL_DIR")
  BINARY_PATH="${INSTALL_DIR}/${BINARY_NAME}"
  echo "info: install dir=$INSTALL_DIR"

  # Check for existing installation
  check_existing "$BINARY_PATH"

  # Build download URLs
  EXT=""
  [ "$OS" = "windows" ] && EXT=".exe"
  ASSET="${BINARY_NAME}-${PLATFORM}${EXT}"
  if [ "$VERSION" = "latest" ]; then
    DOWNLOAD_URL="${GITHUB_BASE}/latest/download/${ASSET}"
    CHECKSUMS_URL="${GITHUB_BASE}/latest/download/checksums.txt"
  else
    DOWNLOAD_URL="${GITHUB_BASE}/download/${VERSION}/${ASSET}"
    CHECKSUMS_URL="${GITHUB_BASE}/download/${VERSION}/checksums.txt"
  fi

  echo "info: version=$VERSION asset=$ASSET"
  echo "info: binary    $DOWNLOAD_URL"
  echo "info: checksums $CHECKSUMS_URL"

  # Download binary to temp file
  TMP_FILE=$(mktemp "${INSTALL_DIR}/.${BINARY_NAME}.XXXXXX" 2>/dev/null || mktemp)
  trap 'rm -f "$TMP_FILE"' EXIT

  echo "info: fetching $DOWNLOAD_URL"
  download "$DOWNLOAD_URL" "$TMP_FILE" "$DOWNLOADER"
  verify_size "$TMP_FILE"
  verify_checksum "$ASSET" "$TMP_FILE" "$CHECKSUMS_URL" "$DOWNLOADER" "$SHA_TOOL"

  # Set executable permission then move into place atomically
  chmod +x "$TMP_FILE"
  mv "$TMP_FILE" "$BINARY_PATH"
  trap - EXIT

  echo "info: installed to $BINARY_PATH"

  # Confirm the binary runs
  INSTALLED_VER=$("$BINARY_PATH" version 2>/dev/null | head -1 || true)
  if [ -n "$INSTALLED_VER" ]; then
    echo "info: verified: $INSTALLED_VER"
  else
    echo "warn: binary installed but 'version' produced no output"
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

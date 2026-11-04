#!/bin/sh

set -e

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-latest}"
BINARY_NAME="vulnetix"
GITHUB_REPO="Vulnetix/cli"
GITHUB_BASE="https://github.com/${GITHUB_REPO}/releases"
DOCS_URL="https://docs.vulnetix.com/cli/"
INSECURE_SKIP_VERIFY="${VULNETIX_INSECURE_SKIP_VERIFY:-0}"
REQUIRE_PROVENANCE="${VULNETIX_REQUIRE_PROVENANCE:-0}"

# The provenance bundle and the identity that signs it, exactly as
# .github/workflows/slsa-provenance.yml produces them: one Sigstore bundle per
# release, named provenance.sigstore.json, holding an SLSA v1 statement whose
# subjects are every line of checksums.txt. The certificate names the reusable
# workflow (job_workflow_ref), not release.yml, at the ref the release ran
# from: refs/heads/main for a dispatched release, refs/tags/v* for a tag push.
# The repository claim pins the caller, since belai calls the same workflow.
PROVENANCE_ASSET="provenance.sigstore.json"
PROVENANCE_TYPE="slsaprovenance1"
PROVENANCE_ISSUER="https://token.actions.githubusercontent.com"
PROVENANCE_IDENTITY_REGEXP='^https://github\.com/Vulnetix/cli/\.github/workflows/slsa-provenance\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+.*)$'
PROVENANCE_REPOSITORY="Vulnetix/cli"
# The provenance job signs a few minutes after the release is published (one to
# nine minutes across the v4 releases so far), so a release resolved from latest
# or a channel in that window has no bundle yet. With provenance required, the
# installer waits up to ten minutes for it.
PROVENANCE_WAIT_TRIES="${VULNETIX_PROVENANCE_WAIT_TRIES:-20}"
PROVENANCE_WAIT_SECONDS=30
FLOATING_VERSION=0

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
    --insecure-skip-verify)
      INSECURE_SKIP_VERIFY=1
      shift
      ;;
    --require-provenance)
      REQUIRE_PROVENANCE=1
      shift
      ;;
    --help)
      cat <<EOF
Usage: install.sh [options]

Options:
  --install-dir DIR       Installation directory (default: /usr/local/bin)
  --version VERSION       Version to install, e.g. v1.2.3, or a major channel
                          such as v3 for the newest v3 release (default: latest)
  --require-provenance    Fail unless cosign is on PATH and the release's signed
                          SLSA provenance verifies for the downloaded binary
  --insecure-skip-verify  Install without checking the SHA-256 checksum or the
                          provenance. Not recommended
  --help                  Show this message

Verification:
  The binary is installed only when its SHA-256 matches the release's
  checksums.txt. The installer stops when it has no SHA-256 tool, cannot
  fetch checksums.txt, or finds no entry for the binary. When cosign is on
  PATH it also verifies the release's signed provenance (${PROVENANCE_ASSET})
  and stops if that fails.

Environment variables:
  INSTALL_DIR                      Overrides --install-dir
  VERSION                          Overrides --version
  VULNETIX_REQUIRE_PROVENANCE=1    Same as --require-provenance
  VULNETIX_INSECURE_SKIP_VERIFY=1  Same as --insecure-skip-verify

Analytics:
  After a successful install the script sends one anonymous event to Google
  Analytics (GA4) with the OS, architecture, CLI version and a random id
  made for this install. Nothing identifies you or your machine. To opt out,
  set either variable:
  VULNETIX_NO_ANALYTICS=1
  DO_NOT_TRACK=1
  The installed CLI honours the same variables and --no-analytics.

Examples:
  curl -fsSL https://cli.vulnetix.com/install.sh | sh
  curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --install-dir ~/.local/bin
  curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --version v1.2.3
  curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --require-provenance

Docs: ${DOCS_URL}
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
    # --retry-all-errors is what makes this retry a TRUNCATED transfer. curl
    # reports an incomplete body as exit 18, which plain --retry treats as a
    # hard failure rather than something to try again — so a connection that
    # dropped part way through a 90 MB binary used to be handed straight to the
    # checksum check, which then announced possible tampering.
    curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors "$url" -o "$dest"
  else
    # wget had no retry configuration at all.
    wget -q --tries=5 --timeout=30 --waitretry=2 "$url" -O "$dest"
  fi
}

# resolve_latest_tag turns the /releases/latest redirect into a concrete tag.
#
# Uses the redirect rather than the API so it needs no token and is not subject
# to the API rate limit, which an unauthenticated CI runner will hit. Prints
# nothing when it cannot resolve, and the caller falls back.
resolve_latest_tag() {
  local url=""
  if command -v curl >/dev/null 2>&1; then
    url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' --retry 2 \
      "https://github.com/Vulnetix/cli/releases/latest" 2>/dev/null)
  elif command -v wget >/dev/null 2>&1; then
    url=$(wget -q --spider --server-response --max-redirect=10 \
      "https://github.com/Vulnetix/cli/releases/latest" 2>&1 \
      | awk '/^  Location: /{print $2}' | tail -n1)
  fi

  case "$url" in
    */tag/v*) printf '%s' "${url##*/tag/}" ;;
    *) printf '' ;;
  esac
}

# resolve_major_tag prints the newest stable vMAJOR.x.y release, or nothing.
#
# The latest release answers it when it belongs to that major, which is the
# usual case and needs no token. An older major (v3 once v4 ships) is read
# from the tag list: git ls-remote when git is present, else the releases API.
# Prereleases (v3.1.0-rc.1) never match.
resolve_major_tag() {
  local channel="$1"
  local major="${channel#v}"
  local latest
  latest=$(resolve_latest_tag)
  case "$latest" in
    "v${major}."*-*) ;;
    "v${major}."*) printf '%s' "$latest"; return ;;
  esac

  local tags=""
  if command -v git >/dev/null 2>&1; then
    tags=$(git ls-remote --tags --refs "https://github.com/${GITHUB_REPO}.git" "v${major}.*" 2>/dev/null \
      | awk '{sub("refs/tags/", "", $2); print $2}')
  fi
  if [ -z "$tags" ] && command -v curl >/dev/null 2>&1; then
    tags=$(curl -fsSL --retry 2 "https://api.github.com/repos/${GITHUB_REPO}/releases?per_page=100" 2>/dev/null \
      | awk -F'"' '/"tag_name":/ {print $4}')
  fi
  printf '%s\n' "$tags" \
    | grep -E "^v${major}\.[0-9]+\.[0-9]+$" \
    | sed 's/^v//' \
    | sort -t. -k1,1n -k2,2n -k3,3n \
    | tail -n1 \
    | sed 's/^./v&/'
}

# expected_size reports the asset's size from the server, or nothing when the
# server will not say. Used to tell an interrupted download apart from a
# genuine integrity failure before the checksum is even computed.
expected_size() {
  local url="$1"
  local downloader="$2"
  if [ "$downloader" = "curl" ]; then
    curl -fsSLI --retry 2 "$url" 2>/dev/null \
      | tr -d '\r' | awk 'tolower($1) == "content-length:" { print $2 }' | tail -n1
  else
    wget -q --spider --server-response "$url" 2>&1 \
      | tr -d '\r' | awk 'tolower($1) == "content-length:" { print $2 }' | tail -n1
  fi
}

# verify_size checks the download arrived whole.
#
# The old floor of 1 KiB only caught an error page served instead of a binary.
# A connection that dropped part way through a 90 MB release binary left tens of
# megabytes on disk — far over the floor, so it passed here and failed at the
# checksum instead, where the message blamed tampering. Comparing against the
# size the server declared is what tells those two apart.
verify_size() {
  local path="$1"
  local want="${2:-}"

  if [ ! -f "$path" ]; then
    echo "error: downloaded file not found at $path" >&2
    exit 1
  fi
  local size
  size=$(wc -c < "$path" 2>/dev/null || echo 0)
  if [ "$size" -lt 1024 ]; then
    echo "error: downloaded file is suspiciously small (${size} bytes), the download may have failed" >&2
    rm -f "$path"
    exit 1
  fi
  if [ -n "$want" ] && [ "$want" -gt 0 ] 2>/dev/null && [ "$size" -ne "$want" ]; then
    echo "error: download is incomplete: got ${size} bytes, server declared ${want}" >&2
    echo "error: this is a network problem, not a corrupt release. Please run the installer again." >&2
    rm -f "$path"
    exit 1
  fi
  echo "info: download size=${size} bytes"
}

# refuse_unverified stops an install that could not be verified, and says how
# to install anyway. It is for "cannot check", never for "checked and wrong".
refuse_unverified() {
  echo "error: $1, refusing to install" >&2
  echo "error: to install without verification (not recommended), re-run with" >&2
  echo "error:   --insecure-skip-verify, or set VULNETIX_INSECURE_SKIP_VERIFY=1" >&2
  exit 1
}

# verify_checksum fails closed: no SHA-256 tool, no checksums.txt or no entry
# for the asset each stop the install, as a mismatch always has.
verify_checksum() {
  local asset="$1"
  local tmp_binary="$2"
  local checksums_url="$3"
  local downloader="$4"
  local sha_tool="$5"

  if [ "$sha_tool" = "none" ]; then
    refuse_unverified "no SHA-256 tool found (sha256sum, shasum, sha256, openssl, rhash or certutil)"
  fi

  TMP_CHECKSUMS=$(mktemp)

  echo "info: fetching $checksums_url"
  if ! download "$checksums_url" "$TMP_CHECKSUMS" "$downloader" 2>&1; then
    refuse_unverified "could not fetch checksums.txt"
  fi

  # Extract expected hash for this asset from checksums.txt
  local expected
  expected=$(grep " \*\{0,1\}${asset}$" "$TMP_CHECKSUMS" | awk '{print $1}' | head -n1)
  rm -f "$TMP_CHECKSUMS"

  if [ -z "$expected" ]; then
    refuse_unverified "asset '${asset}' has no entry in checksums.txt"
  fi

  echo "info: expected sha256=$expected"

  local actual
  actual=$(compute_sha256 "$tmp_binary" "$sha_tool")
  echo "info: actual   sha256=$actual"

  if [ "$actual" != "$expected" ]; then
    # Say what is actually known. An interrupted download is by far the most
    # common cause and is now caught by verify_size, so reaching here with a
    # complete file is the case worth alarming about. Claiming tampering
    # outright, as this used to, sends people hunting a supply-chain
    # compromise over a dropped connection.
    echo "error: checksum mismatch, refusing to install" >&2
    echo "error:   expected: $expected" >&2
    echo "error:   actual:   $actual" >&2
    echo "error:   size:     $(wc -c < "$tmp_binary" 2>/dev/null || echo unknown) bytes" >&2
    echo "error: if the size above looks short, the download was interrupted: run the installer again." >&2
    echo "error: if it is the full size, do not install this binary. Report it at" >&2
    echo "error:   https://github.com/Vulnetix/cli/issues" >&2
    rm -f "$tmp_binary"
    exit 1
  fi

  echo "info: checksum verified ok"
}

# fetch_optional downloads a file that a release may not have. Unlike download
# it does not retry a 404, so an older release without a provenance bundle
# costs one request, not five retries.
fetch_optional() {
  if [ "$3" = "curl" ]; then
    curl -fsSL --retry 3 --retry-delay 2 "$1" -o "$2" 2>/dev/null
  else
    wget -q --tries=3 --timeout=30 "$1" -O "$2" 2>/dev/null
  fi
}

# check_provenance_tooling runs before the download, so --require-provenance
# without cosign fails in a second rather than after a 100 MB transfer.
check_provenance_tooling() {
  if [ "$REQUIRE_PROVENANCE" != "1" ]; then
    return
  fi
  if ! command -v cosign >/dev/null 2>&1; then
    echo "error: --require-provenance is set but cosign is not on PATH" >&2
    echo "error: install cosign (https://docs.sigstore.dev/cosign/system_config/installation/) and run the installer again" >&2
    exit 1
  fi
}

# verify_provenance checks the release's signed SLSA provenance names this
# exact binary. It runs when cosign is on PATH, and --require-provenance makes
# it mandatory. A bundle that is present and does not verify always stops the
# install. A release with no bundle (releases before provenance was signed)
# installs on its checksum alone unless provenance is required.
verify_provenance() {
  local tmp_binary="$1"
  local bundle_url="$2"
  local downloader="$3"

  if ! command -v cosign >/dev/null 2>&1; then
    echo "info: cosign not found, skipping provenance verification (checksum verified)"
    return
  fi

  TMP_BUNDLE=$(mktemp)
  echo "info: fetching $bundle_url"
  local tries=0
  while ! fetch_optional "$bundle_url" "$TMP_BUNDLE" "$downloader" || [ ! -s "$TMP_BUNDLE" ]; do
    if [ "$REQUIRE_PROVENANCE" != "1" ] || [ "$FLOATING_VERSION" != "1" ] || [ "$tries" -ge "$PROVENANCE_WAIT_TRIES" ]; then
      break
    fi
    tries=$((tries + 1))
    echo "info: no ${PROVENANCE_ASSET} yet; a release published in the last few minutes is signed shortly after. Waiting ${PROVENANCE_WAIT_SECONDS}s (${tries}/${PROVENANCE_WAIT_TRIES})"
    sleep "$PROVENANCE_WAIT_SECONDS"
  done
  if [ ! -s "$TMP_BUNDLE" ]; then
    rm -f "$TMP_BUNDLE"
    if [ "$REQUIRE_PROVENANCE" = "1" ]; then
      echo "error: this release has no ${PROVENANCE_ASSET} and --require-provenance is set, refusing to install" >&2
      echo "error: every v4 release has one, some v3 releases do not; pin one that does" >&2
      exit 1
    fi
    echo "warn: this release has no ${PROVENANCE_ASSET}; installing on the checksum alone" >&2
    return
  fi

  local out
  if out=$(cosign verify-blob-attestation \
      --bundle "$TMP_BUNDLE" --new-bundle-format \
      --type "$PROVENANCE_TYPE" \
      --certificate-oidc-issuer "$PROVENANCE_ISSUER" \
      --certificate-identity-regexp "$PROVENANCE_IDENTITY_REGEXP" \
      --certificate-github-workflow-repository "$PROVENANCE_REPOSITORY" \
      "$tmp_binary" 2>&1); then
    rm -f "$TMP_BUNDLE"
    echo "info: provenance verified ok (signed by ${PROVENANCE_REPOSITORY} slsa-provenance.yml)"
    return
  fi

  rm -f "$TMP_BUNDLE"
  echo "error: provenance verification failed, refusing to install" >&2
  printf '%s\n' "$out" | sed 's/^/error:   cosign: /' >&2
  echo "error: if cosign could not reach Sigstore (a network error above), run the installer again." >&2
  echo "error: otherwise do not install this binary. Report it at" >&2
  echo "error:   https://github.com/Vulnetix/cli/issues" >&2
  rm -f "$tmp_binary"
  exit 1
}

# install_client_id is a random id made for this install only, in GA4's own
# <random>.<timestamp> shape. Nothing is stored, so two installs on one machine
# are two ids, and no id says anything about the machine.
install_client_id() {
  local rand
  rand=$(od -An -N4 -tu4 /dev/urandom 2>/dev/null | tr -d ' \n')
  [ -n "$rand" ] || rand="$$"
  printf '%s.%s' "$rand" "$(date +%s)"
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

  if [ "$INSECURE_SKIP_VERIFY" = "1" ] && [ "$REQUIRE_PROVENANCE" = "1" ]; then
    echo "error: --insecure-skip-verify and --require-provenance contradict each other; pick one" >&2
    exit 1
  fi
  check_provenance_tooling
  # Checked before the download too, so a machine with no SHA-256 tool is
  # told so before a 100 MB transfer rather than after it.
  if [ "$SHA_TOOL" = "none" ] && [ "$INSECURE_SKIP_VERIFY" != "1" ]; then
    refuse_unverified "no SHA-256 tool found (sha256sum, shasum, sha256, openssl, rhash or certutil)"
  fi

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
  # `latest` is resolved to a concrete tag ONCE, and both downloads are then
  # pinned to it.
  #
  # Fetching the binary and its checksums through the /latest/ alias is not
  # atomic. A release published between the two moves the alias, so the bytes
  # come from one release and the digest from the next, and the installer then
  # reports a checksum mismatch on two files that are each perfectly intact.
  # That is not hypothetical: a 90 MB binary takes long enough to download that
  # a release landing mid-transfer is an ordinary event on an active project,
  # and the failure it produces accuses us of shipping a tampered binary.
  # A bare major (v3) is a channel: the newest stable release of that major.
  # It is what the GitHub Action installs by default, so a workflow pinned to
  # Vulnetix/cli@v3 keeps a v3 binary after v4 ships.
  case "$VERSION" in
    v[0-9]|v[0-9][0-9]|[0-9]|[0-9][0-9])
      CHANNEL="v${VERSION#v}"
      RESOLVED=$(resolve_major_tag "$CHANNEL")
      if [ -z "$RESOLVED" ]; then
        echo "error: could not resolve the newest $CHANNEL release" >&2
        exit 1
      fi
      echo "info: channel $CHANNEL resolved to $RESOLVED"
      VERSION="$RESOLVED"
      FLOATING_VERSION=1
      ;;
  esac

  if [ "$VERSION" = "latest" ]; then
    RESOLVED=$(resolve_latest_tag)
    FLOATING_VERSION=1
    if [ -n "$RESOLVED" ]; then
      VERSION="$RESOLVED"
    else
      echo "warn: could not resolve the latest tag; falling back to the /latest/ alias." >&2
      echo "warn: if a release lands mid-download this can report a checksum mismatch; retry if it does." >&2
    fi
  fi

  if [ "$VERSION" = "latest" ]; then
    RELEASE_URL="${GITHUB_BASE}/latest/download"
  else
    RELEASE_URL="${GITHUB_BASE}/download/${VERSION}"
  fi
  DOWNLOAD_URL="${RELEASE_URL}/${ASSET}"
  CHECKSUMS_URL="${RELEASE_URL}/checksums.txt"
  BUNDLE_URL="${RELEASE_URL}/${PROVENANCE_ASSET}"

  echo "info: version=$VERSION asset=$ASSET"
  echo "info: binary    $DOWNLOAD_URL"
  echo "info: checksums $CHECKSUMS_URL"

  # Download binary to temp file. One trap removes every temporary file, so a
  # refusal at any step leaves nothing behind in the install directory.
  TMP_FILE=$(mktemp "${INSTALL_DIR}/.${BINARY_NAME}.XXXXXX" 2>/dev/null || mktemp)
  TMP_CHECKSUMS=""
  TMP_BUNDLE=""
  trap 'rm -f "$TMP_FILE" "$TMP_CHECKSUMS" "$TMP_BUNDLE"' EXIT

  echo "info: fetching $DOWNLOAD_URL"
  # Asked before the transfer so an interrupted download is diagnosed as one.
  # Best effort: a server that will not declare a length simply leaves this
  # empty and verify_size falls back to its floor check.
  EXPECT_BYTES=$(expected_size "$DOWNLOAD_URL" "$DOWNLOADER" || true)
  download "$DOWNLOAD_URL" "$TMP_FILE" "$DOWNLOADER"
  verify_size "$TMP_FILE" "$EXPECT_BYTES"
  if [ "$INSECURE_SKIP_VERIFY" = "1" ]; then
    echo "warn: --insecure-skip-verify is set: installing WITHOUT checking the checksum or provenance" >&2
  else
    verify_checksum "$ASSET" "$TMP_FILE" "$CHECKSUMS_URL" "$DOWNLOADER" "$SHA_TOOL"
    verify_provenance "$TMP_FILE" "$BUNDLE_URL" "$DOWNLOADER"
  fi

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
  echo "next: $BINARY_NAME auth login    sign in (optional: without it, scans run in community mode)"
  echo "      $BINARY_NAME scan          scan the current directory"
  echo ""
  echo "docs: ${DOCS_URL}"
  echo "      agentic use cases: https://www.vulnetix.com/articles/bypassing-scanners"
  echo ""
  echo "Thanks for installing Vulnetix CLI -- Vulnetix Team"

  # Fire-and-forget install beacon (respects opt-out; never blocks or fails install).
  # The client id is random per install, so GA4 counts installs, not platforms.
  if [ "${VULNETIX_NO_ANALYTICS:-0}" != "1" ] && [ "${DO_NOT_TRACK:-0}" != "1" ]; then
    echo "info: sending one anonymous install event (set VULNETIX_NO_ANALYTICS=1 or DO_NOT_TRACK=1 to opt out)"
    _GA4_CLIENT_ID=$(install_client_id)
    _GA4_PAYLOAD="{\"client_id\":\"${_GA4_CLIENT_ID}\",\"events\":[{\"name\":\"cli_install\",\"params\":{\"os\":\"${OS}\",\"arch\":\"${ARCH}\",\"version\":\"${VERSION}\"}}]}"
    _GA4_URL="https://www.google-analytics.com/mp/collect?measurement_id=G-NWBJE5RS0Q&api_secret=_XzmAjQNQwmsRiTG1oojbA"
    if [ "$DOWNLOADER" = "curl" ]; then
      curl -s -o /dev/null --max-time 3 -X POST \
        -H 'Content-Type: application/json' \
        -d "$_GA4_PAYLOAD" \
        "$_GA4_URL" >/dev/null 2>&1 &
    else
      wget -q -O /dev/null -T 3 \
        --post-data="$_GA4_PAYLOAD" \
        --header='Content-Type: application/json' \
        "$_GA4_URL" >/dev/null 2>&1 &
    fi
  fi
}

main "$@"

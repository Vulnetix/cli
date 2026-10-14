#!/usr/bin/env bash
# Users can install with: curl -fsSL https://get.example.com | bash
INSTALL_HINT="curl -fsSL https://get.example.com/install.sh | bash"
readonly DOCS_CMD='wget -qO- https://get.example.com | sh'
echo "  curl -fsSL https://get.example.com/install.sh | bash"
printf 'Install: %s\n' "curl -sSL https://get.example.com | sh"
log_info "or run: wget -qO- https://get.example.com | sh"
usage() {
  echo "Usage: $0"
  echo "One-line install: curl -fsSL https://get.example.com | bash"
}

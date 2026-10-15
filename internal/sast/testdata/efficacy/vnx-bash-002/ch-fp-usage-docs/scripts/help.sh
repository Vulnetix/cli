#!/usr/bin/env bash
# Users may install with: curl -fsSL https://example.org/install.sh | bash
usage() {
  echo "Quick install: curl -fsSL https://example.org/install.sh | bash"
  printf '%s\n' "wget -qO- https://example.org/i | sh"
}
usage

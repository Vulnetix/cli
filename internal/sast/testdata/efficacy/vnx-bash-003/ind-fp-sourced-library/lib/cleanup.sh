# Sourced by other scripts; no shebang.
cleanup_workspace() {
  cd "$1"
  rm -rf ./tmp
}

verify_bundle() {
  sha256sum -c "$1.sha256"
}

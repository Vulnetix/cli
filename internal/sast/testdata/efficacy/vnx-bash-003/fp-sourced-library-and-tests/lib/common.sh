# Sourced by other scripts: the caller decides on errexit.
enter_workspace() {
  cd "$1"
  rm -rf .tmp
}

retry() {
  local attempts="$1"; shift
  local n=0
  until [ "$n" -ge "$attempts" ]; do
~>    eval "$@" && return 0
    n=$((n + 1))
  done
  return 1
}

# Reads a setting whose name the caller supplies.
get_setting() {
  local name="$1"
  local value
~>  eval "value=\"\$${name}\""
  printf '%s\n' "$value"
}

set_setting() {
~>  eval "$1=\"\$2\""
}

read_named() {
  read -r key
~>  eval "current=\$$key"
  echo "$current"
}

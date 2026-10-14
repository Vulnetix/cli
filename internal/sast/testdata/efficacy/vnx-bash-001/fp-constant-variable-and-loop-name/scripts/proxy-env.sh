#!/bin/sh
# The evaluated string is a constant stored in a variable, and the indirect
# names come from a fixed list.
list_cmd="ls -la /var/log"
eval "$list_cmd"

for proxy_var in HTTP_PROXY HTTPS_PROXY NO_PROXY; do
  eval "proxy_value=\$$proxy_var"
  [ -n "$proxy_value" ] && echo "$proxy_var is set"
done

PREFIX_VAR="$(env | awk -F= 'toupper($1) == "NPM_CONFIG_PREFIX" { print $1; exit }')"
if [ -n "$PREFIX_VAR" ]; then
  eval "PREFIX_VALUE=\"\$${PREFIX_VAR}\""
fi

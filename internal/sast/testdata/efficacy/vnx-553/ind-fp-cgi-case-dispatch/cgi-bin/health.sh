#!/bin/bash
# Never eval "$QUERY_STRING" here; map it to fixed actions instead.
echo "Content-Type: text/plain"
echo ""

case "$QUERY_STRING" in
  check=disk) df -h / ;;
  check=load) uptime ;;
  *) echo "unknown check: $QUERY_STRING" ;;
esac

echo "login shell: $SHELL"

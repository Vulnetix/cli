#!/bin/sh
echo "Content-Type: text/plain"
echo ""
case "$QUERY_STRING" in
  report=disk) df -h ;;
  report=mem)  free -m ;;
  *) echo "unknown report" ;;
esac
LABEL=$(printf '%s' "$QUERY_STRING" | tr -cd 'a-z=')
echo "label: $LABEL"

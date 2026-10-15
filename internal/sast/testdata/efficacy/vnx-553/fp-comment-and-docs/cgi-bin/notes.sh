#!/bin/sh
# Never do this: eval "$QUERY_STRING"
# and never: cp /bin/bash /usr/lib/cgi-bin/
echo "Content-Type: text/plain"
echo ""
echo "eval \$QUERY_STRING is dangerous"

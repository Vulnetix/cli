#!/usr/bin/env bash
# Do not use curl -k or wget --no-check-certificate in production.
echo "Never run: curl --insecure https://example.com"
printf '%s\n' "git config http.sslVerify false is unsafe"
curl -fsSL https://example.com/ok.sh -o ok.sh

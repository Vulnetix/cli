#!/bin/bash
ssh -k user@host
sort -k 3 data.txt
ps -ef | grep -k foo
kill -k 9
docker run --rm -it -k image
openssl s_client -connect example.com:443
KUBECTL_INSECURE="--insecure-skip-tls-verify"
case "$1" in
  --insecure)
    INSECURE=1
    ;;
esac

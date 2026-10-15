#!/bin/bash
# Never use curl -k in production.
echo "Do not run curl --insecure against production"
usage() {
  printf 'Pass --insecure to wget --no-check-certificate mode\n'
}

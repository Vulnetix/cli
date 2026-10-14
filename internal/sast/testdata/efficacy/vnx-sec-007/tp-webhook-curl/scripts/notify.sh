#!/bin/sh
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"deploy done"}' \
~>  https://hooks.slack.com/services/@@sample:T[A-Z0-9]{10}@@/@@sample:B[A-Z0-9]{10}@@/@@sample:[A-Za-z0-9]{24}@@

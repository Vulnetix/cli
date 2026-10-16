#!/bin/sh
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"deploy done"}' \
~>  @@sample:https://hooks\.slack\.com/services/T[A-Z0-9]{10}/B[A-Z0-9]{10}/[A-Za-z0-9]{24}@@

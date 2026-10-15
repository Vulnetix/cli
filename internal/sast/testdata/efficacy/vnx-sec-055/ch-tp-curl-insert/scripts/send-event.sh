#!/bin/sh
gzip -c event.json | curl -X POST \
  -H "Content-Type: application/json" \
~>  -H "X-Insert-Key: NRII-@@sample:[A-Za-z0-9_-]{32}@@" \
  -H "Content-Encoding: gzip" \
  https://insights-collector.newrelic.com/v1/accounts/1234567/events --data-binary @-
